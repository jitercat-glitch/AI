"""펌웨어 파일 시그니처 스캔과 엔트로피(암호화 여부) 분석."""

import math
import os
import struct
from collections import Counter

CHUNK = 8 * 1024 * 1024
OVERLAP = 4096
MAX_HITS_PER_TYPE = 32


def _ext_ok(buf, sb):
    # sb: ext 슈퍼블록 시작(이미지 시작 + 1024) 위치
    if len(buf) < sb + 100:
        return None
    blocks, = struct.unpack_from("<I", buf, sb + 4)
    log_bs, = struct.unpack_from("<I", buf, sb + 24)
    inodes_per_group, = struct.unpack_from("<I", buf, sb + 40)
    state, = struct.unpack_from("<H", buf, sb + 58)
    rev, = struct.unpack_from("<I", buf, sb + 76)
    if log_bs > 6 or blocks == 0 or inodes_per_group == 0 or rev > 1 or state not in range(1, 8):
        return None
    return blocks * (1024 << log_bs)


def _squashfs_ok(buf, pos):
    if len(buf) < pos + 48:
        return None
    major, = struct.unpack_from("<H", buf, pos + 28)
    used, = struct.unpack_from("<Q", buf, pos + 40)
    if major != 4 or used < 96:
        return None
    return used


def _uimage_ok(buf, pos):
    if len(buf) < pos + 64:
        return None
    size, = struct.unpack_from(">I", buf, pos + 12)
    return 64 + size if size else None


def _dtb_ok(buf, pos):
    if len(buf) < pos + 24:
        return None
    total, = struct.unpack_from(">I", buf, pos + 4)
    version, = struct.unpack_from(">I", buf, pos + 20)
    if version not in (16, 17) or not 64 <= total <= 64 * 1024 * 1024:
        return None
    return total


def _elf_ok(buf, pos):
    if len(buf) < pos + 20:
        return None
    if buf[pos + 4] not in (1, 2) or buf[pos + 5] not in (1, 2) or buf[pos + 6] != 1:
        return None
    return 0


def _bzip2_ok(buf, pos):
    if len(buf) < pos + 10:
        return None
    if not (0x31 <= buf[pos + 3] <= 0x39) or buf[pos + 4:pos + 10] != b"1AY&SY":
        return None
    return 0


def _gpt_ok(buf, pos):
    if len(buf) < pos + 92:
        return None
    rev, hsize = struct.unpack_from("<II", buf, pos + 8)
    if rev != 0x00010000 or not 92 <= hsize <= 512:
        return None
    return 0


# (이름, 매직, 매직이 구조 시작점에서 떨어진 거리, 검증 함수 -> 크기|0|None, 정렬)
SIGNATURES = [
    ("gpt", b"EFI PART", 512, _gpt_ok, 512),
    ("squashfs", b"hsqs", 0, _squashfs_ok, 1),
    ("ext", b"\x53\xef", 1080, _ext_ok, 512),
    ("android-sparse", b"\x3a\xff\x26\xed", 0, None, 1),
    ("android-boot", b"ANDROID!", 0, None, 1),
    ("ubi", b"UBI#", 0, None, 1),
    ("ubifs", b"\x31\x18\x10\x06", 0, None, 4),
    ("uimage", b"\x27\x05\x19\x56", 0, _uimage_ok, 1),
    ("dtb", b"\xd0\x0d\xfe\xed", 0, _dtb_ok, 4),
    ("zip", b"PK\x03\x04", 0, None, 1),
    ("tar", b"ustar", 257, None, 512),
    ("cpio", b"070701", 0, None, 4),
    ("gzip", b"\x1f\x8b\x08", 0, None, 1),
    ("xz", b"\xfd7zXZ\x00", 0, None, 1),
    ("bzip2", b"BZh", 0, _bzip2_ok, 1),
    ("zstd", b"\x28\xb5\x2f\xfd", 0, None, 1),
    ("lz4", b"\x04\x22\x4d\x18", 0, None, 1),
    ("7z", b"7z\xbc\xaf\x27\x1c", 0, None, 1),
    ("openssl-encrypted", b"Salted__", 0, None, 1),
    ("elf", b"\x7fELF", 0, _elf_ok, 1),
]

ALWAYS_REPORTED = {"gpt", "squashfs", "ext", "android-sparse", "android-boot", "ubi",
                   "uimage", "zip", "tar", "openssl-encrypted"}


def _validate(buf, start, sig, abs_start=None):
    name, _magic, _delta, check, align = sig
    if start < 0 or (start if abs_start is None else abs_start) % align:
        return None
    if check is None:
        return 0
    if name == "ext":
        return check(buf, start + 1024)
    if name == "gpt":
        return check(buf, start + 512)
    return check(buf, start)


def identify_header(path):
    """파일 맨 앞(오프셋 0)에 있는 구조의 종류를 돌려준다. 모르면 None."""
    with open(path, "rb") as f:
        head = f.read(64 * 1024)
    for sig in SIGNATURES:
        name, magic, delta, _check, _align = sig
        if head[delta:delta + len(magic)] == magic and _validate(head, 0, sig) is not None:
            return name
    return None


def scan_signatures(path, max_hits=MAX_HITS_PER_TYPE):
    """파일 전체에서 알려진 구조를 찾는다. {종류: {"count": n, "hits": [(offset, size)]}}"""
    found = {}
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        base = 0
        while base < size:
            lead = min(base, OVERLAP)
            f.seek(base - lead)
            buf = f.read(lead + CHUNK + OVERLAP)
            if len(buf) <= lead:
                break
            for sig in SIGNATURES:
                name, magic, delta, _check, _align = sig
                i = buf.find(magic)
                while i != -1:
                    start_local = i - delta
                    abs_start = base - lead + start_local
                    if abs_start >= base + CHUNK:
                        break
                    if start_local >= 0 and abs_start >= base:
                        ln = _validate(buf, start_local, sig, abs_start)
                        if ln is not None:
                            entry = found.setdefault(name, {"count": 0, "hits": []})
                            entry["count"] += 1
                            if len(entry["hits"]) < max_hits:
                                entry["hits"].append((abs_start, ln or None))
                    i = buf.find(magic, i + 1)
            base += CHUNK
    return found


def entropy(data):
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def entropy_profile(path, block=1024 * 1024, samples=256):
    """파일 전체에 고르게 퍼진 블록들의 엔트로피(비트/바이트) 목록."""
    size = os.path.getsize(path)
    if size == 0:
        return []
    count = max(1, min(samples, size // block or 1))
    step = max(block, size // count)
    values = []
    with open(path, "rb") as f:
        for off in range(0, size, step):
            f.seek(off)
            data = f.read(min(block, 256 * 1024))
            if data:
                values.append((off, entropy(data)))
    return values


def looks_encrypted(path, sigs=None):
    """구조를 알아볼 수 없고 엔트로피가 거의 최대이면 암호화된 것으로 본다."""
    prof = entropy_profile(path)
    if not prof:
        return False, 0.0
    high = sum(1 for _off, e in prof if e > 7.95) / len(prof)
    if sigs is None:
        sigs = scan_signatures(path, max_hits=4)
    if "openssl-encrypted" in sigs and sigs["openssl-encrypted"]["hits"][0][0] == 0:
        return True, high
    header = identify_header(path)
    if header and header not in ("elf", "dtb"):
        return False, high  # 압축/컨테이너 형식이라 엔트로피가 높은 것
    structural = any(k in sigs for k in ALWAYS_REPORTED - {"openssl-encrypted"})
    return (high > 0.9 and not structural), high


def inspect_file(path):
    sigs = scan_signatures(path)
    enc, high = looks_encrypted(path, sigs)
    return {
        "path": str(path),
        "size": os.path.getsize(path),
        "header": identify_header(path),
        "signatures": sigs,
        "high_entropy_ratio": round(high, 3),
        "likely_encrypted": enc,
    }


def format_report(info):
    lines = [f"■ {info['path']}  ({info['size']:,} bytes)",
             f"  맨 앞 구조: {info['header'] or '알 수 없음'}",
             f"  고엔트로피 블록 비율: {info['high_entropy_ratio'] * 100:.1f}%"]
    if info["likely_encrypted"]:
        lines.append("  ⚠ 암호화된 것으로 보입니다. 이 도구는 복호화를 하지 않습니다 "
                     "(본인 기기에서 덤프한 평문 이미지를 사용하세요).")
    sigs = info["signatures"]
    for name, entry in sorted(sigs.items(), key=lambda kv: kv[1]["hits"][0][0]):
        if name not in ALWAYS_REPORTED and entry["count"] > 200:
            lines.append(f"  - {name}: {entry['count']}개 (파일 시스템 내부 항목일 가능성이 큼)")
            continue
        shown = ", ".join(
            f"0x{off:x}" + (f"({ln:,}B)" if ln else "") for off, ln in entry["hits"][:6])
        more = f" 외 {entry['count'] - 6}개" if entry["count"] > 6 else ""
        lines.append(f"  - {name}: {shown}{more}")
    return "\n".join(lines)
