"""펌웨어 이미지를 재귀적으로 풀어 루트 파일 시스템을 꺼낸다.

지원: zip, tar(.gz/.xz/.bz2), gzip/xz/bz2 단일 스트림, squashfs, ext2/3/4,
Android sparse, GPT 디스크 이미지(eMMC 덤프), uImage, cpio(newc),
그리고 알 수 없는 바이너리 안에 박힌 squashfs/ext/uImage 조각(carving).
암호화된 파일은 복호화하지 않고 표시만 한다.
"""

import bz2
import gzip
import lzma
import os
import shutil
import struct
import subprocess
import tarfile
import zipfile
from pathlib import Path

from . import scan

MAX_DEPTH = 4
MIN_SIZE = 4096
CARVE_MIN = 64 * 1024  # 폴더 안에서 형식을 모르는 파일은 이보다 클 때만 조사
COPY_BUF = 4 * 1024 * 1024


class Log:
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.encrypted = []

    def __call__(self, depth, msg):
        if self.verbose:
            print("  " * depth + msg, flush=True)


def _copy_range(src, dst, offset, length):
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        fi.seek(offset)
        left = length
        while left > 0:
            data = fi.read(min(COPY_BUF, left))
            if not data:
                break
            fo.write(data)
            left -= len(data)


def _decompress_stream(opener, src, dst):
    with opener(src, "rb") as fi, open(dst, "wb") as fo:
        shutil.copyfileobj(fi, fo, COPY_BUF)


def _run(cmd, log, depth):
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if r.returncode != 0:
        tail = "\n".join(r.stdout.strip().splitlines()[-3:])
        log(depth, f"! {' '.join(map(str, cmd[:2]))} 실패 (코드 {r.returncode}): {tail}")
    return r.returncode == 0


def unsparse(src, dst):
    """Android sparse 이미지를 일반 raw 이미지로 변환."""
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        hdr = fi.read(28)
        (magic, _major, _minor, fhs, chs, blk, total_blks, chunks,
         _crc) = struct.unpack("<IHHHHIIII", hdr)
        if magic != 0xED26FF3A:
            raise ValueError("Android sparse 이미지가 아닙니다")
        fi.seek(fhs)
        for _ in range(chunks):
            ctype, _res, csz, total = struct.unpack("<HHII", fi.read(12))
            fi.seek(chs - 12, 1)
            data_len = total - chs
            if ctype == 0xCAC1:
                left = csz * blk
                while left:
                    data = fi.read(min(COPY_BUF, left))
                    fo.write(data)
                    left -= len(data)
            elif ctype == 0xCAC2:
                fill = fi.read(4) * (blk // 4)
                for _ in range(csz):
                    fo.write(fill)
            elif ctype == 0xCAC3:
                fo.seek(csz * blk, 1)
            else:
                fi.seek(data_len, 1)
        fo.truncate(total_blks * blk)


def parse_gpt(path, sector=512):
    """GPT 파티션 목록 [(이름, 시작 바이트, 길이)]."""
    with open(path, "rb") as f:
        f.seek(sector)
        hdr = f.read(92)
        if hdr[:8] != b"EFI PART":
            return []
        entries_lba, = struct.unpack_from("<Q", hdr, 72)
        count, esize = struct.unpack_from("<II", hdr, 80)
        f.seek(entries_lba * sector)
        table = f.read(count * esize)
    parts = []
    for i in range(count):
        e = table[i * esize:(i + 1) * esize]
        if len(e) < 128 or e[:16] == b"\0" * 16:
            continue
        first, last = struct.unpack_from("<QQ", e, 32)
        name = e[56:128].decode("utf-16-le", "ignore").rstrip("\0") or f"part{i + 1}"
        parts.append((name, first * sector, (last - first + 1) * sector))
    return parts


def extract_cpio(src, dest):
    """newc 형식 cpio(initramfs 등)를 푼다."""
    dest = Path(dest)
    with open(src, "rb") as f:
        while True:
            hdr = f.read(110)
            if len(hdr) < 110 or hdr[:6] not in (b"070701", b"070702"):
                break
            fields = [int(hdr[6 + i * 8:14 + i * 8], 16) for i in range(13)]
            mode, filesize, namesize = fields[1], fields[6], fields[11]
            name = f.read(namesize).rstrip(b"\0").decode("utf-8", "replace")
            f.seek((4 - (110 + namesize) % 4) % 4, 1)
            data = f.read(filesize)
            f.seek((4 - filesize % 4) % 4, 1)
            if name == "TRAILER!!!":
                break
            rel = os.path.normpath(name.lstrip("/"))
            if rel.startswith("..") or rel == ".":
                continue
            out = dest / rel
            kind = mode & 0o170000
            out.parent.mkdir(parents=True, exist_ok=True)
            if kind == 0o040000:
                out.mkdir(exist_ok=True)
            elif kind == 0o120000:
                if out.is_symlink() or out.exists():
                    out.unlink()
                os.symlink(data.decode("utf-8", "replace"), out)
            elif kind == 0o100000:
                out.write_bytes(data)
                os.chmod(out, mode & 0o7777)


def _safe_tar_extract(tf, dest):
    try:
        tf.extractall(dest, filter="tar")
    except TypeError:  # Python < 3.12
        tf.extractall(dest)


def _extract_known(kind, path, work, log, depth):
    """kind 형식의 path를 work 아래에 풀고, 다시 살펴볼 결과 경로 목록을 돌려준다."""
    out_dir = work / (path.name + ".d")
    if kind == "zip":
        out_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path) as zf:
            zf.extractall(out_dir)
        return [out_dir]
    if kind in ("tar", "gzip", "xz", "bzip2") and tarfile.is_tarfile(path):
        out_dir.mkdir(parents=True, exist_ok=True)
        with tarfile.open(path) as tf:
            _safe_tar_extract(tf, out_dir)
        return [out_dir]
    if kind in ("gzip", "xz", "bzip2"):
        opener = {"gzip": gzip.open, "xz": lzma.open, "bzip2": bz2.open}[kind]
        stem = path.stem if path.suffix else path.name + ".raw"
        dst = work / stem
        if dst == path:
            dst = work / (path.name + ".raw")
        try:
            _decompress_stream(opener, path, dst)
        except (OSError, EOFError, lzma.LZMAError) as e:
            log(depth, f"! 압축 해제 실패: {e}")
            return []
        return [dst]
    if kind == "squashfs":
        if not shutil.which("unsquashfs"):
            log(depth, "! unsquashfs가 없습니다 (squashfs-tools 설치 필요)")
            return []
        if _run(["unsquashfs", "-f", "-no-xattrs", "-d", str(out_dir), str(path)], log, depth):
            return [out_dir]
        return [out_dir] if out_dir.exists() else []
    if kind == "ext":
        if not shutil.which("debugfs"):
            log(depth, "! debugfs가 없습니다 (e2fsprogs 설치 필요)")
            return []
        out_dir.mkdir(parents=True, exist_ok=True)
        _run(["debugfs", "-R", f"rdump / {out_dir}", str(path)], log, depth)
        return [out_dir]
    if kind == "android-sparse":
        dst = work / (path.stem + ".raw.img")
        unsparse(path, dst)
        return [dst]
    if kind == "gpt":
        out_dir.mkdir(parents=True, exist_ok=True)
        results = []
        for i, (name, off, ln) in enumerate(parse_gpt(path), 1):
            safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
            dst = out_dir / f"p{i:02d}_{safe}.img"
            log(depth, f"파티션 {i}: {name} (오프셋 0x{off:x}, {ln:,}B)")
            _copy_range(path, dst, off, ln)
            results.append(dst)
        return results
    if kind == "uimage":
        with open(path, "rb") as f:
            hdr = f.read(64)
        size, = struct.unpack_from(">I", hdr, 12)
        img_type = hdr[30]
        name = hdr[32:64].split(b"\0")[0].decode("ascii", "replace").strip() or "payload"
        log(depth, f"uImage: '{name}' (type={img_type})")
        dst = work / (path.name + (".kernel" if img_type == 2 else ".payload"))
        _copy_range(path, dst, 64, size)
        return [dst] if img_type != 2 else []
    if kind == "cpio":
        out_dir.mkdir(parents=True, exist_ok=True)
        extract_cpio(path, out_dir)
        return [out_dir]
    return None


CARVABLE = ("gpt", "squashfs", "ext", "uimage")


def extract(path, work, log=None, depth=0):
    """path(파일 또는 디렉터리)를 work 아래에 재귀적으로 푼다."""
    log = log or Log()
    path, work = Path(path), Path(work)
    work.mkdir(parents=True, exist_ok=True)
    if depth > MAX_DEPTH:
        return
    if path.is_dir():
        for child in sorted(path.rglob("*")):
            if child.is_file() and not child.is_symlink() and child.stat().st_size >= MIN_SIZE:
                kind = scan.identify_header(child)
                if not _worth_extracting(child, kind):
                    continue
                rel = child.relative_to(path)
                log(depth, f"→ {rel} [{kind or '알 수 없음'}]")
                sub = work / (str(rel).replace(os.sep, "__") + ".x")
                _extract_file(child, kind, sub, log, depth + 1)
        return
    kind = scan.identify_header(path)
    log(depth, f"→ {path.name} [{kind or '알 수 없음'}]")
    _extract_file(path, kind, work, log, depth + 1)


def _extract_file(path, kind, work, log, depth):
    work.mkdir(parents=True, exist_ok=True)
    produced = _extract_known(kind, path, work, log, depth) if kind else None
    if produced is None:
        produced = _carve(path, work, log, depth)
    for item in produced:
        if item.is_dir():
            _descend_dir(item, log, depth)
        elif item.is_file():
            sub_kind = scan.identify_header(item)
            log(depth, f"→ {item.name} [{sub_kind or '알 수 없음'}]")
            if sub_kind and sub_kind not in ("elf", "dtb") and depth < MAX_DEPTH:
                _extract_file(item, sub_kind, work / (item.name + ".x"), log, depth + 1)
            elif not sub_kind and depth < MAX_DEPTH:
                _extract_file(item, None, work / (item.name + ".x"), log, depth + 1)


def _worth_extracting(path, kind):
    if kind in ("elf", "dtb"):
        return False
    return kind is not None or path.stat().st_size >= CARVE_MIN


def _descend_dir(d, log, depth):
    """풀린 디렉터리 안의 이미지 파일(rootfs.img 등)도 이어서 푼다.

    루트 파일 시스템처럼 보이는 디렉터리 내부는 건드리지 않는다.
    """
    from .rootfs import looks_like_rootfs
    if looks_like_rootfs(d) or depth >= MAX_DEPTH:
        return
    for child in sorted(d.iterdir()):
        if child.is_dir() and not child.is_symlink():
            _descend_dir(child, log, depth)
        elif child.is_file() and not child.is_symlink() and child.stat().st_size >= MIN_SIZE:
            kind = scan.identify_header(child)
            if _worth_extracting(child, kind):
                log(depth, f"→ {child.name} [{kind or '알 수 없음'}]")
                _extract_file(child, kind, child.parent / (child.name + ".x"), log, depth + 1)


def _carve(path, work, log, depth):
    if path.stat().st_size < MIN_SIZE:
        return []
    sigs = scan.scan_signatures(path)
    enc, high = scan.looks_encrypted(path, sigs)
    if enc:
        log(depth, f"⚠ 암호화된 것으로 보임 (고엔트로피 {high * 100:.0f}%) — 건너뜀")
        log.encrypted.append(str(path))
        return []
    results = []
    taken_until = -1
    candidates = sorted(
        (off, ln, name) for name in CARVABLE if name in sigs
        for off, ln in sigs[name]["hits"] if ln or name == "gpt")
    for off, ln, name in candidates:
        if off < taken_until or (off == 0 and name != "gpt"):
            continue
        if name == "gpt":
            dst = work / f"{path.name}@0x{off:x}.gpt.img"
            ln = path.stat().st_size - off
        else:
            dst = work / f"{path.name}@0x{off:x}.{name}"
        log(depth, f"조각 추출: {name} @0x{off:x} ({ln:,}B)")
        _copy_range(path, dst, off, ln)
        taken_until = off + ln
        results.append(dst)
    if not results:
        log(depth, "(풀 수 있는 구조를 찾지 못함)")
    return results
