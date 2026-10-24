"""풀린 루트 파일 시스템 분석: 아키텍처, 런타임, HMI 실행 파일 후보."""

import configparser
import os
import struct
from pathlib import Path

ELF_MACHINES = {
    0x03: "i386", 0x08: "mips", 0x14: "ppc", 0x28: "arm", 0x3E: "x86_64",
    0xB7: "aarch64", 0xF3: "riscv",
}
# QEMU 실행 파일 이름에 쓰이는 아키텍처 이름
QEMU_ARCH = {"arm": "arm", "aarch64": "aarch64", "x86_64": "x86_64", "i386": "i386",
             "mips": "mips", "ppc": "ppc", "riscv": "riscv64"}

STD_BIN_DIRS = ("bin", "sbin", "usr/bin", "usr/sbin")


def read_elf(path):
    """ELF 헤더 요약. ELF가 아니면 None."""
    try:
        with open(path, "rb") as f:
            head = f.read(64)
            if len(head) < 52 or head[:4] != b"\x7fELF":
                return None
            cls, data = head[4], head[5]
            end = "<" if data == 1 else ">"
            e_type, e_machine = struct.unpack_from(end + "HH", head, 16)
            if cls == 2:
                e_phoff, = struct.unpack_from(end + "Q", head, 32)
                e_flags, = struct.unpack_from(end + "I", head, 48)
                e_phentsize, e_phnum = struct.unpack_from(end + "HH", head, 54)
            else:
                e_phoff, = struct.unpack_from(end + "I", head, 28)
                e_flags, = struct.unpack_from(end + "I", head, 36)
                e_phentsize, e_phnum = struct.unpack_from(end + "HH", head, 42)
            interp = None
            for i in range(min(e_phnum, 64)):
                f.seek(e_phoff + i * e_phentsize)
                ph = f.read(e_phentsize)
                if len(ph) < 32:
                    break
                p_type, = struct.unpack_from(end + "I", ph, 0)
                if p_type != 3:  # PT_INTERP
                    continue
                if cls == 2:
                    p_offset, = struct.unpack_from(end + "Q", ph, 8)
                    p_filesz, = struct.unpack_from(end + "Q", ph, 32)
                else:
                    p_offset, = struct.unpack_from(end + "I", ph, 4)
                    p_filesz, = struct.unpack_from(end + "I", ph, 16)
                f.seek(p_offset)
                interp = f.read(min(p_filesz, 256)).rstrip(b"\0").decode("ascii", "replace")
    except (OSError, struct.error):
        return None
    arch = ELF_MACHINES.get(e_machine, f"machine-0x{e_machine:x}")
    if arch == "arm":
        arch_detail = "armhf" if e_flags & 0x400 else "armel"
    else:
        arch_detail = arch
    return {"arch": arch, "arch_detail": arch_detail, "bits": 64 if cls == 2 else 32,
            "endian": "little" if data == 1 else "big", "type": e_type,
            "interp": interp}


def looks_like_rootfs(d):
    d = Path(d)
    has_bin = any((d / b).is_dir() for b in ("bin", "usr/bin"))
    return has_bin and (d / "etc").is_dir()


def find_rootfs_candidates(base, max_depth=8):
    """base 아래에서 루트 파일 시스템처럼 보이는 디렉터리를 점수순으로."""
    base = Path(base)
    found = []
    for root, dirs, _files in os.walk(base):
        rel_depth = len(Path(root).relative_to(base).parts)
        if rel_depth > max_depth:
            dirs[:] = []
            continue
        if looks_like_rootfs(root):
            found.append(Path(root))
            dirs[:] = []
    scored = []
    for d in found:
        score = 0
        for sub in ("bin", "usr/bin", "lib", "usr/lib", "sbin", "etc/init.d", "etc/systemd"):
            if (d / sub).exists():
                score += 1
        elf_count = sum(1 for b in STD_BIN_DIRS if (d / b).is_dir()
                        for p in (d / b).iterdir() if p.is_file() and read_elf(p))
        score += min(elf_count, 500) / 50
        scored.append((score, d))
    return [d for _s, d in sorted(scored, key=lambda t: -t[0])]


def _resolve_in_root(root, p):
    """루트 안의 심볼릭 링크를 루트 기준으로 따라간다."""
    root = Path(root)
    cur = Path(p)
    for _ in range(16):
        if not cur.is_symlink():
            return cur
        target = os.readlink(cur)
        cur = root / target.lstrip("/") if target.startswith("/") else cur.parent / target
    return cur


def detect_arch(root):
    root = Path(root)
    infos = []
    for b in STD_BIN_DIRS + ("lib", "usr/lib"):
        d = root / b
        if not d.is_dir():
            continue
        for p in sorted(d.iterdir())[:400]:
            real = _resolve_in_root(root, p)
            if real.is_file():
                info = read_elf(real)
                if info:
                    infos.append(info)
    if not infos:
        return None
    counts = {}
    for info in infos:
        counts[info["arch_detail"]] = counts.get(info["arch_detail"], 0) + 1
    best = max(counts, key=counts.get)
    same = [i for i in infos if i["arch_detail"] == best]
    return next((i for i in same if i["interp"]), same[0])


def _glob_names(root, patterns):
    hits = []
    for pat in patterns:
        hits.extend(str(p.relative_to(root)) for p in root.glob(pat))
    return sorted(set(hits))


def _read_text(p, limit=4096):
    try:
        return Path(p).read_text(errors="replace")[:limit]
    except OSError:
        return ""


def systemd_services(root):
    root = Path(root)
    services = []
    for d in ("etc/systemd/system", "lib/systemd/system", "usr/lib/systemd/system"):
        sd = root / d
        if not sd.is_dir():
            continue
        for unit in sorted(sd.glob("*.service")):
            real = _resolve_in_root(root, unit)
            if not real.is_file():
                continue
            cp = configparser.ConfigParser(strict=False, interpolation=None)
            try:
                cp.read_string(_read_text(real, 65536))
                exec_start = cp.get("Service", "ExecStart", fallback="")
            except configparser.Error:
                exec_start = ""
            if exec_start:
                services.append((unit.name, exec_start.strip()))
    return services


def analyze(root, hmi_keywords=()):
    root = Path(root)
    arch = detect_arch(root)
    os_release = ""
    for p in ("etc/os-release", "usr/lib/os-release", "etc/issue", "etc/version"):
        txt = _read_text(root / p, 2048).strip()
        if txt:
            os_release = txt
            break
    init = None
    sbin_init = root / "sbin/init"
    if sbin_init.is_symlink():
        init = os.readlink(sbin_init)
    elif sbin_init.exists():
        init = "/sbin/init"
    qt_platforms = [Path(p).name for p in _glob_names(
        root, ["usr/lib/**/platforms/libq*.so", "opt/**/platforms/libq*.so",
               "lib/**/platforms/libq*.so"])]
    runtimes = {
        "Qt5": bool(_glob_names(root, ["usr/lib/libQt5Core.so*", "usr/lib/*/libQt5Core.so*",
                                       "opt/**/libQt5Core.so*"])),
        "Qt6": bool(_glob_names(root, ["usr/lib/libQt6Core.so*", "usr/lib/*/libQt6Core.so*",
                                       "opt/**/libQt6Core.so*"])),
        "Wayland": bool(_glob_names(root, ["usr/lib/libwayland-client.so*",
                                           "usr/lib/*/libwayland-client.so*"])),
        "Weston": bool(_glob_names(root, ["usr/bin/weston"])),
        "GStreamer": bool(_glob_names(root, ["usr/lib/libgstreamer-1.0.so*",
                                             "usr/lib/*/libgstreamer-1.0.so*"])),
        "EGL/GLES": bool(_glob_names(root, ["usr/lib/libEGL*.so*", "usr/lib/*/libEGL*.so*",
                                            "vendor/lib*/libEGL*.so*"])),
        "D-Bus": bool(_glob_names(root, ["usr/bin/dbus-daemon", "bin/dbus-daemon"])),
        "systemd": (root / "lib/systemd/systemd").exists()
                   or (root / "usr/lib/systemd/systemd").exists(),
    }
    services = systemd_services(root)
    kw = tuple(k.lower() for k in hmi_keywords)
    hmi_services = [s for s in services if any(k in s[0].lower() for k in kw)]
    executables = []
    for p in root.rglob("*"):
        try:
            if p.is_symlink() or not p.is_file() or not os.access(p, os.X_OK):
                continue
            rel = p.relative_to(root)
            if rel.parts and rel.parts[0] in ("proc", "sys", "dev"):
                continue
            info = read_elf(p)
            if info and info["type"] in (2, 3) and ".so" not in p.name:
                executables.append((p.stat().st_size, str(rel)))
        except OSError:
            continue
    executables.sort(reverse=True)
    keyword_bins = [e for e in executables if any(k in e[1].lower() for k in kw)]
    return {
        "root": str(root),
        "arch": arch,
        "os_release": os_release,
        "init": init,
        "runtimes": runtimes,
        "qt_platform_plugins": qt_platforms,
        "services": services,
        "hmi_services": hmi_services,
        "largest_executables": executables[:15],
        "keyword_executables": keyword_bins[:15],
    }


def format_analysis(a):
    out = [f"■ 루트 파일 시스템: {a['root']}"]
    arch = a["arch"]
    out.append(f"  아키텍처: {arch['arch_detail'] if arch else '판별 불가 (Linux rootfs가 아닐 수 있음)'}")
    if arch and arch.get("interp"):
        out.append(f"  동적 로더: {arch['interp']}")
    if a["os_release"]:
        first = " / ".join(a["os_release"].splitlines()[:3])
        out.append(f"  OS 정보: {first}")
    out.append(f"  init: {a['init'] or '없음'}")
    present = [k for k, v in a["runtimes"].items() if v]
    out.append(f"  런타임: {', '.join(present) or '감지 안 됨'}")
    if a["qt_platform_plugins"]:
        out.append(f"  Qt 플랫폼 플러그인: {', '.join(a['qt_platform_plugins'])}")
    if a["hmi_services"]:
        out.append("  HMI로 보이는 서비스:")
        out += [f"    - {n}: {e}" for n, e in a["hmi_services"][:10]]
    elif a["services"]:
        out.append(f"  systemd 서비스 {len(a['services'])}개 (HMI 키워드와 일치하는 것 없음)")
    if a["keyword_executables"]:
        out.append("  이름이 HMI 키워드와 맞는 실행 파일:")
        out += [f"    - /{p} ({s:,}B)" for s, p in a["keyword_executables"][:10]]
    if a["largest_executables"]:
        out.append("  가장 큰 실행 파일 (HMI 본체 후보):")
        out += [f"    - /{p} ({s:,}B)" for s, p in a["largest_executables"][:10]]
    return "\n".join(out)
