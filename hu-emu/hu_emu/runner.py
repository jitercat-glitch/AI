"""QEMU로 루트 파일 시스템을 실행한다.

user 모드: binfmt_misc + chroot로 ARM 사용자 공간을 PC에서 그대로 실행 (가장 현실적).
system 모드: qemu-system의 virt 보드에 커널을 부팅하고 rootfs를 디스크로 붙인다.
"""

import os
import platform
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from .rootfs import QEMU_ARCH, detect_arch

BINFMT_DIR = Path("/proc/sys/fs/binfmt_misc")

# qemu 소스의 scripts/qemu-binfmt-conf.sh 와 같은 값
BINFMT = {
    "aarch64": (r"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xb7\x00",
                r"\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff"),
    "arm": (r"\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00",
            r"\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff"),
}

HOST_ARCH = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64",
             "armv7l": "arm", "i686": "i386"}.get(platform.machine().lower(), platform.machine())


class RunError(SystemExit):
    pass


def qemu_user_binary(arch):
    name = QEMU_ARCH.get(arch, arch)
    for cand in (f"qemu-{name}-static", f"qemu-{name}"):
        path = shutil.which(cand)
        if path:
            return path
    raise RunError(f"qemu-{name}-static을 찾을 수 없습니다. "
                   "예: sudo apt install qemu-user-static")


def binfmt_status(arch):
    """('ok'|'missing'|'unavailable', 상세)"""
    if not (BINFMT_DIR / "register").exists():
        try:
            subprocess.run(["mount", "-t", "binfmt_misc", "binfmt_misc", str(BINFMT_DIR)],
                           check=True, capture_output=True)
        except (OSError, subprocess.CalledProcessError):
            return "unavailable", "binfmt_misc를 마운트할 수 없습니다"
    name = QEMU_ARCH.get(arch, arch)
    for entry in (BINFMT_DIR / f"hu-emu-{name}", BINFMT_DIR / f"qemu-{name}"):
        if entry.exists():
            text = entry.read_text()
            if text.startswith("enabled") and "flags:" in text:
                flags = text.split("flags:")[1].split("\n")[0]
                # F: chroot 안에서도 인터프리터 사용, P: 자식 프로세스의 argv[0] 보존
                if "F" in flags and "P" in flags:
                    return "ok", entry.name
    return "missing", ""


def register_binfmt(arch, qemu):
    if arch not in BINFMT:
        raise RunError(f"{arch}용 binfmt 설정이 없습니다")
    magic, mask = BINFMT[arch]
    name = f"hu-emu-{QEMU_ARCH[arch]}"
    stale = BINFMT_DIR / name
    if stale.exists():
        stale.write_text("-1")
    # P 플래그는 QEMU 6.0 이상 + 커널 5.12 이상에서 별도 래퍼 없이 동작한다
    line = f":{name}:M::{magic}:{mask}:{qemu}:PF"
    with open(BINFMT_DIR / "register", "w") as f:
        f.write(line)
    print(f"[hu-emu] binfmt_misc에 {name} 등록 (해제: echo -1 > {BINFMT_DIR / name})")


def display_env(profile, display, root):
    w, h = profile["display"]["width"], profile["display"]["height"]
    plugins = {p.name for p in Path(root).glob("**/platforms/libq*.so")} if display == "auto" else set()
    if display == "auto":
        if "libqvnc.so" in plugins:
            display = "vnc"
        elif os.environ.get("DISPLAY") and "libqxcb.so" in plugins:
            display = "x11"
        else:
            display = "offscreen"
        print(f"[hu-emu] 화면 출력: {display}")
    env, binds, helper = {}, [], None
    if display == "vnc":
        env["QT_QPA_PLATFORM"] = f"vnc:size={w}x{h}:port=5900"
        print(f"[hu-emu] VNC 뷰어로 localhost:5900 에 접속하세요 ({w}x{h})")
    elif display == "x11":
        env["QT_QPA_PLATFORM"] = "xcb"
        xephyr = shutil.which("Xephyr")
        if xephyr and os.environ.get("DISPLAY"):
            env["DISPLAY"] = ":17"
            helper = [xephyr, ":17", "-screen", f"{w}x{h}", "-title",
                      f"hu-emu {profile['name']}", "-ac"]
        elif os.environ.get("DISPLAY"):
            env["DISPLAY"] = os.environ["DISPLAY"]
        else:
            raise RunError("x11 출력에는 DISPLAY가 필요합니다 (또는 --display vnc)")
        binds.append(("/tmp/.X11-unix", "/tmp/.X11-unix"))
    elif display == "offscreen":
        env["QT_QPA_PLATFORM"] = "offscreen"
    return env, binds, helper


def _guest_env(profile, extra_env, disp_env):
    env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
           "HOME": "/root", "TERM": os.environ.get("TERM", "xterm")}
    env.update(profile.get("env", {}))
    env.update(disp_env)
    env.update(extra_env)
    return env


def build_user_command(root, profile, cmd, display="auto", extra_env=None, binds=(),
                       use_binfmt=True):
    """(argv, 보조 프로세스 argv|None, 설명)"""
    root = Path(root).resolve()
    if not root.is_dir():
        raise RunError(f"rootfs 디렉터리가 없습니다: {root}")
    arch_info = detect_arch(root)
    if not arch_info:
        raise RunError("rootfs에서 ELF 실행 파일을 찾지 못했습니다 (Linux rootfs가 아닐 수 있음)")
    arch = arch_info["arch"]
    disp_env, disp_binds, helper = display_env(profile, display, root)
    env = _guest_env(profile, extra_env or {}, disp_env)
    cmd = list(cmd) or ["/bin/sh"]

    native = arch == HOST_ARCH
    if not native and not use_binfmt:
        qemu = qemu_user_binary(arch)
        guest = root / cmd[0].lstrip("/")
        env["QEMU_LD_PREFIX"] = str(root)
        argv = ["env", "-i"] + [f"{k}={v}" for k, v in env.items()] + \
               [qemu, "-L", str(root), str(guest)] + cmd[1:]
        return argv, helper, f"{arch} (qemu -L 단일 프로세스 모드)"

    all_binds = list(disp_binds) + list(binds)
    xdg = env.get("XDG_RUNTIME_DIR")
    lines = ["set -e", f"R={shlex.quote(str(root))}",
             'mkdir -p "$R/proc" "$R/sys" "$R/dev" "$R/tmp"',
             'mount -t proc proc "$R/proc"',
             'mount -t sysfs sys "$R/sys" 2>/dev/null || mount --rbind /sys "$R/sys" || true',
             'mount --rbind /dev "$R/dev"',
             'mount -t tmpfs tmpfs "$R/tmp"']
    if xdg:
        lines.append(f'mkdir -p "$R"{shlex.quote(xdg)} && chmod 700 "$R"{shlex.quote(xdg)}')
    for host, guest in all_binds:
        g = shlex.quote(guest)
        lines.append(f'if [ -d {shlex.quote(host)} ]; then mkdir -p "$R"{g}; '
                     f'else mkdir -p "$(dirname "$R"{g})"; touch "$R"{g}; fi')
        lines.append(f'mount --bind {shlex.quote(host)} "$R"{g}')
    if Path("/etc/resolv.conf").exists():
        lines.append('[ -e "$R/etc/resolv.conf" ] || cp -L /etc/resolv.conf "$R/etc/resolv.conf" '
                     "2>/dev/null || true")
    env_args = " ".join(shlex.quote(f"{k}={v}") for k, v in env.items())
    chroot = shutil.which("chroot") or "/usr/sbin/chroot"
    lines.append(f'exec env -i {env_args} {chroot} "$R" "$@"')
    script = "\n".join(lines)
    unshare = shutil.which("unshare")
    if not unshare:
        raise RunError("unshare(util-linux)가 필요합니다")
    argv = [unshare, "--mount", "--propagation", "private", "--fork",
            "sh", "-c", script, "hu-emu"] + cmd
    return argv, helper, f"{arch} ({'네이티브' if native else 'qemu-user + binfmt'} chroot)"


def run_user(root, profile, cmd, display="auto", extra_env=None, binds=(), dry_run=False):
    if sys.platform != "linux":
        raise RunError("user 모드는 Linux에서만 동작합니다 (Windows는 WSL2, macOS는 Linux VM 사용)")
    root = Path(root).resolve()
    arch_info = detect_arch(root)
    use_binfmt = True
    if arch_info and arch_info["arch"] != HOST_ARCH and not dry_run:
        if os.geteuid() != 0:
            raise RunError("user 모드는 root 권한이 필요합니다 (sudo로 실행하세요)")
        state, _detail = binfmt_status(arch_info["arch"])
        if state == "missing":
            register_binfmt(arch_info["arch"], qemu_user_binary(arch_info["arch"]))
        elif state == "unavailable":
            print("[hu-emu] ⚠ binfmt_misc를 쓸 수 없어 단일 프로세스 모드로 실행합니다. "
                  "실행한 프로그램이 다른 ARM 프로그램을 띄우면 실패합니다.")
            use_binfmt = False
    elif os.geteuid() != 0 and not dry_run:
        raise RunError("user 모드는 root 권한이 필요합니다 (sudo로 실행하세요)")
    argv, helper, desc = build_user_command(root, profile, cmd, display, extra_env, binds,
                                            use_binfmt)
    print(f"[hu-emu] {profile['name']} / {desc}")
    if dry_run:
        if helper:
            print("보조:", shlex.join(helper))
        print(shlex.join(argv))
        return 0
    helper_proc = subprocess.Popen(helper) if helper else None
    try:
        return subprocess.call(argv)
    finally:
        if helper_proc:
            helper_proc.terminate()


def _dir_size(d):
    total = 0
    for p in Path(d).rglob("*"):
        try:
            if p.is_file() and not p.is_symlink():
                total += p.stat().st_size
        except OSError:
            pass
    return total


def make_disk_image(root, image):
    """rootfs 디렉터리로 ext4 디스크 이미지를 만든다 (mke2fs -d)."""
    mke2fs = shutil.which("mke2fs") or shutil.which("mkfs.ext4")
    if not mke2fs:
        raise RunError("mke2fs(e2fsprogs)가 필요합니다")
    size_mb = int(_dir_size(root) * 1.3 / 1024 / 1024) + 256
    image = Path(image)
    image.parent.mkdir(parents=True, exist_ok=True)
    print(f"[hu-emu] 디스크 이미지 생성: {image} ({size_mb} MB)")
    subprocess.run([mke2fs, "-q", "-F", "-t", "ext4", "-d", str(root), str(image), f"{size_mb}M"],
                   check=True)
    return image


def find_kernel(root):
    boot = Path(root) / "boot"
    for name in ("Image", "Image.gz", "zImage", "vmlinuz", "uImage"):
        hits = sorted(boot.glob(name + "*")) if boot.is_dir() else []
        if hits:
            return hits[0]
    return None


def build_system_command(profile, arch, kernel, disk=None, initrd=None, dtb=None,
                         display="auto", append=""):
    sysp = profile["system"]
    w, h = profile["display"]["width"], profile["display"]["height"]
    qemu = {"aarch64": "qemu-system-aarch64", "arm": "qemu-system-arm"}.get(arch)
    if not qemu:
        raise RunError(f"system 모드가 지원하지 않는 아키텍처: {arch}")
    argv = [shutil.which(qemu) or qemu, "-M", sysp["machine"], "-cpu", sysp["cpu"],
            "-smp", str(sysp["smp"]), "-m", str(sysp["memory_mb"]),
            "-kernel", str(kernel)]
    if initrd:
        argv += ["-initrd", str(initrd)]
    if dtb:
        argv += ["-dtb", str(dtb)]
    cmdline = sysp["cmdline"]
    if disk:
        argv += ["-drive", f"file={disk},if=virtio,format=raw"]
        cmdline = f"root=/dev/vda {cmdline}"
    argv += ["-device", f"virtio-gpu-pci,xres={w},yres={h}",
             "-device", "virtio-tablet-pci", "-device", "virtio-keyboard-pci",
             "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
             "-serial", "mon:stdio"]
    if display == "auto":
        display = "x11" if os.environ.get("DISPLAY") else "vnc"
    argv += ["-display", {"x11": "gtk", "vnc": "vnc=:0", "offscreen": "none",
                          "none": "none"}[display]]
    if display == "vnc":
        print("[hu-emu] VNC 뷰어로 localhost:5900 에 접속하세요")
    argv += ["-append", f"{cmdline} {append}".strip()]
    return argv


def run_system(profile, root=None, kernel=None, disk=None, initrd=None, dtb=None,
               display="auto", append="", workdir=None, dry_run=False):
    arch = None
    if root:
        info = detect_arch(root)
        arch = info["arch"] if info else None
    if not arch and kernel:
        arch = "aarch64" if "Image" in Path(kernel).name else None
    if not arch:
        raise RunError("아키텍처를 알 수 없습니다. --rootfs를 지정하세요")
    if not kernel and root:
        kernel = find_kernel(root)
        if kernel:
            print(f"[hu-emu] rootfs의 커널 사용: {kernel} "
                  "(제조사 커널은 virt 보드에서 부팅되지 않을 가능성이 큽니다)")
    if not kernel:
        raise RunError("--kernel이 필요합니다. 순정 커널은 실제 SoC 전용이라 virt 보드에서는 "
                       "대개 부팅되지 않으므로, 같은 아키텍처의 일반 커널(예: 배포판 arm64 커널)"
                       "을 쓰는 것을 권장합니다")
    if not disk and root:
        disk = Path(workdir or ".") / f"{profile['id']}-rootfs.ext4"
        if not dry_run:
            make_disk_image(root, disk)
    argv = build_system_command(profile, arch, kernel, disk, initrd, dtb, display, append)
    print(f"[hu-emu] {profile['name']} / system 모드 ({arch})")
    if dry_run:
        print(shlex.join(argv))
        return 0
    return subprocess.call(argv)
