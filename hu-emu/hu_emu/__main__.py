"""hu-emu 명령줄 / 대화형 메뉴."""

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, extract, rootfs, runner, scan
from .profiles import list_profiles, load_profile

PROJECT_DIR = Path(__file__).resolve().parent.parent
WORKSPACE = Path(os.environ.get("HU_EMU_WORKSPACE", PROJECT_DIR / "workspace"))


def workspace(profile_id):
    return WORKSPACE / profile_id


def load_state(profile_id):
    p = workspace(profile_id) / "state.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def save_state(profile_id, state):
    p = workspace(profile_id) / "state.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def resolve_rootfs(args):
    if getattr(args, "rootfs", None):
        return Path(args.rootfs)
    if getattr(args, "profile", None):
        st = load_state(args.profile)
        if st.get("rootfs"):
            return Path(st["rootfs"])
    raise SystemExit("rootfs를 모릅니다. 먼저 `setup --profile ...`을 실행하거나 --rootfs를 지정하세요")


def cmd_profiles(_args):
    for p in list_profiles():
        d = p["display"]
        st = load_state(p["id"])
        ready = f"  rootfs: {st['rootfs']}" if st.get("rootfs") else "  (펌웨어 미등록)"
        print(f"{p['id']:6} {p['name']}  {d['width']}x{d['height']}{ready}")


def cmd_inspect(args):
    for path in args.paths:
        path = Path(path)
        files = [path] if path.is_file() else sorted(
            p for p in path.rglob("*") if p.is_file() and not p.is_symlink()
            and p.stat().st_size >= extract.MIN_SIZE)
        for f in files:
            print(scan.format_report(scan.inspect_file(f)))


def cmd_extract(args):
    out = Path(args.output)
    log = extract.Log()
    extract.extract(args.input, out, log)
    cands = rootfs.find_rootfs_candidates(out)
    print()
    if cands:
        print("루트 파일 시스템 후보:")
        for c in cands:
            print(f"  - {c}")
    else:
        print("루트 파일 시스템을 찾지 못했습니다.")
    if log.encrypted:
        print("\n암호화되어 건너뛴 파일:")
        for p in log.encrypted:
            print(f"  - {p}")
    return cands


def cmd_setup(args):
    profile = load_profile(args.profile)
    out = workspace(args.profile) / "extracted"
    print(f"[{profile['name']}] 펌웨어 풀기 → {out}")
    args.input, args.output = args.firmware, out
    cands = cmd_extract(args)
    if not cands:
        raise SystemExit(1)
    chosen = cands[0]
    a = rootfs.analyze(chosen, profile.get("hmi_keywords", ()))
    print()
    print(rootfs.format_analysis(a))
    save_state(args.profile, {"firmware": str(Path(args.firmware).resolve()),
                              "rootfs": str(chosen.resolve()),
                              "arch": a["arch"]["arch_detail"] if a["arch"] else None})
    print(f"\n등록 완료. 실행: python3 -m hu_emu run --profile {args.profile}")


def cmd_analyze(args):
    profile = load_profile(args.profile) if args.profile else {}
    root = resolve_rootfs(args)
    a = rootfs.analyze(root, profile.get("hmi_keywords", ()))
    if args.json:
        print(json.dumps(a, ensure_ascii=False, indent=2))
    else:
        print(rootfs.format_analysis(a))


def _parse_env(items):
    env = {}
    for item in items or ():
        k, sep, v = item.partition("=")
        if not sep:
            raise SystemExit(f"--env 형식은 KEY=VALUE 입니다: {item}")
        env[k] = v
    return env


def _parse_binds(items):
    binds = []
    for item in items or ():
        host, sep, guest = item.partition(":")
        binds.append((host, guest if sep else host))
    return binds


def cmd_run(args):
    profile = load_profile(args.profile)
    cmd = args.command[1:] if args.command[:1] == ["--"] else args.command
    if args.mode == "user":
        root = resolve_rootfs(args)
        return runner.run_user(root, profile, cmd, args.display, _parse_env(args.env),
                               _parse_binds(args.bind), args.dry_run)
    root = None
    if args.rootfs or (not args.disk and load_state(args.profile).get("rootfs")):
        root = resolve_rootfs(args)
    return runner.run_system(profile, root, args.kernel, args.disk, args.initrd, args.dtb,
                             args.display, args.append or "", workspace(args.profile),
                             args.dry_run)


def _ask(prompt, default=None):
    suffix = f" [{default}]" if default else ""
    try:
        ans = input(f"{prompt}{suffix}: ").strip()
    except EOFError:
        raise SystemExit(0)
    return ans or default


def menu():
    profiles = list_profiles()
    print(f"현대·기아 헤드유닛 에뮬레이터 hu-emu {__version__}\n")
    for i, p in enumerate(profiles, 1):
        st = load_state(p["id"])
        mark = "✓ 펌웨어 등록됨" if st.get("rootfs") else "펌웨어 미등록"
        print(f"  {i}) {p['name']}  — {mark}")
    sel = _ask("\n에뮬레이션할 모델 번호")
    try:
        profile = profiles[int(sel) - 1]
    except (TypeError, ValueError, IndexError):
        raise SystemExit("잘못된 선택입니다")
    pid = profile["id"]
    while True:
        st = load_state(pid)
        print(f"\n[{profile['name']}]")
        print("  1) 펌웨어 가져오기 (이미지 풀기 + rootfs 등록)")
        print("  2) 펌웨어 파일 검사 (구조·암호화 여부)")
        print("  3) rootfs 분석 (아키텍처, HMI 후보)")
        print("  4) 실행 — user 모드 셸 (chroot)")
        print("  5) 실행 — user 모드로 HMI 프로그램 실행")
        print("  6) 실행 — system 모드 (커널 부팅)")
        print("  0) 종료")
        choice = _ask("선택")
        ns = argparse.Namespace(profile=pid, rootfs=None, display="auto", env=[], bind=[],
                                dry_run=False, json=False, mode="user", command=[],
                                kernel=None, disk=None, initrd=None, dtb=None, append="")
        try:
            if choice == "1":
                ns.firmware = _ask("펌웨어 파일 또는 폴더 경로")
                cmd_setup(ns)
            elif choice == "2":
                ns.paths = [_ask("검사할 파일 또는 폴더", st.get("firmware"))]
                cmd_inspect(ns)
            elif choice == "3":
                cmd_analyze(ns)
            elif choice == "4":
                runner_rc = cmd_run(ns)
                print(f"(종료 코드 {runner_rc})")
            elif choice == "5":
                ns.command = _ask("rootfs 안의 실행 파일 경로 (예: /usr/bin/HomeApp)").split()
                ns.display = _ask("화면 출력 auto/x11/vnc/offscreen", "auto")
                print(f"(종료 코드 {cmd_run(ns)})")
            elif choice == "6":
                ns.mode = "system"
                ns.kernel = _ask("커널 이미지 경로 (비우면 rootfs/boot에서 찾음)")
                ns.dtb = _ask("DTB 경로 (선택)")
                print(f"(종료 코드 {cmd_run(ns)})")
            elif choice == "0":
                return
        except SystemExit as e:
            if e.code not in (None, 0):
                print(f"오류: {e.code}")


def build_parser():
    ap = argparse.ArgumentParser(prog="hu-emu",
                                 description="현대·기아 ccNC / 표준형 5세대 펌웨어 에뮬레이터")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("profiles", help="모델 프로필 목록").set_defaults(func=cmd_profiles)
    sub.add_parser("menu", help="대화형 메뉴").set_defaults(func=lambda a: menu())

    p = sub.add_parser("inspect", help="펌웨어 파일 구조·암호화 여부 검사")
    p.add_argument("paths", nargs="+")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("extract", help="펌웨어 이미지를 재귀적으로 풀기")
    p.add_argument("input")
    p.add_argument("-o", "--output", required=True)
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("setup", help="펌웨어를 풀어 해당 모델의 rootfs로 등록")
    p.add_argument("--profile", required=True, choices=[x["id"] for x in list_profiles()])
    p.add_argument("firmware")
    p.set_defaults(func=cmd_setup)

    p = sub.add_parser("analyze", help="rootfs 분석")
    p.add_argument("--profile", choices=[x["id"] for x in list_profiles()])
    p.add_argument("--rootfs")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("run", help="에뮬레이터 실행")
    p.add_argument("--profile", required=True, choices=[x["id"] for x in list_profiles()])
    p.add_argument("--mode", choices=["user", "system"], default="user")
    p.add_argument("--rootfs")
    p.add_argument("--display", choices=["auto", "x11", "vnc", "offscreen", "none"],
                   default="auto")
    p.add_argument("--env", action="append", metavar="KEY=VALUE")
    p.add_argument("--bind", action="append", metavar="HOST[:GUEST]")
    p.add_argument("--kernel")
    p.add_argument("--initrd")
    p.add_argument("--dtb")
    p.add_argument("--disk", help="system 모드: 이미 만든 raw 디스크 이미지")
    p.add_argument("--append", help="system 모드: 커널 명령줄 추가")
    p.add_argument("--dry-run", action="store_true", help="실행하지 않고 명령만 출력")
    p.add_argument("command", nargs=argparse.REMAINDER,
                   help="user 모드에서 rootfs 안에서 실행할 명령 (기본: /bin/sh)")
    p.set_defaults(func=cmd_run)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not getattr(args, "func", None):
        return menu()
    rc = args.func(args)
    return rc if isinstance(rc, int) else 0


if __name__ == "__main__":
    sys.exit(main())
