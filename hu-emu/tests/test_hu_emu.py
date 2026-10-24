"""hu-emu 테스트. 실행: python3 -m unittest discover -s tests

ARM busybox가 필요한 테스트는 HU_EMU_TEST_BUSYBOX(aarch64 정적 busybox 경로)가
없으면 건너뛴다. 예) Ubuntu: apt download busybox-static:arm64 후 dpkg-deb -x
"""

import gzip
import io
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hu_emu import extract, rootfs, runner, scan  # noqa: E402
from hu_emu.profiles import list_profiles, load_profile  # noqa: E402

BUSYBOX = os.environ.get("HU_EMU_TEST_BUSYBOX")
HAVE = {t: bool(shutil.which(t)) for t in ("mksquashfs", "unsquashfs", "mke2fs", "debugfs")}


def fake_elf(machine=0xB7, cls=2):
    """실행은 안 되지만 헤더는 올바른 ELF."""
    hdr = bytearray(64)
    hdr[:4] = b"\x7fELF"
    hdr[4], hdr[5], hdr[6] = cls, 1, 1
    struct.pack_into("<HH", hdr, 16, 2, machine)
    return bytes(hdr) + b"\0" * 64


def make_rootfs(d, busybox=None, machine=0xB7):
    d = Path(d)
    for sub in ("bin", "etc", "usr/bin", "lib/systemd/system"):
        (d / sub).mkdir(parents=True, exist_ok=True)
    if busybox:
        shutil.copy(busybox, d / "bin/busybox")
        for applet in ("sh", "echo", "uname", "cat"):
            os.symlink("/bin/busybox", d / "bin" / applet)
    else:
        (d / "bin/busybox").write_bytes(fake_elf(machine))
    (d / "bin/busybox").chmod(0o755)
    (d / "usr/bin/NaviHmi").write_bytes(fake_elf(machine) + b"x" * 5000)
    (d / "usr/bin/NaviHmi").chmod(0o755)
    (d / "etc/os-release").write_text('NAME="TestHU"\n')
    (d / "lib/systemd/system/navi-hmi.service").write_text(
        "[Service]\nExecStart=/usr/bin/NaviHmi --start\n")
    return d


def write_gpt(path, parts, sector=512):
    """parts: [(이름, 데이터 bytes)] → GPT 디스크 이미지."""
    lba = 34
    layout = []
    for name, data in parts:
        n = (len(data) + sector - 1) // sector
        layout.append((name, data, lba, lba + n - 1))
        lba += n
    with open(path, "wb") as f:
        f.truncate((lba + 34) * sector)
        hdr = bytearray(92)
        hdr[:8] = b"EFI PART"
        struct.pack_into("<II", hdr, 8, 0x00010000, 92)
        struct.pack_into("<Q", hdr, 72, 2)
        struct.pack_into("<II", hdr, 80, 128, 128)
        f.seek(sector)
        f.write(hdr)
        for i, (name, data, first, last) in enumerate(layout):
            e = bytearray(128)
            e[:16] = b"\x11" * 16
            struct.pack_into("<QQ", e, 32, first, last)
            e[56:56 + len(name) * 2] = name.encode("utf-16-le")
            f.seek(2 * sector + i * 128)
            f.write(e)
            f.seek(first * sector)
            f.write(data)


class ProfileTest(unittest.TestCase):
    def test_both_models_available(self):
        ids = {p["id"] for p in list_profiles()}
        self.assertEqual(ids, {"ccnc", "gen5"})
        for pid in ids:
            p = load_profile(pid)
            self.assertGreater(p["display"]["width"], 0)


class ScanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_random_data_is_flagged_encrypted(self):
        p = self.tmp / "enc.bin"
        p.write_bytes(os.urandom(512 * 1024))
        self.assertTrue(scan.inspect_file(p)["likely_encrypted"])

    def test_gzip_is_not_flagged_encrypted(self):
        p = self.tmp / "a.gz"
        p.write_bytes(gzip.compress(os.urandom(256 * 1024)))
        info = scan.inspect_file(p)
        self.assertEqual(info["header"], "gzip")
        self.assertFalse(info["likely_encrypted"])

    def test_signature_across_chunk_boundary(self):
        p = self.tmp / "big.bin"
        off = scan.CHUNK - 2  # 매직이 두 청크에 걸침
        with open(p, "wb") as f:
            f.truncate(scan.CHUNK + 4096)
            f.seek(off)
            f.write(b"\x27\x05\x19\x56" + b"\0" * 8 + struct.pack(">I", 100))
        hits = scan.scan_signatures(p).get("uimage", {}).get("hits", [])
        self.assertIn((off, 164), hits)


class ExtractTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.log = extract.Log(verbose=False)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _single_rootfs(self, out):
        cands = rootfs.find_rootfs_candidates(out)
        self.assertEqual(len(cands), 1, cands)
        return cands[0]

    def test_android_sparse_roundtrip(self):
        blk = 4096
        raw = os.urandom(blk * 2)
        buf = io.BytesIO()
        buf.write(struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, blk, 5, 3, 0))
        buf.write(struct.pack("<HHII", 0xCAC1, 0, 2, 12 + len(raw)) + raw)
        buf.write(struct.pack("<HHII", 0xCAC2, 0, 2, 16) + b"\xab\xcd\xef\x01")
        buf.write(struct.pack("<HHII", 0xCAC3, 0, 1, 12))
        src, dst = self.tmp / "s.img", self.tmp / "r.img"
        src.write_bytes(buf.getvalue())
        extract.unsparse(src, dst)
        out = dst.read_bytes()
        self.assertEqual(len(out), blk * 5)
        self.assertEqual(out[:blk * 2], raw)
        self.assertEqual(out[blk * 2:blk * 4], b"\xab\xcd\xef\x01" * (blk // 2))

    def test_cpio_newc(self):
        def entry(name, mode, data=b""):
            nb = name.encode() + b"\0"
            fields = [0, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nb), 0]
            h = b"070701" + b"".join(b"%08X" % v for v in fields)
            out = h + nb
            out += b"\0" * ((4 - len(out) % 4) % 4) + data
            return out + b"\0" * ((4 - len(data) % 4) % 4)
        blob = (entry("bin", 0o040755) + entry("bin/init", 0o100755, b"#!/bin/sh\n")
                + entry("bin/sh", 0o120777, b"busybox") + entry("TRAILER!!!", 0))
        src = self.tmp / "initrd.cpio"
        src.write_bytes(blob)
        extract.extract_cpio(src, self.tmp / "o")
        self.assertEqual((self.tmp / "o/bin/init").read_bytes(), b"#!/bin/sh\n")
        self.assertEqual(os.readlink(self.tmp / "o/bin/sh"), "busybox")

    @unittest.skipUnless(HAVE["mksquashfs"] and HAVE["unsquashfs"], "squashfs-tools 필요")
    def test_tar_gz_package_with_squashfs(self):
        make_rootfs(self.tmp / "root")
        sq = self.tmp / "system.img"
        subprocess.run(["mksquashfs", str(self.tmp / "root"), str(sq), "-quiet", "-noappend"],
                       check=True, stdout=subprocess.DEVNULL)
        pkg = self.tmp / "update.tar.gz"
        with tarfile.open(pkg, "w:gz") as tf:
            tf.add(sq, "update/system.img")
            enc = self.tmp / "navi.dat"
            enc.write_bytes(os.urandom(200 * 1024))
            tf.add(enc, "update/navi.dat")
        extract.extract(pkg, self.tmp / "out", self.log)
        root = self._single_rootfs(self.tmp / "out")
        self.assertTrue((root / "usr/bin/NaviHmi").exists())
        self.assertTrue(any(p.endswith("navi.dat") for p in self.log.encrypted))

    @unittest.skipUnless(HAVE["mksquashfs"] and HAVE["unsquashfs"], "squashfs-tools 필요")
    def test_carve_squashfs_from_raw_blob(self):
        make_rootfs(self.tmp / "root")
        sq = self.tmp / "s.img"
        subprocess.run(["mksquashfs", str(self.tmp / "root"), str(sq), "-quiet", "-noappend"],
                       check=True, stdout=subprocess.DEVNULL)
        blob = self.tmp / "dump.bin"
        blob.write_bytes(b"\0" * 12345 + sq.read_bytes() + b"\xff" * 5000)
        extract.extract(blob, self.tmp / "out", self.log)
        self._single_rootfs(self.tmp / "out")

    @unittest.skipUnless(HAVE["mke2fs"] and HAVE["debugfs"], "e2fsprogs 필요")
    def test_gpt_emmc_dump_with_ext4(self):
        make_rootfs(self.tmp / "root")
        ext = self.tmp / "root.ext4"
        subprocess.run(["mke2fs", "-q", "-t", "ext4", "-d", str(self.tmp / "root"),
                        str(ext), "8M"], check=True)
        disk = self.tmp / "emmc.bin"
        write_gpt(disk, [("boot_a", b"\0" * 4096), ("system_a", ext.read_bytes())])
        self.assertEqual([p[0] for p in extract.parse_gpt(disk)], ["boot_a", "system_a"])
        extract.extract(disk, self.tmp / "out", self.log)
        root = self._single_rootfs(self.tmp / "out")
        self.assertIn("system_a", str(root))


class RootfsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_analyze_detects_arch_and_hmi(self):
        root = make_rootfs(self.tmp / "r", machine=0x28)
        a = rootfs.analyze(root, load_profile("gen5")["hmi_keywords"])
        self.assertEqual(a["arch"]["arch"], "arm")
        self.assertEqual(a["hmi_services"], [("navi-hmi.service", "/usr/bin/NaviHmi --start")])
        self.assertIn("usr/bin/NaviHmi", [p for _s, p in a["keyword_executables"]])


class RunnerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_system_command_uses_profile_resolution(self):
        for pid in ("ccnc", "gen5"):
            p = load_profile(pid)
            argv = runner.build_system_command(p, "aarch64", "/k/Image", "/d.img",
                                               display="vnc")
            w, h = p["display"]["width"], p["display"]["height"]
            self.assertIn(f"virtio-gpu-pci,xres={w},yres={h}", argv)
            self.assertIn("-kernel", argv)
            self.assertTrue(argv[-1].startswith("root=/dev/vda"))

    def test_user_command_dry_build(self):
        root = make_rootfs(self.tmp / "r")
        argv, helper, desc = runner.build_user_command(
            root, load_profile("ccnc"), ["/usr/bin/NaviHmi"], display="offscreen")
        self.assertIsNone(helper)
        self.assertEqual(argv[-1], "/usr/bin/NaviHmi")
        self.assertIn("QT_QPA_PLATFORM=offscreen", argv[7])

    @unittest.skipUnless(BUSYBOX and os.geteuid() == 0 and shutil.which("qemu-aarch64-static"),
                         "HU_EMU_TEST_BUSYBOX, root, qemu-user-static 필요")
    def test_user_mode_runs_arm_shell(self):
        root = make_rootfs(self.tmp / "r", busybox=BUSYBOX)
        state, _ = runner.binfmt_status("aarch64")
        if state == "missing":
            runner.register_binfmt("aarch64", runner.qemu_user_binary("aarch64"))
        argv, _h, _d = runner.build_user_command(
            root, load_profile("gen5"), ["/bin/sh", "-c", "uname -m; cat /etc/os-release"],
            display="none")
        out = subprocess.run(argv, capture_output=True, text=True, check=True).stdout
        self.assertIn("aarch64", out)
        self.assertIn("TestHU", out)
        # 네임스페이스 안에서만 마운트했으므로 끝나면 남지 않아야 한다
        self.assertEqual(list((root / "proc").iterdir()), [])

    @unittest.skipUnless(BUSYBOX and shutil.which("qemu-aarch64-static"),
                         "HU_EMU_TEST_BUSYBOX, qemu-user-static 필요")
    def test_single_process_fallback(self):
        root = make_rootfs(self.tmp / "r", busybox=BUSYBOX)
        argv, _h, desc = runner.build_user_command(
            root, load_profile("ccnc"), ["/bin/busybox", "uname", "-m"], display="none",
            use_binfmt=False)
        self.assertIn("-L", desc)
        out = subprocess.run(argv, capture_output=True, text=True, check=True).stdout
        self.assertEqual(out.strip(), "aarch64")


if __name__ == "__main__":
    unittest.main()
