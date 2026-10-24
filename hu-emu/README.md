# hu-emu — 현대·기아 헤드유닛 펌웨어 에뮬레이터

**ccNC**와 **표준형 5세대** 내비게이션의 펌웨어(리눅스 루트 파일 시스템)를 PC에서
QEMU로 실행하는 도구입니다. 시작할 때 두 모델 중 하나를 고르고, 모델마다 펌웨어와
설정(해상도, 메모리 등)을 따로 관리합니다.

```
현대·기아 헤드유닛 에뮬레이터 hu-emu 0.1.0

  1) ccNC (12.3")  — 펌웨어 미등록
  2) 표준형 5세대 (10.25")  — ✓ 펌웨어 등록됨
```

## 먼저 알아둘 점

- **펌웨어는 들어 있지 않습니다.** 본인 차량의 헤드유닛에서 직접 덤프한 이미지
  (eMMC 덤프, 파티션 이미지 등)를 사용하세요. 펌웨어를 배포하면 안 됩니다.
- **암호화된 업데이트 파일은 복호화하지 않습니다.** 내비게이션 업데이트로 받는
  패키지 대부분은 암호화되어 있습니다. 이 도구는 그런 파일을 찾아서 알려 주기만 합니다.
- **순정 HMI가 바로 뜨지는 않을 가능성이 큽니다.** 실제 헤드유닛 프로그램은 전용 SoC의
  GPU 드라이버, CAN·차량 신호, 제조사 서비스(D-Bus 등)에 의존합니다. PC에서는 이것들이
  없어서 대개 중간에 멈춥니다. 이 도구는 "ARM 펌웨어를 PC에서 띄우고 살펴보는 환경"까지를
  만들어 주고, 그다음(빠진 서비스 흉내 내기 등)은 분석하면서 채워 나가야 합니다.
- 실제 차량 네트워크에 연결하지 마세요.

## 준비물

Linux PC가 필요합니다 (Windows는 WSL2, macOS는 Linux VM). Ubuntu/Debian 기준:

```bash
sudo apt install python3 qemu-user-static qemu-system-arm squashfs-tools e2fsprogs
```

Python 표준 라이브러리만 씁니다. 따로 `pip install`할 것은 없습니다.

## 사용법

### 대화형 메뉴

```bash
cd hu-emu
sudo python3 -m hu_emu
```

모델(1 또는 2)을 고른 뒤 메뉴에서 펌웨어 가져오기 → 분석 → 실행 순서로 진행합니다.

### 명령줄

```bash
# 두 모델 프로필과 등록 상태 보기
python3 -m hu_emu profiles

# 펌웨어 파일 구조·암호화 여부 검사
python3 -m hu_emu inspect emmc_dump.bin

# 펌웨어를 풀어 해당 모델에 등록 (rootfs를 자동으로 찾음)
sudo python3 -m hu_emu setup --profile ccnc emmc_dump.bin
sudo python3 -m hu_emu setup --profile gen5 gen5_system.img

# rootfs 분석: 아키텍처, Qt/Wayland 같은 런타임, HMI 서비스·실행 파일 후보
python3 -m hu_emu analyze --profile ccnc

# user 모드: ARM rootfs 안의 셸 (기본 명령은 /bin/sh)
sudo python3 -m hu_emu run --profile ccnc

# user 모드로 HMI 실행 (Qt 앱이면 VNC로 1920x720 화면 확인)
sudo python3 -m hu_emu run --profile gen5 --display vnc -- /usr/bin/HomeApp

# system 모드: 커널을 부팅하고 rootfs를 디스크로 연결
sudo python3 -m hu_emu run --profile ccnc --mode system --kernel Image --display x11

# 실행하지 않고 실제로 실행될 명령만 보기
python3 -m hu_emu run --profile ccnc --mode system --kernel Image --dry-run
```

`setup`으로 푼 결과는 `hu-emu/workspace/<모델>/`에 저장됩니다. 위치를 바꾸려면
`HU_EMU_WORKSPACE` 환경 변수를 쓰세요.

## 동작 방식

| 단계 | 하는 일 |
|---|---|
| `inspect` | 파일 전체에서 GPT, squashfs, ext4, Android sparse, UBI, uImage, DTB, zip/tar/gzip/xz 등의 시그니처를 찾고, 엔트로피로 암호화 여부를 추정 |
| `extract`/`setup` | 형식에 맞게 재귀적으로 풂: zip, tar(.gz/.xz/.bz2), squashfs, ext2/3/4, Android sparse, **GPT 디스크(eMMC 덤프)의 파티션**, uImage, cpio. 알 수 없는 바이너리 안에 박힌 squashfs/ext4도 잘라 냄 |
| `analyze` | ELF 헤더로 아키텍처(aarch64/armhf 등) 판별, 동적 로더, Qt5/Qt6·Wayland·GStreamer·EGL·D-Bus·systemd 여부, Qt 플랫폼 플러그인, systemd 서비스의 `ExecStart`, HMI 실행 파일 후보 |
| `run --mode user` | binfmt_misc(`PF` 플래그)로 `qemu-<arch>-static`을 등록하고, 별도 마운트 네임스페이스에서 `/proc`, `/sys`, `/dev`를 연결한 뒤 rootfs로 `chroot`. 종료하면 마운트는 자동으로 사라짐 |
| `run --mode system` | rootfs로 ext4 디스크 이미지를 만들고, `qemu-system-aarch64`(또는 `-arm`)의 `virt` 보드에 모델 해상도의 virtio-gpu, 터치 대신 쓸 태블릿 입력, 네트워크를 붙여 부팅 |

### 어느 모드를 써야 하나

- **user 모드부터 쓰세요.** 커널 없이 ARM 프로그램을 PC 커널 위에서 그대로 실행하므로
  가장 잘 됩니다. HMI 프로그램을 하나씩 띄워 보고 무엇이 없어서 멈추는지 확인하기 좋습니다.
- **system 모드**는 init부터 전체 부팅을 보고 싶을 때 씁니다. 순정 커널은 실제 SoC 전용이라
  `virt` 보드에서는 대개 부팅되지 않습니다. 같은 아키텍처의 일반 커널(예: 배포판 arm64 커널)에
  순정 rootfs를 붙이는 방법을 권장합니다.

### 화면 출력 (`--display`)

| 값 | user 모드 | system 모드 |
|---|---|---|
| `auto` | rootfs에 Qt VNC 플러그인이 있으면 `vnc`, X 화면이 있고 xcb 플러그인이 있으면 `x11`, 둘 다 아니면 `offscreen` | X 화면이 있으면 `x11`, 없으면 `vnc` |
| `vnc` | `QT_QPA_PLATFORM=vnc:size=1920x720:port=5900` | QEMU VNC `:0` (포트 5900) |
| `x11` | Xephyr가 있으면 모델 해상도의 창을 띄워 연결, 없으면 현재 `$DISPLAY` 사용 | QEMU GTK 창 |
| `offscreen` | Qt를 화면 없이 실행 (로그만 확인) | 화면 없음 |

다른 방식(eglfs, wayland 등)은 `--env QT_QPA_PLATFORM=...`로 직접 지정할 수 있습니다.

## 모델 프로필

`hu_emu/profiles/ccnc.json`, `hu_emu/profiles/gen5.json`에 해상도, VM 메모리·코어 수,
커널 명령줄, 게스트 환경 변수, HMI 후보를 찾을 키워드가 들어 있습니다. 기본값은 에뮬레이터용
추정치이므로 펌웨어를 분석해서 확인한 값이 있으면 이 파일을 고치세요.

## 테스트

```bash
python3 -m unittest discover -s tests
```

ARM 바이너리를 실제로 실행하는 테스트는 root 권한과 `qemu-user-static`, 그리고
`HU_EMU_TEST_BUSYBOX`(aarch64 정적 busybox 경로)가 있을 때만 돌아갑니다.

```bash
apt download busybox-static:arm64   # arm64 저장소가 설정된 경우
dpkg-deb -x busybox-static_*_arm64.deb bb
sudo HU_EMU_TEST_BUSYBOX=$PWD/bb/usr/bin/busybox python3 -m unittest discover -s tests
```
