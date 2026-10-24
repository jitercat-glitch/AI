"""ccNC / 표준형 5세대 프로필 로딩."""

import json
from pathlib import Path

PROFILE_DIR = Path(__file__).resolve().parent / "profiles"


def list_profiles():
    return [load_profile(p.stem) for p in sorted(PROFILE_DIR.glob("*.json"))]


def load_profile(profile_id):
    path = PROFILE_DIR / f"{profile_id}.json"
    if not path.is_file():
        known = ", ".join(p.stem for p in sorted(PROFILE_DIR.glob("*.json")))
        raise SystemExit(f"알 수 없는 프로필: {profile_id} (사용 가능: {known})")
    with open(path, encoding="utf-8") as f:
        return json.load(f)
