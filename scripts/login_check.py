#!/usr/bin/env python3
"""Prove the school login works, without downloading models or processing lectures.

This is a deliberately small probe: it logs in to WebVPN, completes the iCourse
CAS login, verifies the course API with a real authenticated call, and then
enumerates every subscribed course.  It never downloads a video, runs ASR, or
sends mail, so a login regression can be diagnosed in about a minute instead of
a full run.

Output policy: status codes, counts, presence of known response fields and
redirect categories only.  No response bodies, redirect URLs, cookies or
credentials are printed.

Exit codes: 0 when every configured course was enumerated, 1 otherwise.
"""

from __future__ import annotations

import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.runtime import config
from src.api.icourse import ICourseClient
from src.api.webvpn import SecondFactorError
# The probe deliberately reuses the production retry policy so it fails and
# recovers exactly like a real run does.
from main import login_with_retry


def _configured(value: str) -> str:
    return "configured" if value else "missing"


def main() -> int:
    print("iCourse login check — no models, no lectures, no mail")
    print(f"  student id: {_configured(config.STUDENT_ID)}")
    print(f"  password:   {_configured(config.PASSWORD)}")
    print(f"  UIS TOTP:   {_configured(config.TOTP_SECRET)}")

    if not config.STUDENT_ID or not config.PASSWORD:
        print("FAIL: StuId / UISPsw are not configured")
        return 1

    print("\n[Step] WebVPN + iCourse CAS login (shared retry policy)")
    try:
        vpn = login_with_retry(max_attempts=3)
    except SecondFactorError as exc:
        # Not retryable by design: the runner cannot invent the missing step.
        print(f"FAIL: second factor — {exc}")
        return 1
    except Exception as exc:  # noqa: BLE001 - report the class, never the body
        print(f"FAIL: login — {type(exc).__name__}: {exc}")
        traceback.print_exc(limit=2)
        return 1

    client = ICourseClient(vpn)
    try:
        userinfo = client.get_userinfo()
        print(f"[Step] Course API verified (userinfo fields: {len(userinfo)})")
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL: course API — {type(exc).__name__}: {exc}")
        return 1

    if not config.COURSE_IDS:
        print("No COURSE_IDS configured; login and API are proven, nothing to enumerate.")
        return 0

    failures = 0
    total_lectures = 0
    total_playback = 0
    print(f"\n[Step] Enumerating {len(config.COURSE_IDS)} subscribed course(s)")
    for course_id in config.COURSE_IDS:
        try:
            detail = client.get_course_detail(course_id)
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"  {course_id}: FAILED ({type(exc).__name__})")
            continue
        lectures = detail["lectures"]
        playback = sum(1 for item in lectures if item.get("has_playback"))
        total_lectures += len(lectures)
        total_playback += playback
        print(
            f"  {course_id}: {detail['title']} / {detail['teacher']} — "
            f"{len(lectures)} lecture(s), {playback} with playback"
        )

    ok_courses = len(config.COURSE_IDS) - failures
    print(
        f"\nSummary: {ok_courses}/{len(config.COURSE_IDS)} course(s) enumerated, "
        f"{total_lectures} lecture(s) total, {total_playback} playable"
    )
    if failures:
        print("FAIL: some subscribed courses could not be enumerated")
        return 1
    print("OK: WebVPN login, iCourse CAS login, course API and enumeration all succeeded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
