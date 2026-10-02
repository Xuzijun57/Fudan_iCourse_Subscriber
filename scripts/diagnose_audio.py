"""Read-only reproduction of a truncated lecture; never prints credentials."""
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.api.icourse import ICourseClient
from src.api.webvpn import WebVPNSession


def safe(text):
    text = re.sub(r'https?://\S+', '[URL omitted]', text)
    return re.sub(r'(?im)^.*(?:cookie|authorization|ticket|password).*$','[credential line omitted]',text)


for attempt in range(10):
    try:
        vpn = WebVPNSession()
        vpn.login()
        vpn.authenticate_icourse()
        break
    except Exception as exc:
        print('Login retry', attempt+1, type(exc).__name__, flush=True)
        if attempt == 9:
            raise RuntimeError('Could not establish a school session') from None
        time.sleep(5)
client = ICourseClient(vpn)
sub_id = os.environ.get('DIAG_SUB_ID', '662493')
course_id = None
for cid in os.environ['COURSE_IDS'].split(','):
    detail = client.get_course_detail(cid.strip())
    if any(str(l['sub_id']) == sub_id for l in detail['lectures']):
        course_id = cid.strip()
        break
if course_id is None:
    raise RuntimeError('Requested lecture not found in subscriptions')
url = client.get_video_url(course_id, sub_id)
vpn_url, headers = client.get_stream_params(url)
print('Diagnostic lecture', course_id, sub_id, flush=True)
for start in (0, 536870912, 1073741824):
    with vpn.get_raw(vpn_url, headers={'Range': f'bytes={start}-{start+1023}',
                                      'Accept-Encoding': 'identity'},
                     stream=True, timeout=(15, 30)) as resp:
        print('Range probe', start, 'status', resp.status_code,
              'length', resp.headers.get('Content-Length'),
              'range', resp.headers.get('Content-Range'),
              'type', resp.headers.get('Content-Type'), flush=True)
        resp.raw.read(1024)
with tempfile.TemporaryDirectory() as tmp:
    video = os.path.join(tmp, 'complete.mp4')
    client.download_lecture_video(course_id, sub_id, video)
    path = os.path.join(tmp, 'audio.raw')
    cmd = ['ffmpeg', '-nostdin', '-nostats', '-y', '-i', video,
           '-vn', '-ar', '16000', '-ac', '1', '-f', 'f32le', path]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        _, stderr = proc.communicate(timeout=900)
    except subprocess.TimeoutExpired:
        proc.kill()
        _, stderr = proc.communicate()
        print('Diagnostic decode timed out', flush=True)
    print('ffmpeg return code', proc.returncode, flush=True)
    print('Decoded audio seconds', os.path.getsize(path)/64000 if os.path.exists(path) else 0, flush=True)
    text = safe(stderr.decode(errors='replace'))
    print('FFMPEG START', text[:8000], 'FFMPEG END', text[-16000:], flush=True)
    duration = re.search(r'Duration:\s*(\d+):(\d+):(\d+(?:\.\d+)?)', text)
    if not duration or proc.returncode:
        raise RuntimeError('Local decode failed')
    h, m, s = duration.groups()
    expected = int(h)*3600 + int(m)*60 + float(s)
    actual = os.path.getsize(path)/64000
    if actual < expected*0.99:
        raise RuntimeError('Decoded audio remains incomplete')
    print('VERIFIED FULL AUDIO', actual, expected, flush=True)
