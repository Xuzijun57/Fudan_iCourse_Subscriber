"""Bounded HTTP range downloads for finite MP4 recordings.

Never feed a truncated HTTP response to a decoder. A dropped response resumes
at the last byte written; a server ignoring Range cannot corrupt the file.
"""
from __future__ import annotations

import os
import re
import shutil
import threading
import time
from collections.abc import Callable

import requests


class DownloadCancelled(RuntimeError):
    pass


def download_ranges(get_response: Callable, refresh_url: Callable, path: str,
                    cancel: threading.Event | None = None,
                    block_size: int = 32 * 1024 * 1024,
                    max_attempts: int = 4, timeout: float = 1800,
                    log: Callable[[str], None] = print) -> str:
    """Download with bounded requests and verify every Content-Range.

    get_response(start, end) returns a streamed requests.Response. URLs and
    cookies stay inside the caller. No response body or URL is ever logged.
    refresh_url is called after a transient failure to replace expired URLs.
    A non-range server is supported only for its initial, length-checked 200.
    """
    cancel = cancel or threading.Event()
    temp = path + '.part'
    deadline = time.monotonic() + timeout
    offset = 0
    total = None
    validator = None
    failures = 0
    last_report = 0
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)

    def check_cancel():
        if cancel.is_set():
            raise DownloadCancelled('Audio download cancelled')
        if time.monotonic() >= deadline:
            raise TimeoutError('Video download exceeded its time limit')

    try:
        with open(temp, 'wb') as out:
            while total is None or offset < total:
                check_cancel()
                start = offset
                end = start + block_size - 1
                if total is not None:
                    end = min(end, total - 1)
                try:
                    with get_response(start, end) as response:
                        status = response.status_code
                        if status not in (200, 206):
                            raise RuntimeError(f'Video HTTP status {status}')
                        if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
                            raise ValueError('Encoded video response cannot be resumed safely')
                        if status == 206:
                            match = re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)',
                                response.headers.get('Content-Range', ''))
                            if not match:
                                raise ValueError('Invalid video Content-Range')
                            first, last, size = map(int, match.groups())
                            if first != start or last > end or last < first or last >= size:
                                raise ValueError('Server returned the wrong video byte range')
                            expected = last - first + 1
                        else:
                            if start:
                                raise ValueError('Server ignored Range during resume')
                            try:
                                size = expected = int(response.headers['Content-Length'])
                            except (KeyError, ValueError):
                                raise ValueError('Video response has no valid size') from None
                        if size <= 0 or (total is not None and size != total):
                            raise ValueError('Video size changed during download')
                        identity = response.headers.get('ETag') or response.headers.get('Last-Modified')
                        if validator and identity and identity != validator:
                            raise ValueError('Video changed during download')
                        validator = validator or identity
                        if total is None:
                            total = size
                            # Reserve the whole MP4 plus room for its decoded PCM.
                            if shutil.disk_usage(os.path.dirname(path) or '.').free < total + 1024**3:
                                raise OSError('Insufficient disk space for complete video download')
                            log(f'[AudioDownload] Video size {total} bytes')
                        received = 0
                        for chunk in response.iter_content(chunk_size=256 * 1024):
                            check_cancel()
                            if not chunk:
                                continue
                            if received + len(chunk) > expected:
                                raise ValueError('Video response exceeded its declared range')
                            out.write(chunk)
                            received += len(chunk)
                            offset += len(chunk)
                        if received != expected:
                            raise RuntimeError('Video response ended before its declared range')
                    failures = 0
                    now = time.monotonic()
                    if now - last_report >= 30 or offset == total:
                        log(f'[AudioDownload] Verified {offset}/{total} bytes ({offset/total:.0%})')
                        last_report = now
                except (requests.RequestException, RuntimeError) as exc:
                    if isinstance(exc, DownloadCancelled):
                        raise
                    # A bounded proxy can truncate multiple requests. Keep
                    # useful progress; only exhaust retries when no bytes arrive.
                    failures = 1 if offset > start else failures + 1
                    if failures >= max_attempts:
                        raise RuntimeError(f'Video download failed at byte {offset} after {failures} attempts') from None
                    check_cancel()
                    log(f'[AudioDownload] Retrying at byte {offset} ({type(exc).__name__})')
                    refresh_url()
                    cancel.wait(min(failures, 3))
        check_cancel()
        os.replace(temp, path)
        return path
    finally:
        if os.path.exists(temp):
            os.remove(temp)
