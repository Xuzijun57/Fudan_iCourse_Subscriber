import contextlib
import os
import socket
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import requests

from src.api.media_download import DownloadCancelled, download_ranges


@contextlib.contextmanager
def server(data, mode='normal'):
    state = {'requests': [], 'closed': 0}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            requested = self.headers['Range'][6:].split('-')
            start, end = map(int, requested)
            end = min(end, len(data)-1)
            state['requests'].append((start, end))
            self.send_response(200 if mode == 'ignored' else 206)
            self.send_header('Content-Length', str(len(data) if mode == 'ignored' else end-start+1))
            first = start+1 if mode == 'wrong-range' else start
            self.send_header('Content-Range', f'bytes {first}-{end}/{len(data)}')
            self.send_header('ETag', 'same-recording')
            self.end_headers()
            if mode == 'drop' and end-start > 300000:
                self.wfile.write(data[start:start+300000])
                self.wfile.flush()
                state['closed'] += 1
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
            else:
                self.wfile.write(data if mode == 'ignored' else data[start:end+1])

    http = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{http.server_port}/video', state
    finally:
        http.shutdown()
        http.server_close()
        thread.join()


class MediaDownloadTests(unittest.TestCase):
    def run_download(self, data, mode='normal', **kwargs):
        with tempfile.TemporaryDirectory() as tmp, server(data, mode) as (url, state):
            path = os.path.join(tmp, 'recording.mp4')
            def get(start, end):
                return requests.get(url, headers={'Range': f'bytes={start}-{end}'},
                                    stream=True, timeout=5)
            download_ranges(get, lambda: None, path, block_size=512*1024,
                            log=lambda _: None, **kwargs)
            result = Path(path).read_bytes()
            self.assertFalse(Path(path+'.part').exists())
            return result, state

    def test_full_file_and_last_short_range(self):
        data = os.urandom(1200000)
        result, state = self.run_download(data)
        self.assertEqual(data, result)
        self.assertEqual(state['requests'][-1][1], len(data)-1)

    def test_repeated_disconnect_resumes_without_duplicates(self):
        data = os.urandom(1400000)
        result, state = self.run_download(data, 'drop')
        self.assertEqual(data, result)
        self.assertGreater(state['closed'], 1)
        self.assertEqual(state['requests'][1][0], 262144)

    def test_wrong_range_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'wrong video byte range'):
            self.run_download(os.urandom(600000), 'wrong-range')

    def test_nonrange_server_must_deliver_complete_file(self):
        data = os.urandom(600000)
        result, _ = self.run_download(data, 'ignored')
        self.assertEqual(data, result)

    def test_cancelled_download_removes_partial(self):
        cancel = threading.Event()
        cancel.set()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'cancelled.mp4')
            with self.assertRaises(DownloadCancelled):
                download_ranges(lambda *args: None, lambda: None, path, cancel=cancel)
            self.assertFalse(Path(path).exists())
            self.assertFalse(Path(path+'.part').exists())

    def test_network_failure_exhausts_bounded_retries(self):
        calls = []
        def failed(start, end):
            calls.append(start)
            raise requests.ConnectionError('simulated outage')
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'failed.mp4')
            with self.assertRaisesRegex(RuntimeError, 'after 2 attempts'):
                download_ranges(failed, lambda: None, path, max_attempts=2,
                                log=lambda _: None)
            self.assertEqual(len(calls), 2)
            self.assertFalse(Path(path).exists())
            self.assertFalse(Path(path+'.part').exists())

    def test_downloaded_media_decodes_to_full_duration(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, 'source.wav')
            subprocess.run(['ffmpeg', '-v', 'error', '-f', 'lavfi', '-i',
                'sine=frequency=440:duration=30', '-ar', '16000', '-ac', '1', source], check=True)
            data = Path(source).read_bytes()
            restored, _ = self.run_download(data, 'drop')
            complete = os.path.join(tmp, 'complete.wav')
            Path(complete).write_bytes(restored)
            pcm = subprocess.check_output(['ffmpeg', '-v', 'error', '-i', complete,
                '-ar', '16000', '-ac', '1', '-f', 'f32le', '-'])
            self.assertAlmostEqual(len(pcm)/64000, 30, places=2)


if __name__ == '__main__':
    unittest.main()
