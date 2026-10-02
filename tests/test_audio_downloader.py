import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from src.runtime.scheduler import AudioDownloader


class AudioDownloaderTests(unittest.TestCase):
    def test_download_failure_is_not_classified_as_no_video(self):
        class Client:
            def download_lecture_video(self, *args, **kwargs):
                raise RuntimeError('Network failed at byte 300000')
        with tempfile.TemporaryDirectory() as tmp:
            downloader = AudioDownloader(tmp, max_concurrent=1)
            downloader.schedule(Client(), '1', '2')
            with self.assertRaisesRegex(RuntimeError, 'Network failed'):
                downloader.get('2', timeout=5)
            downloader.release('2')
            self.assertEqual(downloader._active, {})
            self.assertTrue(downloader._sem.acquire(timeout=1))
            downloader._sem.release()

    def test_pending_download_can_be_cancelled(self):
        entered = threading.Event()
        ended = threading.Event()
        class Client:
            def download_lecture_video(self, *args, cancel=None):
                entered.set()
                cancel.wait(5)
                ended.set()
                return None
        with tempfile.TemporaryDirectory() as tmp:
            downloader = AudioDownloader(tmp, max_concurrent=1)
            downloader.schedule(Client(), '1', '2')
            self.assertTrue(entered.wait(2))
            downloader.release('2')
            self.assertTrue(ended.wait(2))
            self.assertIsNone(downloader.get('2', timeout=1))
            self.assertTrue(downloader._sem.acquire(timeout=1))
            downloader._sem.release()

    def test_complete_local_video_decodes_and_releases_resources(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, 'source.wav')
            subprocess.run(['ffmpeg', '-v', 'error', '-f', 'lavfi', '-i',
                'sine=frequency=440:duration=3', '-ar', '16000', '-ac', '1', source], check=True)
            class Client:
                def download_lecture_video(self, course, sub, path, cancel=None):
                    shutil.copyfile(source, path)
                    return path
            downloader = AudioDownloader(tmp, max_concurrent=1)
            downloader.schedule(Client(), '1', '2')
            handle = downloader.get('2', timeout=5)
            self.assertEqual(handle.process.wait(timeout=10), 0)
            self.assertAlmostEqual(Path(handle.path).stat().st_size/64000, 3, places=2)
            downloader.release('2')
            self.assertFalse(Path(handle.path).exists())
            self.assertTrue(downloader._sem.acquire(timeout=2))
            downloader._sem.release()
            self.assertFalse(Path(handle.video_path).exists())


if __name__ == '__main__':
    unittest.main()
