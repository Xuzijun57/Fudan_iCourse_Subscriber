import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from src.data.database import Database
from src.pipeline.lecture_runner import LectureRunner
from src.ai.transcriber import NoAudioStreamError
from scripts.merge_db import merge


class MissingContentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(str(Path(self.tmp.name) / 'local.db'))
        self.db.upsert_course('course', 'Test course', 'Teacher')
        self.db.insert_lecture('lesson', 'course', 'Test lesson', '2026-09-24')

    def tearDown(self):
        self.db.conn.close()
        self.tmp.cleanup()

    def runner(self):
        runner = LectureRunner(Mock(), self.db, Mock(), Mock(), Mock(), Mock())
        runner._ppt = Mock()
        return runner

    def test_legacy_processed_without_summary_is_requeued_and_uses_cached_transcript(self):
        self.db.update_transcript('lesson', 'Already transcribed course material')
        self.db.mark_processed('lesson')
        self.assertEqual(self.db.get_processed_sub_ids('course'), set())
        self.assertEqual([r['sub_id'] for r in self.db.get_unprocessed_lectures('course')], ['lesson'])
        runner = self.runner()
        runner._summarizer.summarize.return_value = ('Recovered summary', 'Test model')
        self.assertEqual(runner.run('course', 'Course', {'sub_id': 'lesson'}), 'Recovered summary')
        runner._transcriber.transcribe_tail.assert_not_called()
        self.assertIn('Already transcribed course material', runner._summarizer.summarize.call_args.args[1])
        self.assertEqual(self.db.get_processed_sub_ids('course'), {'lesson'})

    def test_empty_summary_is_recorded_as_failure_and_not_completed(self):
        self.db.update_transcript('lesson', 'Transcribed material')
        self.db.mark_processed('lesson')
        runner = self.runner()
        runner._summarizer.summarize.return_value = ('  ', 'Test model')
        with self.assertRaisesRegex(RuntimeError, 'empty content'):
            runner.run('course', 'Course', {'sub_id': 'lesson'})
        row = self.db.get_lecture('lesson')
        self.assertIsNone(row['processed_at'])
        self.assertEqual(row['error_stage'], 'summarize')
        self.assertFalse(row['summary'])

    def test_empty_transcription_retains_error_and_can_retry(self):
        self.db.mark_processed('lesson')
        runner = self.runner()
        runner._get_transcript = Mock(return_value=('', []))
        self.assertIsNone(runner.run('course', 'Course', {'sub_id': 'lesson'}))
        row = self.db.get_lecture('lesson')
        self.assertIsNone(row['processed_at'])
        self.assertEqual(row['error_stage'], 'transcribe')
        self.assertEqual(row['error_count'], 1)
        runner._summarizer.summarize.assert_not_called()
        runner._scheduler.audio_downloader.release.assert_called_with('lesson')

    def test_missing_audio_is_not_marked_completed(self):
        runner = self.runner()
        runner._transcriber.transcribe_tail.side_effect = NoAudioStreamError('Video has no audio')
        self.assertEqual(runner._get_transcript(None, 'course', 'lesson'), (None, None))
        self.assertIsNone(self.db.get_lecture('lesson')['processed_at'])
        self.assertEqual(self.db.get_lecture('lesson')['error_stage'], 'transcribe')

    def test_merge_does_not_resurrect_skipped_timestamp_or_erase_retry_error(self):
        remote = Database(str(Path(self.tmp.name) / 'remote.db'))
        remote.upsert_course('course', 'Test course', 'Teacher')
        remote.insert_lecture('lesson', 'course', 'Test lesson', '')
        remote.mark_processed('lesson')
        self.db.update_error('lesson', 'transcribe', 'Empty transcription')
        remote.conn.close()
        merge(self.db.db_path, remote.db_path)
        remote = Database(remote.db_path)
        row = remote.get_lecture('lesson')
        self.assertIsNone(row['processed_at'])
        self.assertEqual(row['error_stage'], 'transcribe')
        self.assertEqual(row['error_msg'], 'Empty transcription')
        remote.conn.close()

    def test_merge_preserves_valid_remote_content_when_local_retry_is_empty(self):
        remote = Database(str(Path(self.tmp.name) / 'remote.db'))
        remote.upsert_course('course', 'Test course', 'Teacher')
        remote.insert_lecture('lesson', 'course', 'Test lesson', '')
        remote.update_transcript('lesson', 'Real transcript')
        remote.conn.execute("UPDATE lectures SET summary='Real summary' WHERE sub_id='lesson'")
        remote.conn.commit()
        remote.mark_processed('lesson')
        self.db.update_transcript('lesson', '')
        self.db.update_error('lesson', 'transcribe', 'Empty transcription')
        remote.conn.close()
        merge(self.db.db_path, remote.db_path)
        remote = Database(remote.db_path)
        row = remote.get_lecture('lesson')
        self.assertEqual(row['transcript'], 'Real transcript')
        self.assertEqual(row['summary'], 'Real summary')
        self.assertIsNotNone(row['processed_at'])
        self.assertIsNone(row['error_stage'])
        remote.conn.close()
