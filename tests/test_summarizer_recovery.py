import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from openai import AuthenticationError
from src.ai.summarizer import Summarizer


class SummarizerRecoveryTests(unittest.TestCase):
    def create(self):
        providers = [dict(name='first', api_key='dummy', base_url='https://example.test', models=['a', 'b']),
                     dict(name='second', api_key='dummy', base_url='https://example.test', models=['c'])]
        with patch('src.ai.summarizer.config.resolve_model_providers', return_value=providers), patch('src.ai.summarizer.OpenAI'):
            summary = Summarizer()
        return summary

    def test_empty_response_switches_to_next_model(self):
        summary = self.create()
        summary._clients['first'].chat.completions.create.side_effect = [
            SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content='  '))]),
            SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content='Recovered notes'))])]
        self.assertEqual(summary.summarize('Course', 'Lecture transcript'), ('Recovered notes', 'first/b'))

    def test_unauthorized_provider_is_skipped_for_remaining_lectures(self):
        summary = self.create()
        response = Mock(status_code=401, request=Mock(), headers={})
        failure = AuthenticationError('Invalid credential', response=response, body=None)
        summary._call_llm = Mock(side_effect=[failure, 'First notes', 'Second notes'])
        self.assertEqual(summary.summarize('Course', 'Lecture one'), ('First notes', 'second/c'))
        self.assertEqual(summary.summarize('Course', 'Lecture two'), ('Second notes', 'second/c'))
        self.assertEqual([call.args[1] for call in summary._call_llm.call_args_list], ['a', 'c', 'c'])

    def test_all_empty_responses_remain_retryable_failures(self):
        summary = self.create()
        summary._call_llm = Mock(side_effect=ValueError('API returned empty summary content'))
        with self.assertRaisesRegex(RuntimeError, 'All LLM models failed'):
            summary.summarize('Course', 'Lecture transcript')
