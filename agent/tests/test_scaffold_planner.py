from __future__ import annotations

import unittest

from agent.core.llm import ModelRequestError
from agent.scaffold.planner import _extract_json_object


class PlannerJsonExtractionTests(unittest.TestCase):
    def test_accepts_strict_object(self) -> None:
        payload = _extract_json_object('{"name":"repo_tree","arguments":{},"rationale":"x"}')
        self.assertEqual(payload["name"], "repo_tree")

    def test_accepts_markdown_fenced_object(self) -> None:
        payload = _extract_json_object(
            '```json\n{"name":"view_window","arguments":{"path":"access.py"},"rationale":"x"}\n```'
        )
        self.assertEqual(payload["name"], "view_window")

    def test_accepts_single_object_after_reasoning_wrapper(self) -> None:
        payload = _extract_json_object(
            '<think>Need to inspect the implementation first.</think>\n'
            '{"name":"view_window","arguments":{"path":"access.py"},"rationale":"inspect"}'
        )
        self.assertEqual(payload["arguments"]["path"], "access.py")

    def test_accepts_single_object_with_trailing_commentary(self) -> None:
        payload = _extract_json_object(
            'Action:\n{"name":"repo_tree","arguments":{},"rationale":"inspect"}\nDone.'
        )
        self.assertEqual(payload["name"], "repo_tree")

    def test_ignores_non_action_braces_before_complete_action(self) -> None:
        payload = _extract_json_object(
            'Thinking about {not valid} and {"path":"not-an-action"}.\n'
            '{"rationale":"inspect","name":"repo_tree","arguments":{}}'
        )
        self.assertEqual(payload["name"], "repo_tree")

    def test_rejects_nested_arguments_from_truncated_outer_action(self) -> None:
        with self.assertRaisesRegex(ModelRequestError, "no complete action object"):
            _extract_json_object(
                '{"rationale":"too long","name":"ctf_transform","arguments":'
                '{"path":"records.bin","steps":[{"operation":"zlib"}]}'
            )

    def test_rejects_multiple_objects(self) -> None:
        with self.assertRaisesRegex(ModelRequestError, "multiple JSON objects"):
            _extract_json_object(
                '{"name":"repo_tree","arguments":{},"rationale":"one"}\n'
                '{"name":"finish","arguments":{},"rationale":"two"}'
            )

    def test_rejects_no_object(self) -> None:
        with self.assertRaisesRegex(ModelRequestError, "no complete action object"):
            _extract_json_object("I cannot decide what to do next")


if __name__ == "__main__":
    unittest.main()
