from __future__ import annotations

import unittest

from agent.runtime.process import sanitized_child_environment


class RuntimeProcessPolicyTests(unittest.TestCase):
    def test_model_secrets_and_control_variables_are_removed(self):
        env = {
            "PATH": "/bin",
            "OPENAI_API_KEY": "secret",
            "OPENAI_BASE_URL": "http://model",
            "LOCAL_AGENT_MODEL": "model",
            "LOCAL_AGENT_WORKDIR": "/app",
            "OTHER_TOKEN": "token",
            "GIT_EXTERNAL_DIFF": "evil",
            "SAFE_VALUE": "ok",
        }
        result = sanitized_child_environment(env)
        self.assertEqual(result["PATH"], "/bin")
        self.assertEqual(result["SAFE_VALUE"], "ok")
        self.assertNotIn("OPENAI_API_KEY", result)
        self.assertNotIn("OPENAI_BASE_URL", result)
        self.assertNotIn("LOCAL_AGENT_MODEL", result)
        self.assertNotIn("LOCAL_AGENT_WORKDIR", result)
        self.assertNotIn("OTHER_TOKEN", result)
        self.assertNotIn("GIT_EXTERNAL_DIFF", result)

    def test_sensitive_extra_override_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "sensitive"):
            sanitized_child_environment({"PATH": "/bin"}, extra={"API_KEY": "x"})


if __name__ == "__main__":
    unittest.main()
