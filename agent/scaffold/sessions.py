"""Safe single-session interactive runtime inspired by EnIGMA-style tools."""

from __future__ import annotations

import os
import re
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from agent.core.models import AgentAction, ToolResult

from .contracts import CapabilityLevel, ExecutionContext, ToolSpec


MAX_SESSION_OUTPUT_BYTES = 16_000
MAX_SESSION_INPUT_CHARS = 8_000
SENSITIVE_ENV_RE = re.compile(
    r"(?:API[_-]?KEY|TOKEN|CREDENTIAL|PASSWORD|PRIVATE[_-]?KEY|SECRET)", re.I
)
CONTROL_ENV_NAMES = frozenset(
    {
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTEST_ADDOPTS",
        "GIT_EXTERNAL_DIFF",
        "NODE_OPTIONS",
        "RUSTC_WRAPPER",
    }
)


def sanitized_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if key not in CONTROL_ENV_NAMES
        and not key.startswith("OPENAI_")
        and not key.startswith("LOCAL_AGENT_")
        and not SENSITIVE_ENV_RE.search(key)
    }


SessionArgvBuilder = Callable[[dict[str, Any], Path], tuple[str, ...]]


@dataclass(frozen=True)
class SessionProfile:
    name: str
    description: str
    argv_builder: SessionArgvBuilder
    modes: tuple[str, ...] = ("general",)


class InteractiveSessionError(RuntimeError):
    pass


class InteractiveSessionManager:
    """One non-blocking child REPL at a time; shell interpretation is never used."""

    def __init__(self):
        self._process: subprocess.Popen[bytes] | None = None
        self._profile: str | None = None
        self._argv: tuple[str, ...] = ()
        self._captured = bytearray()
        self._total_output = 0
        self._lock = threading.Lock()
        self._reader: threading.Thread | None = None
        self._started_at = 0.0

    @property
    def active(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def _drain(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        reader = process.stdout
        try:
            while True:
                read1 = getattr(reader, "read1", None)
                chunk = read1(1024) if read1 is not None else reader.read(1)
                if not chunk:
                    return
                with self._lock:
                    self._total_output += len(chunk)
                    self._captured.extend(chunk)
                    if len(self._captured) > MAX_SESSION_OUTPUT_BYTES:
                        del self._captured[:-MAX_SESSION_OUTPUT_BYTES]
        except (OSError, ValueError):
            return

    def _wait_for_output(self, previous_total: int, timeout: float = 0.3) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if self._total_output > previous_total:
                    return
            process = self._process
            if process is None or process.poll() is not None:
                return
            time.sleep(0.01)

    def start(self, profile: SessionProfile, arguments: dict[str, Any], workdir: Path) -> dict[str, Any]:
        if self.active:
            raise InteractiveSessionError("only one interactive session may run at a time")
        argv = profile.argv_builder(arguments, workdir)
        if not argv or any(not isinstance(item, str) or not item for item in argv):
            raise InteractiveSessionError("session profile produced invalid argv")
        options: dict[str, Any] = {}
        if os.name == "posix":
            options["start_new_session"] = True
        elif os.name == "nt":
            options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        try:
            process = subprocess.Popen(
                argv,
                cwd=workdir,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=sanitized_environment(),
                shell=False,
                **options,
            )
        except OSError as error:
            raise InteractiveSessionError(f"session failed to start: {error}") from error
        self._process = process
        self._profile = profile.name
        self._argv = tuple(argv)
        with self._lock:
            self._captured.clear()
            self._total_output = 0
        self._started_at = time.monotonic()
        self._reader = threading.Thread(target=self._drain, daemon=True)
        self._reader.start()
        self._wait_for_output(0)
        return self.snapshot()

    def send(self, text: str) -> dict[str, Any]:
        if not self.active or self._process is None or self._process.stdin is None:
            raise InteractiveSessionError("no active interactive session")
        if not isinstance(text, str) or not text:
            raise InteractiveSessionError("session input must be non-empty text")
        if len(text) > MAX_SESSION_INPUT_CHARS:
            raise InteractiveSessionError(
                f"session input exceeds {MAX_SESSION_INPUT_CHARS} characters"
            )
        with self._lock:
            previous_total = self._total_output
        try:
            self._process.stdin.write(text.encode("utf-8") + b"\n")
            self._process.stdin.flush()
        except OSError as error:
            raise InteractiveSessionError(f"cannot write to session: {error}") from error
        self._wait_for_output(previous_total)
        return self.snapshot()

    def snapshot(self) -> dict[str, Any]:
        process = self._process
        with self._lock:
            output = bytes(self._captured).decode("utf-8", errors="replace")
            total = self._total_output
            captured_size = len(self._captured)
        return {
            "active": self.active,
            "profile": self._profile,
            "argv": list(self._argv),
            "pid": process.pid if process is not None else None,
            "return_code": process.poll() if process is not None else None,
            "elapsed_seconds": (
                round(time.monotonic() - self._started_at, 3) if self._started_at else 0.0
            ),
            "output_tail": output,
            "output_truncated": total > captured_size,
            "total_output_bytes": total,
        }

    def stop(self) -> dict[str, Any]:
        process = self._process
        if process is None:
            return self.snapshot()
        if process.poll() is None:
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGTERM)
                else:
                    process.terminate()
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                    process.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        if self._reader is not None:
            self._reader.join(timeout=1)
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        return self.snapshot()


class InteractiveSessionProvider:
    name = "interactive-sessions"

    def __init__(self, profiles: tuple[SessionProfile, ...]):
        self.profiles = {profile.name: profile for profile in profiles}
        self.manager = InteractiveSessionManager()

    def catalog(self, context: ExecutionContext) -> tuple[ToolSpec, ...]:
        enabled = [
            profile for profile in self.profiles.values() if context.decision.mode in profile.modes
        ]
        if not enabled:
            return ()
        modes = tuple(sorted({mode for profile in enabled for mode in profile.modes}))
        return (
            ToolSpec(
                "session_start",
                "Start one configured non-blocking interactive tool session.",
                {"profile": "string", "options": "object={}"},
                modes,
                CapabilityLevel.INTERACTIVE,
                False,
                self.name,
            ),
            ToolSpec(
                "session_send",
                "Send one line to the active interactive session and read its bounded output tail.",
                {"input": "string"},
                modes,
                CapabilityLevel.INTERACTIVE,
                False,
                self.name,
            ),
            ToolSpec(
                "session_status",
                "Read bounded state/output from the active interactive session.",
                {},
                modes,
                CapabilityLevel.INTERACTIVE,
                False,
                self.name,
            ),
            ToolSpec(
                "session_stop",
                "Terminate the active interactive session and its process group.",
                {},
                modes,
                CapabilityLevel.INTERACTIVE,
                False,
                self.name,
            ),
        )

    def execute(self, action: AgentAction, context: ExecutionContext) -> ToolResult:
        try:
            if action.name == "session_start":
                profile_name = action.arguments.get("profile")
                options = action.arguments.get("options", {})
                if not isinstance(profile_name, str) or profile_name not in self.profiles:
                    raise InteractiveSessionError("unknown session profile")
                if not isinstance(options, dict):
                    raise InteractiveSessionError("session options must be an object")
                profile = self.profiles[profile_name]
                if context.decision.mode not in profile.modes:
                    raise InteractiveSessionError("session profile is forbidden in current mode")
                data = self.manager.start(profile, options, context.workdir)
            elif action.name == "session_send":
                if set(action.arguments) != {"input"}:
                    raise InteractiveSessionError("session_send requires only input")
                data = self.manager.send(action.arguments["input"])
            elif action.name == "session_status":
                if action.arguments:
                    raise InteractiveSessionError("session_status takes no arguments")
                data = self.manager.snapshot()
            elif action.name == "session_stop":
                if action.arguments:
                    raise InteractiveSessionError("session_stop takes no arguments")
                data = self.manager.stop()
            else:
                return ToolResult(False, f"unknown session action: {action.name}")
            return ToolResult(True, f"{action.name} completed", data)
        except (OSError, ValueError, RuntimeError) as error:
            return ToolResult(False, f"{action.name} failed: {error}")
