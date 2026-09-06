"""Bounded, non-blocking single interactive session scaffold.

Inspired by EnIGMA's simple interactive interfaces: one parallel session at a
 time, explicit start/send/read/stop lifecycle, no shell interpretation and a
bounded transcript.  No dangerous executable is enabled by default; feature
owners must inject an argv policy (e.g. for gdb or a task-local connector).
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from agent.core.workspace import resolve_workspace_path

from .contracts import RuntimeLimits
from .process import sanitized_child_environment


SessionArgvPolicy = Callable[[tuple[str, ...]], str]


class SessionError(RuntimeError):
    """Interactive-session lifecycle or policy error."""


def deny_all_sessions(argv: tuple[str, ...]) -> str:
    raise SessionError(f"interactive executable is not enabled: {argv[0] if argv else '<empty>'}")


@dataclass(frozen=True)
class SessionSnapshot:
    session_id: str
    profile: str
    argv: tuple[str, ...]
    running: bool
    exit_code: int | None
    output: str
    output_truncated: bool
    started_monotonic: float

    def as_payload(self) -> dict[str, object]:
        return {
            "session_id": self.session_id,
            "profile": self.profile,
            "argv": list(self.argv),
            "running": self.running,
            "exit_code": self.exit_code,
            "output": self.output,
            "output_truncated": self.output_truncated,
        }


class InteractiveSessionManager:
    """At most one subprocess-backed interactive session per agent run."""

    def __init__(
        self,
        workdir: Path | str,
        *,
        argv_policy: SessionArgvPolicy = deny_all_sessions,
        limits: RuntimeLimits | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ):
        self.workdir = Path(workdir).resolve()
        self.argv_policy = argv_policy
        self.limits = limits or RuntimeLimits()
        self.sleeper = sleeper
        self._process: subprocess.Popen[bytes] | None = None
        self._snapshot_args: tuple[str, ...] = ()
        self._profile = ""
        self._started = 0.0
        self._session_id = ""
        self._buffer = bytearray()
        self._total_output = 0
        self._lock = threading.Lock()
        self._reader: threading.Thread | None = None
        self._counter = 0

    @property
    def active(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def _drain(self, process: subprocess.Popen[bytes]) -> None:
        assert process.stdout is not None
        try:
            fd = process.stdout.fileno()
            while True:
                chunk = os.read(fd, 1024)
                if not chunk:
                    break
                with self._lock:
                    self._total_output += len(chunk)
                    self._buffer.extend(chunk)
                    overflow = len(self._buffer) - self.limits.max_session_output_bytes
                    if overflow > 0:
                        del self._buffer[:overflow]
        except (OSError, ValueError):
            return

    def _wait_for_output_change(self, before_total: int, timeout: float) -> None:
        deadline = time.monotonic() + max(0.0, min(timeout, 0.5))
        while time.monotonic() < deadline:
            with self._lock:
                changed = self._total_output > before_total
            if changed:
                # Give a line-oriented child a tiny chance to flush the rest of
                # the observation without turning the interface into a blocking REPL.
                self.sleeper(0.02)
                return
            process = self._process
            if process is not None and process.poll() is not None:
                return
            self.sleeper(0.01)

    def start(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        cwd: str = ".",
    ) -> SessionSnapshot:
        if self.active:
            raise SessionError("an interactive session is already running")
        command = tuple(argv)
        if not command or any(not isinstance(item, str) or not item for item in command):
            raise SessionError("argv must contain non-empty strings")
        profile = self.argv_policy(command)
        command_cwd = resolve_workspace_path(self.workdir, cwd)
        if not command_cwd.is_dir():
            raise SessionError(&"session cwd is not a directory: {cwd}")

        popen_options: dict[str, object] = {}
        if os.name == "posix":
            popen_options["start_new_session"] = True
        elif os.name == "nt":
            popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        try:
            process = subprocess.Popen(
                command,
                cwd=command_cwd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=sanitized_child_environment(),
                shell=False,
                bufsize=0,
                **popen_options,
            )
        except OSError as error:
            raise SessionError(f"interactive session failed to start: {error}") from error

        self._counter += 1
        self._process = process
        self._snapshot_args = command
        self._profile = profile
        self._started = time.monotonic()
        self._session_id = f"session-{self._counter}"
        self._buffer = bytearray()
        self._total_output = 0
        self._reader = threading.Thread(target=self._drain, args=(process,), daemon=True)
        self._reader.start()
        self._wait_for_output_change(0, 0.5)
        return self.snapshot()

    def send(self, data: str, *, newline: bool = True, settle_seconds: float = 0.05) -> SessionSnapshot:
        process = self._process
        if process is None or process.poll() is not None:
            raise SessionError("no running interactive session")
        if not isinstance(data, str) or len(data) > self.limits.max_session_input_chars:
            raise SessionError(
                f"session input must be text up to {self.limits.max_session_input_chars} characters"
            )
        elapsed = time.monotonic() - self._started
        if elapsed > self.limits.max_session_seconds:
            self.stop()
            raise SessionError("interactive session time budget exhausted")
        payload = (data + ("\n" if newline else "")).encode("utf-8")
        assert process.stdin is not None
        with self._lock:
            before_total = self._total_output
        try:
            process.stdin.write(payload)
            process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as error:
            raise SessionError(f"interactive session input failed: {error}") from error
        self._wait_for_output_change(before_total, settle_seconds)
        return self.snapshot()

    def snapshot(self) -> SessionSnapshot:
        process = self._process
        if process is None:
            raise SessionError("interactive session has not been started")
        with self._lock:
            output = bytes(self._buffer).decode("utf-8", errors="replace")
            total = self._total_output
        exit_code = process.poll()
        return SessionSnapshot(
            session_id=self._session_id,
            profile=self._profile,
            argv=self._snapshot_args,
            running=exit_code is None,
            exit_code=exit_code,
            output=output,
            output_truncated=total > len(self._buffer),
            started_monotonic=self._started,
        )

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
        except (OSError, ProcessLookupError):
            return
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except (OSError, ProcessLookupError):
                pass

    def stop(self) -> SessionSnapshot:
        process = self._process
        if process is None:
            raise SessionError("interactive session has not been started")
        self._terminate(process)
        if self._reader is not None:
            self._reader.join(timeout=1)
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
        if process.stdout is not None:
            try:
                process.stdout.close()
            except OSError:
                pass
        return self.snapshot()

    def close(self) -> None:
        if self._process is not None and self._process.poll() is None:
            try:
                self.stop()
            except SessionError:
                pass

    def __enter__(self) -> "InteractiveSessionManager":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()
