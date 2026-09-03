#!/usr/bin/env python3
"""HTTP security and regression checks for the public insecure-api exercise."""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable


@dataclass
class CheckResult:
    name: str
    passed: bool
    duration_ms: int
    detail: str


class ApiClient:
    def __init__(self, base_url: str, timeout: float):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> tuple[int, Any]:
        url = f"{self.base_url}{path}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"

        body = None
        headers: dict[str, str] = {}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(
            url,
            data=body,
            headers=headers,
            method=method,
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                status = response.status
                raw = response.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            raw = exc.read()

        text = raw.decode("utf-8", errors="replace")
        try:
            return status, json.loads(text)
        except json.JSONDecodeError:
            return status, text


class RegressionSuite:
    def __init__(self, client: ApiClient):
        self.client = client
        self.results: list[CheckResult] = []

    def check(self, name: str, function: Callable[[], str]) -> None:
        started = time.monotonic()
        try:
            detail = function()
            passed = True
        except Exception as exc:  # Keep running to collect every failure.
            detail = f"{type(exc).__name__}: {exc}"
            passed = False
        elapsed_ms = round((time.monotonic() - started) * 1000)
        self.results.append(CheckResult(name, passed, elapsed_ms, detail))

    @staticmethod
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise AssertionError(message)

    def run(self) -> list[CheckResult]:
        self.check("healthz", self._healthz)
        self.check("login_valid", self._login_valid)
        self.check("login_wrong_password", self._login_wrong_password)
        self.check("sqli_comment_rejected", self._sqli_comment_rejected)
        self.check("sqli_or_rejected", self._sqli_or_rejected)
        self.check("search_regression", self._search_regression)
        self.check("list_filter_regression", self._list_filter_regression)
        self.check("crud_regression", self._crud_regression)
        self.check("comments_regression", self._comments_regression)
        self.check("tags_regression", self._tags_regression)
        self.check("users_do_not_expose_passwords", self._users_regression)
        return self.results

    def _healthz(self) -> str:
        status, body = self.client.request("GET", "/healthz")
        self.require(status == 200, f"expected 200, got {status}: {body!r}")
        self.require(body == {"status": "ok"}, f"unexpected body: {body!r}")
        return "service is healthy"

    def _login_valid(self) -> str:
        status, body = self.client.request(
            "POST",
            "/login",
            payload={"username": "admin", "password": "secret123"},
        )
        self.require(status == 200, f"expected 200, got {status}: {body!r}")
        self.require(isinstance(body, dict) and body.get("token"), "token is missing")
        return "normal login still works"

    def _login_wrong_password(self) -> str:
        status, body = self.client.request(
            "POST",
            "/login",
            payload={"username": "admin", "password": "wrong"},
        )
        self.require(status == 401, f"expected 401, got {status}: {body!r}")
        return "wrong password is rejected"

    def _assert_login_rejected(self, username: str) -> str:
        status, body = self.client.request(
            "POST",
            "/login",
            payload={"username": username, "password": "x"},
        )
        self.require(status != 200, f"payload authenticated: {body!r}")
        return f"payload rejected with HTTP {status}"

    def _sqli_comment_rejected(self) -> str:
        return self._assert_login_rejected("admin'--")

    def _sqli_or_rejected(self) -> str:
        return self._assert_login_rejected("admin' OR '1'='1")

    def _search_regression(self) -> str:
        status, body = self.client.request("GET", "/search", query={"q": "timeout"})
        self.require(status == 200, f"expected 200, got {status}: {body!r}")
        self.require(isinstance(body, list), f"expected list, got {body!r}")
        names = [item.get("name") for item in body if isinstance(item, dict)]
        self.require("Fix login timeout" in names, f"expected item not found: {names!r}")
        return "search result preserved"

    def _list_filter_regression(self) -> str:
        status, body = self.client.request(
            "GET", "/items", query={"status": "open"}
        )
        self.require(status == 200, f"expected 200, got {status}: {body!r}")
        self.require(isinstance(body, list) and body, "expected non-empty item list")
        self.require(
            all(isinstance(item, dict) and item.get("status") == "open" for item in body),
            f"filter returned non-open items: {body!r}",
        )
        return "item filtering preserved"

    def _crud_regression(self) -> str:
        unique_name = f"C04 regression {time.time_ns()}"
        item_id: int | None = None
        deleted = False
        try:
            status, body = self.client.request(
                "POST",
                "/items",
                payload={
                    "name": unique_name,
                    "description": "Created by C-04 regression verification",
                    "status": "open",
                    "priority": "high",
                    "owner_id": 1,
                },
            )
            self.require(status == 200, f"create failed: HTTP {status}: {body!r}")
            self.require(isinstance(body, dict) and isinstance(body.get("id"), int), "created item has no integer id")
            item_id = body["id"]

            status, body = self.client.request(
                "PUT", f"/items/{item_id}", payload={"status": "closed"}
            )
            self.require(status == 200, f"update failed: HTTP {status}: {body!r}")
            self.require(isinstance(body, dict) and body.get("status") == "closed", "updated status was not returned")

            status, body = self.client.request("DELETE", f"/items/{item_id}")
            self.require(status == 200, f"delete failed: HTTP {status}: {body!r}")
            deleted = True

            status, body = self.client.request("GET", f"/items/{item_id}")
            self.require(status == 404, f"deleted item is still available: HTTP {status}: {body!r}")
            return "create, update, delete and 404 verification passed"
        finally:
            if item_id is not None and not deleted:
                try:
                    self.client.request("DELETE", f"/items/{item_id}")
                except Exception:
                    pass

    def _comments_regression(self) -> str:
        status, body = self.client.request("GET", "/items/1/comments")
        self.require(status == 200, f"list comments failed: HTTP {status}: {body!r}")
        self.require(isinstance(body, list), f"expected comment list, got {body!r}")

        marker = f"C04 comment {time.time_ns()}"
        status, body = self.client.request(
            "POST",
            "/items/1/comments",
            payload={"author_id": 1, "body": marker},
        )
        self.require(status == 200, f"create comment failed: HTTP {status}: {body!r}")
        self.require(isinstance(body, dict) and body.get("body") == marker, "created comment body changed")
        return "comment listing and creation preserved"

    def _tags_regression(self) -> str:
        status, body = self.client.request("GET", "/tags")
        self.require(status == 200, f"list tags failed: HTTP {status}: {body!r}")
        self.require(isinstance(body, list), f"expected tag list, got {body!r}")
        names = [tag.get("name") for tag in body if isinstance(tag, dict)]
        self.require("bug" in names, f"default tag is missing: {names!r}")
        return "tag listing preserved"

    def _users_regression(self) -> str:
        status, body = self.client.request("GET", "/users")
        self.require(status == 200, f"list users failed: HTTP {status}: {body!r}")
        self.require(isinstance(body, list) and len(body) >= 3, f"unexpected users: {body!r}")
        self.require(
            all(isinstance(user, dict) and "password" not in user for user in body),
            "user response exposes a password field",
        )
        return "user listing preserved without password fields"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    suite = RegressionSuite(ApiClient(args.base_url, args.timeout))
    results = suite.run()
    passed = sum(result.passed for result in results)
    report = {
        "passed": passed,
        "failed": len(results) - passed,
        "total": len(results),
        "checks": [asdict(result) for result in results],
    }

    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{rendered}\n", encoding="utf-8")
    print(rendered)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
