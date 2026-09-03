import ast
import asyncio
import importlib.util
import sys
import types
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUTH_PATH = PROJECT_ROOT / "routers" / "auth.py"
EXPECTED_QUERY = "SELECT id FROM users WHERE username = $1 AND password = $2"


class StubAPIRouter:
    def __init__(self, **_kwargs):
        pass

    @staticmethod
    def _decorator(*_args, **_kwargs):
        return lambda function: function

    get = _decorator
    post = _decorator


class StubHTTPException(Exception):
    def __init__(self, status_code, detail):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class StubLoginResponse:
    def __init__(self, token):
        self.token = token


class FakeConnection:
    def __init__(self):
        self.calls = []

    async def fetchrow(self, query, *parameters):
        self.calls.append((query, parameters))
        if query != EXPECTED_QUERY:
            raise AssertionError(f"Unexpected SQL: {query!r}")
        if parameters == ("admin", "secret123"):
            return {"id": 1}
        return None


class FakeAcquireContext:
    def __init__(self, connection):
        self.connection = connection

    async def __aenter__(self):
        return self.connection

    async def __aexit__(self, _exc_type, _exc, _traceback):
        return False


class FakePool:
    def __init__(self, connection):
        self.connection = connection

    def acquire(self):
        return FakeAcquireContext(self.connection)


def load_auth_module():
    fastapi = types.ModuleType("fastapi")
    fastapi.APIRouter = StubAPIRouter
    fastapi.HTTPException = StubHTTPException

    db = types.ModuleType("db")

    async def unconfigured_get_pool():
        raise AssertionError("The test must configure get_pool")

    db.get_pool = unconfigured_get_pool

    models = types.ModuleType("models")
    models.LoginRequest = object
    models.LoginResponse = StubLoginResponse

    previous_modules = {
        name: sys.modules.get(name) for name in ("fastapi", "db", "models")
    }
    sys.modules.update({"fastapi": fastapi, "db": db, "models": models})
    try:
        spec = importlib.util.spec_from_file_location("c03_auth", AUTH_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name, previous in previous_modules.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


class LoginSecurityFixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.auth = load_auth_module()

    def run_login(self, username, password):
        connection = FakeConnection()
        pool = FakePool(connection)

        async def get_pool():
            return pool

        self.auth.get_pool = get_pool
        request = types.SimpleNamespace(username=username, password=password)

        try:
            result = asyncio.run(self.auth.login(request))
            return result, None, connection.calls
        except StubHTTPException as exc:
            return None, exc, connection.calls

    def test_fetchrow_uses_constant_query_and_separate_parameters(self):
        tree = ast.parse(AUTH_PATH.read_text(encoding="utf-8"))
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "fetchrow"
        ]
        self.assertEqual(len(calls), 1)
        call = calls[0]
        self.assertEqual(len(call.args), 3)
        self.assertIsInstance(call.args[0], ast.Constant)
        self.assertEqual(call.args[0].value, EXPECTED_QUERY)
        self.assertEqual(ast.unparse(call.args[1]), "req.username")
        self.assertEqual(ast.unparse(call.args[2]), "req.password")

    def test_valid_credentials_preserve_normal_login(self):
        result, error, calls = self.run_login("admin", "secret123")
        self.assertIsNone(error)
        self.assertEqual(result.token, "token-1")
        self.assertEqual(calls, [(EXPECTED_QUERY, ("admin", "secret123"))])

    def test_wrong_password_is_rejected(self):
        result, error, calls = self.run_login("admin", "wrong")
        self.assertIsNone(result)
        self.assertEqual(error.status_code, 401)
        self.assertEqual(calls[0][1], ("admin", "wrong"))

    def test_comment_based_sqli_is_data_not_sql(self):
        result, error, calls = self.run_login("admin'--", "x")
        self.assertIsNone(result)
        self.assertEqual(error.status_code, 401)
        self.assertEqual(calls[0][0], EXPECTED_QUERY)
        self.assertEqual(calls[0][1], ("admin'--", "x"))

    def test_or_based_sqli_is_data_not_sql(self):
        payload = "admin' OR '1'='1"
        result, error, calls = self.run_login(payload, "x")
        self.assertIsNone(result)
        self.assertEqual(error.status_code, 401)
        self.assertEqual(calls[0][0], EXPECTED_QUERY)
        self.assertEqual(calls[0][1], (payload, "x"))


if __name__ == "__main__":
    unittest.main()
