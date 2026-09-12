"""Safe, structured adapters around the deterministic C-06/C-07 tools."""

from __future__ import annotations

import hashlib
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

from agent.strategies import StrategyDecision
from agent.tools.audit_signals import scan_audit_signals
from agent.tools.binary_records import carve_records
from agent.tools.event_table import event_table
from agent.tools.ctf import (
    MAX_TRANSFORM_BYTES,
    describe_ctf_bytes,
    transform_ctf_bytes,
    transform_ctf_data,
)
from agent.tools.forensics import (
    analyze_incident,
    ensure_output_outside_evidence,
    format_report,
    inventory_artifacts,
    inventory_digest,
    resolve_incident_directory,
)
from agent.tools.dns_exfil import correlate_dns_exfil
from agent.tools.security_scan import finding_observation, render_report, scan_project
from agent.tools.sql_parameterize import parameterize_project
from agent.validators import (
    canonical_path,
    dependency_path,
    path_is_within,
    protected_path,
)

from .contracts import ContractError, map_instruction_path
from .models import AgentAction, ToolDefinition, ToolResult
from .workspace import (
    _read_regular_bytes,
    apply_workspace_patch,
    list_workspace_files,
    read_workspace_bytes,
    read_workspace_text,
    resolve_workspace_path,
    run_workspace_command,
    search_workspace_text,
)


MAX_EXACT_TEXT_CHARS = 64_000
RESERVED_ACTIONS = frozenset({"finish", "abort"})
READ_ACTIONS = frozenset({"list_files", "read_file", "read_bytes", "search_text"})
WRITE_ACTIONS = frozenset({"apply_patch", "run_command"})
MODE_ACTIONS = {
    "audit": READ_ACTIONS | {"security_scan", "audit_signals"},
    "fix": READ_ACTIONS | WRITE_ACTIONS | {"security_scan", "sql_parameterize"},
    "forensics": READ_ACTIONS | {
        "read_events", "forensics_analyze", "dns_exfil_correlate", "ctf_transform"
    },
    "ctf": READ_ACTIONS | {"binary_records", "ctf_transform", "ctf_batch_transform", "write_exact_text"},
    "general": READ_ACTIONS | WRITE_ACTIONS | {"write_exact_text"},
}
TOOL_ORDER = (
    "list_files",
    "read_file",
    "read_bytes",
    "search_text",
    "security_scan",
    "audit_signals",
    "sql_parameterize",
    "forensics_analyze",
    "read_events",
    "dns_exfil_correlate",
    "binary_records",
    "ctf_transform",
    "ctf_batch_transform",
    "write_exact_text",
    "apply_patch",
    "run_command",
)
TOOL_DEFINITIONS = {
    "list_files": ToolDefinition(
        "list_files",
        "List bounded regular files under a workspace path.",
        {"path": "string=.", "max_depth": "integer=6", "max_entries": "integer=200"},
    ),
    "read_file": ToolDefinition(
        "read_file",
        "Read a bounded UTF-8 line range from one regular file.",
        {"path": "string", "start_line": "integer=1", "max_lines": "integer=200"},
    ),
    "read_bytes": ToolDefinition(
        "read_bytes",
        "Read a bounded byte range as hex and printable ASCII.",
        {"path": "string", "offset": "integer=0", "length": "integer=256"},
    ),
    "search_text": ToolDefinition(
        "search_text",
        "Literal bounded text search over workspace files.",
        {
            "query": "string",
            "path": "string=.",
            "glob": "string=*",
            "case_sensitive": "boolean=false",
        },
    ),
    "security_scan": ToolDefinition(
        "security_scan",
        "Run the deterministic Python SQL-injection scanner.",
        {"target": "string=.", "write_report": "boolean=false", "output": "string"},
        True,
    ),
    "audit_signals": ToolDefinition(
        "audit_signals",
        "Locate conservative non-SQL security leads with concrete source lines and CWE hints. Leads require source confirmation and are not automatic findings.",
        {"target": "string=."},
    ),
    "sql_parameterize": ToolDefinition(
        "sql_parameterize",
        "Apply supported asyncpg SQL value parameterization.",
        {"target": "string=."},
        True,
    ),
    "forensics_analyze": ToolDefinition(
        "forensics_analyze",
        "Correlate the supported incident evidence profile.",
        {"target": "string=.", "output": "string=incident_report.txt"},
        True,
    ),
    "read_events": ToolDefinition(
        "read_events",
        "Read a bounded JSONL event table and compute UTC from explicit clock offsets. Positive offset means clock fast: UTC=recorded-offset. Does not select malicious events or infer correlations.",
        {"path": "string", "time_field": "string; existing timestamp key in each JSONL object",
         "clock_offset_seconds": "integer=0; positive fast, negative slow; max absolute 86400",
         "offset_start": "optional ISO8601 with timezone; recorded-clock start, inclusive; requires offset_end",
         "offset_end": "optional ISO8601 with timezone; recorded-clock end, inclusive; requires offset_start",
         "start_line": "integer=1", "max_rows": "integer=50; maximum 100"},
    ),
    "dns_exfil_correlate": ToolDefinition(
        "dns_exfil_correlate",
        "For an explicit DNS domain, deduplicate sequenced resolver queries, order and Base32-decode once, map the client through inventory CSV, and correlate the nearest prior process JSONL event.",
        {
            "resolver_path": "string; resolver text log with timestamp, client= and q= fields",
            "inventory_path": "string; CSV containing ip and host columns",
            "process_path": "string; JSONL containing ts, src and process fields",
            "domain": "string; evidence-selected DNS suffix",
            "client": "optional string; required only when multiple clients match",
        },
    ),
    "binary_records": ToolDefinition(
        "binary_records",
        "Locate binary records using the documented magic and integer header. Read format documentation first. Returns exact payload offsets/lengths and all header values; select the configured kind yourself.",
        {"path": "string", "magic_hex": "hex string; 1..64 bytes",
         "field_sizes": "preferred integer[] AFTER magic; each width 1,2,4,8 bytes; one entry per field. A kind byte plus two-byte length is [1,2], NOT [1,1,2]",
         "byte_order": "big (default) or little; used with field_sizes",
         "header_format": "alternative to field_sizes: explicit struct format; >BH has TWO fields, >BBH has THREE",
         "length_field": "integer; zero-based header field containing payload byte count",
         "max_records": "integer=32; max 64"},
    ),
    "ctf_transform": ToolDefinition(
        "ctf_transform",
        "Transform text, a complete bounded file, or an exact file byte range without copying encoded bytes through the model.",
        {
            "value": "string; text input, mutually exclusive with path/offset/length",
            "path": "string; source file; omit offset/length to transform the complete file up to 4096 bytes",
            "offset": "integer>=0; zero-based first byte",
            "length": "integer=1..4096; exact byte count, short reads fail",
            "steps": 'object[] in recovery order; each {"operation":"base32|base64|'
            'base64url|hex|url|rot13|reverse|reverse_bytes|xor|gzip|zlib|strip|split|json_get"}; '
            'split requires separator:string and index:integer; json_get requires path as dotted string or string/integer array; '
            'xor requires exactly key_text:string OR key_hex:string (never key); '
            'reverse is UTF-8 characters, reverse_bytes is raw bytes; '
            'textual hex requires an initial {"operation":"hex"}',
        },
    ),
    "ctf_batch_transform": ToolDefinition(
        "ctf_batch_transform",
        "Read several bounded files in the supplied evidence-derived order, apply the same steps independently to each, then concatenate decoded bytes. Use for manifest-indexed shards; never concatenate encoded strings first.",
        {
            "paths": "string[] in final evidence-derived order; 1..32 files, each <=4096 bytes",
            "steps": "object[] applied independently to every file; same operations as ctf_transform",
            "final_steps": "optional object[] applied once after decoded byte concatenation",
        },
    ),
    "write_exact_text": ToolDefinition(
        "write_exact_text",
        "Write an exact bounded text artifact requested by the instruction.",
        {"path": "string", "content": "string"},
        True,
    ),
    "apply_patch": ToolDefinition(
        "apply_patch",
        "Apply a bounded unified diff to existing non-protected UTF-8 files.",
        {"patch": "string"},
        True,
    ),
    "run_command": ToolDefinition(
        "run_command",
        "Run an allowlisted test/check command without shell interpretation.",
        {"argv": "string[]", "cwd": "string=.", "timeout_seconds": "integer=60"},
        True,
    ),
}


class ToolPolicyError(RuntimeError):
    """Raised when a structured action exceeds the current task's authority."""


def _expect_bool(arguments: dict[str, Any], key: str, default: bool) -> bool:
    value = arguments.get(key, default)
    if not isinstance(value, bool):
        raise ToolPolicyError(f"{key} must be a boolean")
    return value


class SecurityToolRegistry:
    """Dispatch a deliberately small allowlist with workdir containment checks."""

    def __init__(self, workdir: Path | str):
        self.workdir = canonical_path(workdir)
        if not self.workdir.is_dir():
            raise ToolPolicyError(f"workdir is not a directory: {self.workdir}")
        self._handlers: dict[str, Callable[[dict[str, Any]], ToolResult]] = {
            "list_files": self._list_files,
            "read_file": self._read_file,
            "read_bytes": self._read_bytes,
            "search_text": self._search_text,
            "security_scan": self._security_scan,
            "audit_signals": self._audit_signals,
            "sql_parameterize": self._sql_parameterize,
            "forensics_analyze": self._forensics_analyze,
            "read_events": self._read_events,
            "dns_exfil_correlate": self._dns_exfil_correlate,
            "binary_records": self._binary_records,
            "ctf_transform": self._ctf_transform,
            "ctf_batch_transform": self._ctf_batch_transform,
            "write_exact_text": self._write_exact_text,
            "apply_patch": self._apply_patch,
            "run_command": self._run_command,
        }

    def _path(self, raw_value: object, *, default: Path | None = None) -> Path:
        if raw_value is None:
            if default is None:
                raise ToolPolicyError("required path is missing")
            candidate = default
        elif isinstance(raw_value, str) and raw_value:
            try:
                candidate = map_instruction_path(raw_value, self.workdir)
            except ContractError as error:
                raise ToolPolicyError(str(error)) from error
        else:
            raise ToolPolicyError("path must be a non-empty string")
        resolved = canonical_path(candidate)
        if not path_is_within(resolved, self.workdir):
            raise ToolPolicyError(f"path is outside workdir: {candidate}")
        return resolved

    def catalog(self, decision: StrategyDecision) -> tuple[ToolDefinition, ...]:
        allowed = MODE_ACTIONS.get(decision.mode, frozenset())
        return tuple(TOOL_DEFINITIONS[name] for name in TOOL_ORDER if name in allowed)

    def _analysis_target(self, raw_value: object) -> Path:
        target = self._path(raw_value, default=self.workdir)
        relative = target.relative_to(self.workdir).as_posix()
        if relative != "." and protected_path(relative):
            raise ToolPolicyError(f"refusing protected analysis target: {relative}")
        return target

    def execute(self, action: AgentAction, decision: StrategyDecision) -> ToolResult:
        allowed = MODE_ACTIONS.get(decision.mode, frozenset())
        if action.name not in allowed:
            return ToolResult(
                False,
                f"action {action.name!r} is forbidden in {decision.mode!r} mode",
            )
        handler = self._handlers.get(action.name)
        if handler is None:
            return ToolResult(False, f"unknown action: {action.name}")
        if not isinstance(action.arguments, dict):
            return ToolResult(False, "action arguments must be an object")
        try:
            return handler(action.arguments)
        except (OSError, UnicodeError, ValueError, RuntimeError) as error:
            return ToolResult(False, f"{action.name} failed: {error}")

    @staticmethod
    def _only(arguments: dict[str, Any], allowed: set[str], action: str) -> None:
        unknown = sorted(set(arguments) - allowed)
        if unknown:
            raise ToolPolicyError(f"unsupported {action} argument(s): {unknown}")

    def _list_files(self, arguments: dict[str, Any]) -> ToolResult:
        self._only(arguments, {"path", "max_depth", "max_entries"}, "list_files")
        data = list_workspace_files(
            self.workdir,
            path=arguments.get("path", "."),
            max_depth=arguments.get("max_depth", 6),
            max_entries=arguments.get("max_entries", 200),
        )
        return ToolResult(True, f"listed {data['count']} workspace file(s)", data)

    def _read_file(self, arguments: dict[str, Any]) -> ToolResult:
        self._only(arguments, {"path", "start_line", "max_lines"}, "read_file")
        if "path" not in arguments:
            raise ToolPolicyError("read_file requires path")
        data = read_workspace_text(
            self.workdir,
            path=arguments["path"],
            start_line=arguments.get("start_line", 1),
            max_lines=arguments.get("max_lines", 200),
        )
        return ToolResult(
            True,
            f"read lines {data['start_line']}..{data['end_line']} from {data['path']}",
            data,
        )

    def _read_bytes(self, arguments: dict[str, Any]) -> ToolResult:
        self._only(arguments, {"path", "offset", "length"}, "read_bytes")
        if "path" not in arguments:
            raise ToolPolicyError("read_bytes requires path")
        data = read_workspace_bytes(
            self.workdir,
            path=arguments["path"],
            offset=arguments.get("offset", 0),
            length=arguments.get("length", 256),
        )
        return ToolResult(True, f"read {data['bytes_read']} byte(s) from {data['path']}", data)

    def _search_text(self, arguments: dict[str, Any]) -> ToolResult:
        self._only(
            arguments, {"query", "path", "glob", "case_sensitive"}, "search_text"
        )
        if "query" not in arguments:
            raise ToolPolicyError("search_text requires query")
        data = search_workspace_text(
            self.workdir,
            query=arguments["query"],
            path=arguments.get("path", "."),
            glob=arguments.get("glob", "*"),
            case_sensitive=arguments.get("case_sensitive", False),
        )
        return ToolResult(True, f"text search found {data['match_count']} match(es)", data)

    def _security_scan(self, arguments: dict[str, Any]) -> ToolResult:
        allowed_keys = {"target", "write_report", "output"}
        unknown = sorted(set(arguments) - allowed_keys)
        if unknown:
            raise ToolPolicyError(f"unsupported security_scan argument(s): {unknown}")
        target = self._analysis_target(arguments.get("target"))
        findings = scan_project(target, include_tests=False)
        write_report = _expect_bool(arguments, "write_report", False)
        output_path: Path | None = None
        if write_report:
            raw_output = arguments.get("output", "security_report.json")
            output_path = resolve_workspace_path(
                self.workdir, raw_output, must_exist=False, for_write=True
            )
            relative = output_path.relative_to(self.workdir).as_posix()
            if protected_path(relative) or dependency_path(relative):
                raise ToolPolicyError(f"refusing report path: {relative}")
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(render_report(findings), encoding="utf-8", newline="\n")
        return ToolResult(
            True,
            f"security scan completed with {len(findings)} finding(s)",
            {
                **finding_observation(findings),
                "report": str(output_path) if output_path else None,
                "scope": "Python dynamic SQL only; a clean scan does not prove other vulnerability classes absent",
            },
        )

    def _audit_signals(self, arguments: dict[str, Any]) -> ToolResult:
        self._only(arguments, {"target"}, "audit_signals")
        target = self._analysis_target(arguments.get("target"))
        data = scan_audit_signals(target)
        return ToolResult(
            True,
            f"non-SQL audit scan produced {data['lead_count']} lead(s); confirm each from source",
            data,
        )

    def _sql_parameterize(self, arguments: dict[str, Any]) -> ToolResult:
        allowed_keys = {"target"}
        unknown = sorted(set(arguments) - allowed_keys)
        if unknown:
            raise ToolPolicyError(f"unsupported sql_parameterize argument(s): {unknown}")
        target = self._analysis_target(arguments.get("target"))
        changes = parameterize_project(target, apply=True)
        return ToolResult(
            True,
            f"SQL parameterization applied {len(changes)} change(s)",
            {
                "change_count": len(changes),
                "changes": [asdict(change) for change in changes],
            },
        )

    def _forensics_analyze(self, arguments: dict[str, Any]) -> ToolResult:
        allowed_keys = {"target", "output"}
        unknown = sorted(set(arguments) - allowed_keys)
        if unknown:
            raise ToolPolicyError(f"unsupported forensics_analyze argument(s): {unknown}")
        target = self._analysis_target(arguments.get("target"))
        output = resolve_workspace_path(
            self.workdir,
            arguments.get("output", "incident_report.txt"),
            must_exist=False,
            for_write=True,
        )
        relative = output.relative_to(self.workdir).as_posix()
        if protected_path(relative) or dependency_path(relative):
            raise ToolPolicyError(f"refusing incident report path: {relative}")

        incident_dir = resolve_incident_directory(target)
        ensure_output_outside_evidence(output, incident_dir)
        before_digest = inventory_digest(inventory_artifacts(incident_dir))
        conclusion = analyze_incident(incident_dir)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(format_report(conclusion), encoding="utf-8", newline="\n")
        after_digest = inventory_digest(inventory_artifacts(incident_dir))
        if before_digest != after_digest:
            raise ToolPolicyError("evidence changed during forensics analysis")
        return ToolResult(
            True,
            "forensics correlation completed and incident report written",
            {"report": str(output)},
        )

    def _write_exact_text(self, arguments: dict[str, Any]) -> ToolResult:
        if set(arguments) != {"path", "content"}:
            raise ToolPolicyError("write_exact_text requires only path and content")
        content = arguments["content"]
        if not isinstance(content, str):
            raise ToolPolicyError("content must be text")
        if len(content) > MAX_EXACT_TEXT_CHARS:
            raise ToolPolicyError(f"content exceeds {MAX_EXACT_TEXT_CHARS} characters")
        output = resolve_workspace_path(
            self.workdir, arguments["path"], must_exist=False, for_write=True
        )
        relative = output.relative_to(self.workdir).as_posix()
        if protected_path(relative) or dependency_path(relative):
            raise ToolPolicyError(f"refusing protected output path: {relative}")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8", newline="\n")
        return ToolResult(
            True,
            f"wrote exact UTF-8 content to {relative}",
            {"path": str(output), "characters": len(content)},
        )

    def _read_events(self, arguments: dict[str, Any]) -> ToolResult:
        self._only(arguments, {"path", "time_field", "clock_offset_seconds", "offset_start", "offset_end", "start_line", "max_rows"}, "read_events")
        if not {"path", "time_field"} <= arguments.keys():
            raise ToolPolicyError("read_events requires path and time_field")
        path, raw = _read_regular_bytes(self.workdir, arguments["path"])
        data = event_table(raw, **{key: value for key, value in arguments.items() if key != "path"})
        data["path"] = path.relative_to(self.workdir).as_posix()
        return ToolResult(True, f"read {len(data['rows'])} event(s) with explicit UTC correction; correlate source IDs before selecting the requested event", data)

    def _dns_exfil_correlate(self, arguments: dict[str, Any]) -> ToolResult:
        self._only(
            arguments,
            {"resolver_path", "inventory_path", "process_path", "domain", "client"},
            "dns_exfil_correlate",
        )
        required = {"resolver_path", "inventory_path", "process_path", "domain"}
        if not required <= set(arguments):
            raise ToolPolicyError(
                "dns_exfil_correlate requires resolver_path, inventory_path, process_path and domain"
            )
        resolver_path, resolver_raw = _read_regular_bytes(
            self.workdir, arguments["resolver_path"]
        )
        inventory_path, inventory_raw = _read_regular_bytes(
            self.workdir, arguments["inventory_path"]
        )
        process_path, process_raw = _read_regular_bytes(
            self.workdir, arguments["process_path"]
        )
        data = correlate_dns_exfil(
            resolver_raw=resolver_raw,
            inventory_raw=inventory_raw,
            process_raw=process_raw,
            domain=arguments["domain"],
            client=arguments.get("client"),
        )
        data["sources"] = {
            "resolver": resolver_path.relative_to(self.workdir).as_posix(),
            "inventory": inventory_path.relative_to(self.workdir).as_posix(),
            "process": process_path.relative_to(self.workdir).as_posix(),
        }
        return ToolResult(
            True,
            "deduplicated and correlated sequenced DNS exfiltration evidence",
            data,
        )

    def _binary_records(self, arguments: dict[str, Any]) -> ToolResult:
        self._only(arguments, {"path", "magic_hex", "header_format", "length_field", "max_records", "field_sizes", "byte_order"}, "binary_records")
        required = {"path", "magic_hex", "length_field"}
        if not required <= arguments.keys():
            raise ToolPolicyError("binary_records requires path, magic_hex, length_field and field_sizes OR header_format")
        path, raw = _read_regular_bytes(self.workdir, arguments["path"])
        data = carve_records(raw, **{key: value for key, value in arguments.items() if key != "path"})
        data["path"] = path.relative_to(self.workdir).as_posix()
        if not data["valid_count"]:
            return ToolResult(False, "no valid records for the supplied schema; correct the schema by comparing layout field count/widths "
                              "with documentation before transforming. Invalid offsets/lengths are NOT usable; "
                              "do not clamp the declared length to EOF or assume input corruption", data)
        return ToolResult(True, f"located {data['valid_count']} valid / {data['count']} candidate record(s); select the configured header values", data)

    def _ctf_transform(self, arguments: dict[str, Any]) -> ToolResult:
        self._only(arguments, {"value", "steps", "path", "offset", "length"}, "ctf_transform")
        if set(arguments) == {"value", "steps"}:
            data = transform_ctf_data(arguments["value"], arguments["steps"])
        elif set(arguments) == {"path", "steps"}:
            path, raw = _read_regular_bytes(self.workdir, arguments["path"])
            if not raw or len(raw) > MAX_TRANSFORM_BYTES:
                raise ToolPolicyError(
                    f"complete transform source must contain 1..{MAX_TRANSFORM_BYTES} bytes"
                )
            data = transform_ctf_bytes(raw, arguments["steps"])
            data["source"] = {
                "path": path.relative_to(self.workdir).as_posix(),
                "offset": 0,
                "length": len(raw),
            }
        elif set(arguments) == {"path", "offset", "length", "steps"}:
            source = read_workspace_bytes(
                self.workdir, path=arguments["path"],
                offset=arguments["offset"], length=arguments["length"],
            )
            if source["bytes_read"] != arguments["length"]:
                raise ToolPolicyError("binary range is incomplete; check offset and declared length")
            data = transform_ctf_bytes(bytes.fromhex(source["hex"]), arguments["steps"])
            data["source"] = {
                "path": source["path"], "offset": source["offset"],
                "length": source["bytes_read"],
            }
        else:
            raise ToolPolicyError(
                "ctf_transform requires value+steps, path+steps, OR path+offset+length+steps"
            )
        return ToolResult(
            True,
            f"applied {len(data['operations'])} bounded CTF transform(s)",
            data,
        )

    def _ctf_batch_transform(self, arguments: dict[str, Any]) -> ToolResult:
        self._only(arguments, {"paths", "steps", "final_steps"}, "ctf_batch_transform")
        if not {"paths", "steps"} <= set(arguments):
            raise ToolPolicyError("ctf_batch_transform requires paths and steps")
        paths = arguments["paths"]
        if not isinstance(paths, list) or not 1 <= len(paths) <= 32 or not all(
            isinstance(path, str) and path for path in paths
        ):
            raise ToolPolicyError("paths must be an array of 1..32 non-empty strings")
        if len(set(paths)) != len(paths):
            raise ToolPolicyError(
                "paths must not repeat a shard; derive one ordered entry per manifest index"
            )

        decoded: list[bytes] = []
        components: list[dict[str, Any]] = []
        input_digest = hashlib.sha256()
        input_size = 0
        resolved_paths: set[Path] = set()
        for raw_path in paths:
            path, raw = _read_regular_bytes(self.workdir, raw_path)
            if path in resolved_paths:
                raise ToolPolicyError(
                    "paths resolve to a duplicate shard; use every evidence file once"
                )
            resolved_paths.add(path)
            if not raw or len(raw) > MAX_TRANSFORM_BYTES:
                raise ToolPolicyError(
                    f"each batch source must contain 1..{MAX_TRANSFORM_BYTES} bytes"
                )
            input_size += len(raw)
            input_digest.update(len(raw).to_bytes(8, "big"))
            input_digest.update(raw)
            transformed = transform_ctf_bytes(raw, arguments["steps"])
            output = bytes.fromhex(transformed["hex"])
            decoded.append(output)
            components.append(
                {
                    "path": path.relative_to(self.workdir).as_posix(),
                    "input_sha256": transformed["input_sha256"],
                    "output_sha256": transformed["sha256"],
                    "output_size_bytes": transformed["size_bytes"],
                    "operations": transformed["operations"],
                }
            )
        combined = b"".join(decoded)
        if len(combined) > MAX_TRANSFORM_BYTES:
            raise ToolPolicyError(
                f"concatenated decoded output exceeds {MAX_TRANSFORM_BYTES} bytes"
            )
        final_steps = arguments.get("final_steps")
        if final_steps is not None:
            data = transform_ctf_bytes(combined, final_steps)
            operations = ["batch-each:" + ",".join(components[0]["operations"]), *data["operations"]]
            data["operations"] = operations
        else:
            data = describe_ctf_bytes(
                combined,
                input_size_bytes=input_size,
                input_sha256=input_digest.hexdigest(),
                operations=["batch-each:" + ",".join(components[0]["operations"]), "concat-decoded"],
            )
        data["components"] = components
        return ToolResult(
            True,
            f"transformed and concatenated {len(components)} ordered file(s)",
            data,
        )

    def _apply_patch(self, arguments: dict[str, Any]) -> ToolResult:
        self._only(arguments, {"patch"}, "apply_patch")
        if "patch" not in arguments:
            raise ToolPolicyError("apply_patch requires patch")
        data = apply_workspace_patch(self.workdir, patch=arguments["patch"])
        return ToolResult(
            True,
            f"applied {data['hunk_count']} hunk(s) to {data['file_count']} file(s)",
            data,
        )

    def _run_command(self, arguments: dict[str, Any]) -> ToolResult:
        self._only(arguments, {"argv", "cwd", "timeout_seconds"}, "run_command")
        if "argv" not in arguments:
            raise ToolPolicyError("run_command requires argv")
        data = run_workspace_command(
            self.workdir,
            argv=arguments["argv"],
            cwd=arguments.get("cwd", "."),
            timeout_seconds=arguments.get("timeout_seconds", 60),
        )
        ok = data["exit_code"] == 0 and not data["timed_out"]
        summary = (
            f"command {data['profile']} completed with exit code {data['exit_code']}"
            if not data["timed_out"]
            else f"command {data['profile']} timed out"
        )
        return ToolResult(ok, summary, data)
