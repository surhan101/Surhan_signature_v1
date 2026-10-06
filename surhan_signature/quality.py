"""Code-quality telemetry used while the legacy API is decomposed safely."""

from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path

import frappe


CMD_COMPAT_METHODS = frozenset({
    "phase27b_apply_employee_control_permissions",
    "phase27b_admin_register_employee_signature",
    "phase27b_seed_employee_controls_from_employees",
    "phase27b_restrict_employee_signature_profile_permissions",
    "phase27e_operations_data",
    "phase27g_signature_inbox_data",
})


def api_metrics(path: str | Path | None = None) -> dict:
    source_path = Path(path) if path else Path(__file__).with_name("api.py")
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(source_path))
    definitions = defaultdict(list)
    command_compatible = set()
    whitelist_count = 0
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        definitions[node.name].append(node.lineno)
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if isinstance(target, ast.Attribute) and target.attr == "whitelist":
                whitelist_count += 1
        arguments = {item.arg for item in node.args.args + node.args.kwonlyargs}
        if "cmd" in arguments or node.args.kwarg:
            command_compatible.add(node.name)
    duplicates = {name: lines for name, lines in definitions.items() if len(lines) > 1}
    return {
        "lines": len(source.splitlines()),
        "top_level_functions": len(definitions),
        "whitelisted_methods": whitelist_count,
        "duplicate_function_names": len(duplicates),
        "cmd_compatibility_ok": CMD_COMPAT_METHODS <= command_compatible,
        "cmd_compatibility_missing": sorted(CMD_COMPAT_METHODS - command_compatible),
    }


@frappe.whitelist()
def health():
    metrics = api_metrics()
    recent_cmd_errors = frappe.db.count(
        "Error Log",
        filters={
            "creation": (">=", frappe.utils.add_to_date(frappe.utils.now_datetime(), hours=-24)),
            "method": ("like", "%unexpected keyword argument 'cmd'%"),
        },
    )
    return {
        "ok": bool(metrics["cmd_compatibility_ok"]),
        "api": metrics,
        "recent_cmd_errors_24h": recent_cmd_errors,
        "decomposition_strategy": "incremental",
    }
