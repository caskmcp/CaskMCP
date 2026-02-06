"""Scope engine for filtering endpoints."""

from caskmcp.core.scope.builtins import get_builtin_scope
from caskmcp.core.scope.engine import ScopeEngine
from caskmcp.core.scope.parser import parse_scope_dict, parse_scope_file

__all__ = [
    "ScopeEngine",
    "get_builtin_scope",
    "parse_scope_file",
    "parse_scope_dict",
]
