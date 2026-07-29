"""Canonical Solidity function identifiers shared by analysis and PoC stages."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Set


def canonical_function_id(name: str, parameters: Iterable[Any] = ()) -> str:
    """Return the ABI-style identifier used throughout this application.

    The contract name is deliberately not included: a finding is evaluated
    against one analyzed target at a time, while `name(type,...)` preserves
    overload information and remains directly usable in Solidity test code.
    """
    types: List[str] = []
    for parameter in parameters:
        if isinstance(parameter, (tuple, list)):
            types.append(str(parameter[0]))
        elif isinstance(parameter, dict):
            types.append(str(parameter.get("type", "")))
        else:
            types.append(str(parameter))
    return f"{name}({','.join(types)})"


def known_function_ids(function_details: Iterable[Dict[str, Any]]) -> Set[str]:
    return {
        detail["function_id"]
        for detail in function_details
        if detail.get("function_id") and detail.get("function") not in {"constructor", "fallback", "receive"}
    }


def normalize_affected_functions(values: Iterable[Any], allowed: Set[str]) -> List[str]:
    """Accept only exact canonical IDs; never silently map hallucinated names."""
    normalized: List[str] = []
    for value in values or []:
        candidate = str(value).strip()
        if candidate in allowed and candidate not in normalized:
            normalized.append(candidate)
    return normalized
