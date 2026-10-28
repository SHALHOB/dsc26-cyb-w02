"""tmcheck: a checker for threat models kept as YAML in the repository.

Fill in every function. Keep the names and signatures exactly as they are: the grader imports them.
The full rules are in README.md ("What to build").
"""
from __future__ import annotations

from dataclasses import dataclass

"""Threat-model checker: loading, validation, coverage and ranking."""


import re
from pathlib import Path

import yaml


class ModelError(Exception):
    ...


@dataclass(frozen=True, order=True)
class Issue:
    ref: str
    code: str
    message: str = ""


@dataclass(frozen=True, order=True)
class Gap:
    ref: str
    category: str


@dataclass(frozen=True)
class RankedThreat:
    id: str
    score: int
    level: str


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

_KINDS = frozenset({"external_entity", "process", "data_store"})
_STRIDE = frozenset("STRIDE")
# STRIDE ordering used for coverage_gaps output: S, T, R, I, D, E
_STRIDE_ORDER = {c: i for i, c in enumerate("STRIDE")}

_STATUSES = frozenset({"open", "mitigated", "accepted"})

_APPLICABLE: dict[str, frozenset[str]] = {
    "external_entity": frozenset("SR"),
    "process":         frozenset("STRIDE"),
    "data_store":      frozenset("TID"),
    "data_flow":       frozenset("TID"),
}

_TLS_PROTOCOLS = frozenset({"https", "tls", "mtls", "sftp", "ssh"})


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

def _as_list(value, section: str) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ModelError(f"section {section!r} must be a list")
    return value


def load_model(path) -> dict:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ModelError(f"cannot read {path!r}: {exc}") from exc
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ModelError(f"invalid YAML: {exc}") from exc

    if not isinstance(loaded, dict):
        raise ModelError("top level must be a mapping")

    result = dict(loaded)
    for section in ("zones", "elements", "flows", "threats"):
        result[section] = _as_list(result.get(section), section)
    return result


# --------------------------------------------------------------------------- #
# Applicability
# --------------------------------------------------------------------------- #

def applicable(kind: str, *, is_log: bool = False) -> set[str]:
    if kind not in _APPLICABLE:
        raise ValueError(f"unknown kind: {kind!r}")
    result = set(_APPLICABLE[kind])
    if kind == "data_store" and is_log:
        result.add("R")
    return result


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _item_id(item) -> str | None:
    if isinstance(item, dict):
        value = item.get("id")
        if isinstance(value, str):
            return value
    return None


def _zone_index(model: dict) -> dict[str, dict]:
    return {z["id"]: z for z in model.get("zones", []) if isinstance(z, dict) and isinstance(z.get("id"), str)}


def _element_index(model: dict) -> dict[str, dict]:
    return {e["id"]: e for e in model.get("elements", []) if isinstance(e, dict) and isinstance(e.get("id"), str)}


def _flow_index(model: dict) -> dict[str, dict]:
    return {f["id"]: f for f in model.get("flows", []) if isinstance(f, dict) and isinstance(f.get("id"), str)}


def _int_1_to_5(value) -> bool:
    # bool is a subclass of int — explicitly reject it. Floats are rejected too.
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 5


def _natural_key(s: str):
    """Split into digit / non-digit runs for natural ordering (T2 < T10)."""
    parts = re.split(r"(\d+)", s)
    return [int(p) if p.isdigit() else p for p in parts]


# --------------------------------------------------------------------------- #
# validate
# --------------------------------------------------------------------------- #

def validate(model: dict) -> list[Issue]:
    issues: set[Issue] = set()

    zones = model.get("zones", [])
    elements = model.get("elements", [])
    flows = model.get("flows", [])
    threats = model.get("threats", [])

    zone_by_id = _zone_index(model)
    element_by_id = _element_index(model)
    flow_by_id = _flow_index(model)

    # ---- DUPLICATE_ID across one shared id space ---------------------------
    seen: dict[str, int] = {}
    for section in (zones, elements, flows, threats):
        for item in section:
            ident = _item_id(item)
            if ident is None:
                continue
            seen[ident] = seen.get(ident, 0) + 1
    for ident, count in seen.items():
        if count > 1:
            issues.add(Issue(ident, "DUPLICATE_ID", "id is used more than once"))

    # ---- zones -------------------------------------------------------------
    # (no structural checks for zones beyond duplicate ids, per spec)

    # ---- elements ----------------------------------------------------------
    for element in elements:
        ident = _item_id(element)
        if ident is None:
            continue
        kind = element.get("kind")
        if kind not in _KINDS:
            issues.add(Issue(ident, "BAD_KIND", f"unknown element kind: {kind!r}"))
        zone = element.get("zone")
        if zone not in zone_by_id:
            issues.add(Issue(ident, "UNKNOWN_ZONE", f"unknown zone: {zone!r}"))

    # ---- flows -------------------------------------------------------------
    for flow in flows:
        ident = _item_id(flow)
        if ident is None:
            continue
        source = flow.get("source")
        target = flow.get("target")

        source_elem = element_by_id.get(source) if isinstance(source, str) else None
        target_elem = element_by_id.get(target) if isinstance(target, str) else None

        if source_elem is None or target_elem is None:
            issues.add(Issue(ident, "UNKNOWN_REF", "flow source or target is not an element"))

        # INVALID_FLOW: source equals target, or neither end is a process.
        source_is_process = source_elem is not None and source_elem.get("kind") == "process"
        target_is_process = target_elem is not None and target_elem.get("kind") == "process"
        if source == target or not (source_is_process or target_is_process):
            issues.add(Issue(ident, "INVALID_FLOW", "flow endpoints must include a process and differ"))

    # ---- threats -----------------------------------------------------------
    for threat in threats:
        ident = _item_id(threat)
        if ident is None:
            continue
        target = threat.get("target")
        category = threat.get("category")

        # UNKNOWN_REF: target is neither an element nor a flow.
        target_elem = element_by_id.get(target) if isinstance(target, str) else None
        target_flow = flow_by_id.get(target) if isinstance(target, str) else None
        if target_elem is None and target_flow is None:
            issues.add(Issue(ident, "UNKNOWN_REF", f"threat target not found: {target!r}"))

        # BAD_CATEGORY: must be exactly one uppercase STRIDE letter.
        category_valid = isinstance(category, str) and category in _STRIDE
        if not category_valid:
            issues.add(Issue(ident, "BAD_CATEGORY", f"invalid category: {category!r}"))
        else:
            # INAPPLICABLE_CATEGORY: only meaningful if target is known.
            if target_elem is not None:
                kind = target_elem.get("kind")
                if kind in _APPLICABLE:
                    is_log = bool(target_elem.get("is_log"))
                    if category not in applicable(kind, is_log=is_log):
                        issues.add(
                            Issue(ident, "INAPPLICABLE_CATEGORY",
                                  f"{category} does not apply to {kind}")
                        )
            elif target_flow is not None:
                if category not in applicable("data_flow"):
                    issues.add(
                        Issue(ident, "INAPPLICABLE_CATEGORY",
                              f"{category} does not apply to data_flow")
                    )

        likelihood = threat.get("likelihood")
        impact = threat.get("impact")
        if not _int_1_to_5(likelihood) or not _int_1_to_5(impact):
            issues.add(Issue(ident, "BAD_SCORE", "likelihood/impact must be integers 1..5"))

        status = threat.get("status")
        if status not in _STATUSES:
            issues.add(Issue(ident, "BAD_STATUS", f"invalid status: {status!r}"))

        if status == "mitigated":
            mitigation = threat.get("mitigation")
            if not isinstance(mitigation, str) or not mitigation.strip():
                issues.add(Issue(ident, "MISSING_MITIGATION", "mitigated threat needs mitigation text"))

        if status == "accepted":
            justification = threat.get("justification")
            if not isinstance(justification, str) or not justification.strip():
                issues.add(Issue(ident, "MISSING_JUSTIFICATION", "accepted threat needs justification text"))

    return sorted(issues)


# --------------------------------------------------------------------------- #
# crossing_flows
# --------------------------------------------------------------------------- #

def crossing_flows(model: dict) -> list[str]:
    zone_by_id = _zone_index(model)
    element_by_id = _element_index(model)
    result: list[str] = []

    for flow in model.get("flows", []):
        ident = _item_id(flow)
        if ident is None:
            continue
        source_elem = element_by_id.get(flow.get("source"))
        target_elem = element_by_id.get(flow.get("target"))
        if source_elem is None or target_elem is None:
            continue
        source_zone = source_elem.get("zone")
        target_zone = target_elem.get("zone")
        if source_zone not in zone_by_id or target_zone not in zone_by_id:
            # An end in an undefined zone can't be compared reliably — skip.
            continue
        if source_zone != target_zone:
            result.append(ident)
    return result


# --------------------------------------------------------------------------- #
# coverage_gaps
# --------------------------------------------------------------------------- #

def coverage_gaps(model: dict) -> list[Gap]:
    element_by_id = _element_index(model)
    flow_by_id = _flow_index(model)

    # Scope: every crossing flow plus both of its end elements.
    scope: set[str] = set()
    for flow_id in crossing_flows(model):
        flow = flow_by_id.get(flow_id)
        if flow is None:
            continue
        scope.add(flow_id)
        for end in (flow.get("source"), flow.get("target")):
            if isinstance(end, str) and end in element_by_id:
                scope.add(end)

    # Collect (target, category) pairs already covered by any threat.
    covered: set[tuple[str, str]] = set()
    for threat in model.get("threats", []):
        target = threat.get("target")
        category = threat.get("category")
        if isinstance(target, str) and isinstance(category, str):
            covered.add((target, category))

    gaps: list[Gap] = []
    for ref in scope:
        if ref in flow_by_id:
            kind = "data_flow"
            is_log = False
        else:
            element = element_by_id.get(ref)
            if element is None:
                continue
            kind = element.get("kind")
            if kind not in _APPLICABLE:
                continue
            is_log = bool(element.get("is_log"))
        for category in applicable(kind, is_log=is_log):
            if (ref, category) not in covered:
                gaps.append(Gap(ref, category))

    gaps.sort(key=lambda g: (g.ref, _STRIDE_ORDER.get(g.category, 99)))
    return gaps


# --------------------------------------------------------------------------- #
# policy_findings
# --------------------------------------------------------------------------- #

def policy_findings(model: dict) -> list[Issue]:
    zone_by_id = _zone_index(model)
    element_by_id = _element_index(model)
    flow_by_id = _flow_index(model)
    findings: set[Issue] = set()

    # Trust lookup helper (missing zone treated as "no trust" → cannot compare).
    def _trust(zone_id) -> int | None:
        zone = zone_by_id.get(zone_id)
        if zone is None:
            return None
        trust = zone.get("trust")
        if isinstance(trust, int) and not isinstance(trust, bool):
            return trust
        return None

    crossing = set(crossing_flows(model))

    for flow in model.get("flows", []):
        ident = _item_id(flow)
        if ident is None or ident not in crossing:
            continue

        protocol = flow.get("protocol")
        proto_norm = protocol.strip().lower() if isinstance(protocol, str) else ""
        if proto_norm not in _TLS_PROTOCOLS:
            findings.add(Issue(ident, "UNENCRYPTED_CROSSING",
                               f"crossing flow uses non-encrypted protocol: {protocol!r}"))

        source_elem = element_by_id.get(flow.get("source"))
        target_elem = element_by_id.get(flow.get("target"))
        if source_elem is not None and target_elem is not None:
            source_trust = _trust(source_elem.get("zone"))
            target_trust = _trust(target_elem.get("zone"))
            if (source_trust is not None and target_trust is not None
                    and target_trust > source_trust):
                if flow.get("authenticated") is not True:
                    findings.add(Issue(ident, "UNAUTHENTICATED_INBOUND",
                                       "unauthenticated crossing into higher-trust zone"))

    # PII_STORE_WITHOUT_I_THREAT
    i_targets: set[str] = set()
    for threat in model.get("threats", []):
        if threat.get("category") == "I" and isinstance(threat.get("target"), str):
            i_targets.add(threat["target"])

    for element in model.get("elements", []):
        ident = _item_id(element)
        if ident is None:
            continue
        if element.get("kind") != "data_store":
            continue
        if element.get("holds_pii") is not True:
            continue
        if ident not in i_targets:
            findings.add(Issue(ident, "PII_STORE_WITHOUT_I_THREAT",
                               "PII data store has no information-disclosure threat"))

    return sorted(findings)


# --------------------------------------------------------------------------- #
# rank
# --------------------------------------------------------------------------- #

def rank(model: dict) -> list[RankedThreat]:
    ranked: list[tuple[int, int, str]] = []  # (score, impact, id)

    for threat in model.get("threats", []):
        ident = _item_id(threat)
        if ident is None:
            continue
        if threat.get("status") != "open":
            continue
        likelihood = threat.get("likelihood")
        impact = threat.get("impact")
        if not _int_1_to_5(likelihood) or not _int_1_to_5(impact):
            continue
        score = likelihood * impact
        if score >= 15:
            level = "high"
        elif score >= 8:
            level = "medium"
        else:
            level = "low"
        ranked.append((score, impact, ident, level))  # type: ignore[arg-type]

    ranked.sort(key=lambda t: (-t[0], -t[1], _natural_key(t[2])))
    return [RankedThreat(id=t[2], score=t[0], level=t[3]) for t in ranked]

class ModelError(Exception):
    """The file cannot be read as a threat model."""


@dataclass(frozen=True, order=True)
class Issue:
    ref: str          # id of the zone/element/flow/threat the issue is about
    code: str
    message: str = ""


@dataclass(frozen=True, order=True)
class Gap:
    ref: str          # element or flow id
    category: str     # one STRIDE letter


@dataclass(frozen=True)
class RankedThreat:
    id: str
    score: int
    level: str        # "high" | "medium" | "low"


def load_model(path) -> dict:
    """Read the YAML file with yaml.safe_load and return the mapping.

    Missing or null `zones`, `elements`, `flows`, `threats` become []. Raise ModelError if the
    file cannot be read, is not valid YAML, uses a tag safe_load refuses, has a top level that
    is not a mapping, or has one of the four sections that is not a list.
    """
    raise NotImplementedError


def applicable(kind: str, *, is_log: bool = False) -> set[str]:
    """STRIDE per element: the categories that apply to `kind`. Unknown kind: ValueError."""
    raise NotImplementedError


def validate(model: dict) -> list[Issue]:
    """Structural problems, sorted by (ref, code, message), no duplicates."""
    raise NotImplementedError


def crossing_flows(model: dict) -> list[str]:
    """Ids of flows whose source and target are in different zones, in file order."""
    raise NotImplementedError


def coverage_gaps(model: dict) -> list[Gap]:
    """(ref, category) pairs in scope with no threat recorded, sorted by ref then S, T, R, I, D, E."""
    raise NotImplementedError


def policy_findings(model: dict) -> list[Issue]:
    """UNENCRYPTED_CROSSING, UNAUTHENTICATED_INBOUND, PII_STORE_WITHOUT_I_THREAT, sorted by (ref, code)."""
    raise NotImplementedError


def rank(model: dict) -> list[RankedThreat]:
    """Open threats with valid scores, by score desc, then impact desc, then natural id order."""
    raise NotImplementedError
