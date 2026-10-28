"""Command line: python -m tmcheck MODEL.yaml

Print one JSON object with the keys "issues", "gaps", "policy" and "ranked" (each a list of
objects with the dataclass fields, for example {"ref": "f01", "category": "T"}).
Exit code 2 if the file cannot be loaded, 1 if there are any issues, gaps or policy findings,
otherwise 0. If there are structural issues you may leave "gaps" and "policy" empty.
"""
import sys
"""CLI entry point: python -m tmcheck MODEL.yaml"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict

from .core import (
    ModelError,
    coverage_gaps,
    load_model,
    policy_findings,
    rank,
    validate,
)


def _build_report(model: dict) -> dict:
    issues = validate(model)

    # If the model is structurally broken, gaps/policy may be left empty.
    if issues:
        gaps: list = []
        policy: list = []
    else:
        gaps = coverage_gaps(model)
        policy = policy_findings(model)

    ranked = rank(model)

    return {
        "issues": [asdict(i) for i in issues],
        "gaps": [asdict(g) for g in gaps],
        "policy": [asdict(p) for p in policy],
        "ranked": [asdict(r) for r in ranked],
    }


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    if len(argv) != 1:
        print("usage: python -m tmcheck MODEL.yaml", file=sys.stderr)
        return 2

    path = argv[0]

    try:
        model = load_model(path)
    except ModelError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = _build_report(model)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=False))

    if report["issues"] or report["gaps"] or report["policy"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m tmcheck MODEL.yaml", file=sys.stderr)
        return 2
    path = argv[0]
    raise NotImplementedError


if __name__ == "__main__":
    raise SystemExit(main())
