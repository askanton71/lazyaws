#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Compatibility entrypoint for the LazyAWS Excel report builder.

The canonical implementation lives in checks/check_report.py.  This module is
kept so older commands such as `python checks/report.py` still work.
"""

from __future__ import annotations

import argparse
import json

try:
    from .check_report import analyze
except Exception:
    from check_report import analyze  # type: ignore


def add_arguments(ap: argparse.ArgumentParser):
    ap.add_argument("--out", default="Reports/LazyAWS_Report.xlsx", help="Output XLSX path")
    ap.add_argument("--profile", default=None, help="(for header only)")
    ap.add_argument("--region", default=None, help="(unused; header only)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LazyAWS - Build Excel Report from RawData/")
    add_arguments(parser)
    args = parser.parse_args()
    try:
        from aws_common import run_check

        run_check(analyze, args)
    except Exception:
        meta, findings, aux = analyze(args)
        print(json.dumps({"Meta": meta, "Findings": findings, "Aux": aux}, indent=2))
