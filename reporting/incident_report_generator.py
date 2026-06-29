#!/usr/bin/env python3
"""
reporting/incident_report_generator.py
=======================================
Generates a structured Markdown incident report from a JSON incident summary.
Based on a Five W's investigation framework used in MSSP SOC operations.

Usage:
    python incident_report_generator.py --input incident.json
    python incident_report_generator.py --input incident.json --output report.md
    python incident_report_generator.py --interactive

Input JSON format: see incident_template.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


# ── Template ──────────────────────────────────────────────────────────────────

REPORT_TEMPLATE = """\
# Incident Report — {title}

| Field | Value |
|---|---|
| **Incident ID** | {incident_id} |
| **Severity** | {severity} |
| **Status** | {status} |
| **Classification** | {classification} |
| **Analyst** | {analyst} |
| **Date / Time (UTC)** | {datetime_utc} |
| **Customer / Tenant** | {customer} |
| **SIEM Platform** | {siem_platform} |
| **Alert Rule** | {alert_rule} |

---

## Executive Summary

{executive_summary}

---

## Five W's Investigation

### Who
{who}

### What
{what}

### When
{when}

### Where
{where}

### Why (Root Cause / Intent Assessment)
{why}

---

## Timeline

| Time (UTC) | Event |
|---|---|
{timeline_rows}

---

## Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
{ioc_rows}

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique |
|---|---|---|
{mitre_rows}

---

## Evidence

{evidence}

---

## Actions Taken

{actions_taken}

---

## Recommendations

{recommendations}

---

## Verdict

**{verdict}**

{verdict_notes}

---

*Report generated: {generated_at} UTC*
*Author: {analyst}*
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def format_table_rows(items: list, columns: list) -> str:
    """Format a list of dicts into markdown table rows."""
    if not items:
        return "| — | — | — |"
    rows = []
    for item in items:
        row = "| " + " | ".join(str(item.get(col, "—")) for col in columns) + " |"
        rows.append(row)
    return "\n".join(rows)


def format_timeline(events: list) -> str:
    if not events:
        return "| — | — |"
    return "\n".join(f"| {e.get('time','—')} | {e.get('event','—')} |" for e in events)


def format_actions(actions: list) -> str:
    if not actions:
        return "_No actions recorded._"
    return "\n".join(f"{i+1}. {a}" for i, a in enumerate(actions))


def format_evidence(evidence: list) -> str:
    if not evidence:
        return "_No evidence logged._"
    return "\n".join(f"- {e}" for e in evidence)


def format_recommendations(recs: list) -> str:
    if not recs:
        return "_No recommendations._"
    return "\n".join(f"- {r}" for r in recs)


# ── Report Builder ─────────────────────────────────────────────────────────────

def build_report(data: dict) -> str:
    """Build the full Markdown report from incident data dict."""
    return REPORT_TEMPLATE.format(
        title=data.get("title", "Untitled Incident"),
        incident_id=data.get("incident_id", "INC-UNKNOWN"),
        severity=data.get("severity", "Unknown"),
        status=data.get("status", "Open"),
        classification=data.get("classification", "Unclassified"),
        analyst=data.get("analyst", "Unknown"),
        datetime_utc=data.get("datetime_utc", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")),
        customer=data.get("customer", "Unknown"),
        siem_platform=data.get("siem_platform", "Unknown"),
        alert_rule=data.get("alert_rule", "Unknown"),
        executive_summary=data.get("executive_summary", "_No summary provided._"),
        who=data.get("who", "_Not determined._"),
        what=data.get("what", "_Not determined._"),
        when=data.get("when", "_Not determined._"),
        where=data.get("where", "_Not determined._"),
        why=data.get("why", "_Under investigation._"),
        timeline_rows=format_timeline(data.get("timeline", [])),
        ioc_rows=format_table_rows(
            data.get("iocs", []),
            columns=["type", "value", "context"]
        ),
        mitre_rows=format_table_rows(
            data.get("mitre", []),
            columns=["tactic", "technique", "sub_technique"]
        ),
        evidence=format_evidence(data.get("evidence", [])),
        actions_taken=format_actions(data.get("actions_taken", [])),
        recommendations=format_recommendations(data.get("recommendations", [])),
        verdict=data.get("verdict", "Under Investigation"),
        verdict_notes=data.get("verdict_notes", ""),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    )


# ── Interactive Mode ───────────────────────────────────────────────────────────

def interactive_mode() -> dict:
    """Collect incident details interactively via prompts."""
    print("\n=== Incident Report Generator (Interactive Mode) ===\n")
    data = {}
    data["title"]            = input("Incident title: ").strip()
    data["incident_id"]      = input("Incident ID (e.g. INC-2025-001): ").strip()
    data["severity"]         = input("Severity [Critical/High/Medium/Low]: ").strip()
    data["status"]           = input("Status [Open/Closed/In Progress]: ").strip()
    data["classification"]   = input("Classification [True Positive/False Positive/Benign]: ").strip()
    data["analyst"]          = input("Analyst name: ").strip()
    data["customer"]         = input("Customer / Tenant: ").strip()
    data["siem_platform"]    = input("SIEM Platform: ").strip()
    data["alert_rule"]       = input("Alert rule / use case name: ").strip()
    data["executive_summary"]= input("Executive summary (one paragraph): ").strip()
    data["who"]              = input("Who — source account/IP/actor: ").strip()
    data["what"]             = input("What — what happened: ").strip()
    data["when"]             = input("When — timeframe of activity: ").strip()
    data["where"]            = input("Where — affected systems/locations: ").strip()
    data["why"]              = input("Why — root cause or intent: ").strip()
    data["verdict"]          = input("Verdict [True Positive/False Positive/Benign/Inconclusive]: ").strip()
    data["verdict_notes"]    = input("Verdict notes: ").strip()

    print("\nTimeline events (enter blank line when done):")
    data["timeline"] = []
    while True:
        time_str = input("  Time (UTC): ").strip()
        if not time_str:
            break
        event_str = input("  Event: ").strip()
        data["timeline"].append({"time": time_str, "event": event_str})

    print("\nIOCs (enter blank type when done):")
    data["iocs"] = []
    while True:
        ioc_type = input("  IOC Type [ip/domain/hash/url]: ").strip()
        if not ioc_type:
            break
        ioc_value   = input("  Value: ").strip()
        ioc_context = input("  Context: ").strip()
        data["iocs"].append({"type": ioc_type, "value": ioc_value, "context": ioc_context})

    print("\nActions taken (enter blank line when done):")
    data["actions_taken"] = []
    while True:
        action = input("  Action: ").strip()
        if not action:
            break
        data["actions_taken"].append(action)

    return data


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Generate structured incident reports in Markdown")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--input", type=str, help="Path to incident JSON file")
    mode.add_argument("--interactive", action="store_true", help="Enter incident details interactively")
    parser.add_argument("--output", type=str, default=None, help="Output Markdown file path")
    args = parser.parse_args()

    if args.interactive:
        data = interactive_mode()
    else:
        path = Path(args.input)
        if not path.exists():
            print(f"[ERROR] File not found: {args.input}")
            sys.exit(1)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

    report = build_report(data)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"[+] Report saved to: {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
