#!/usr/bin/env python3
"""
reporting/shift_handover_generator.py
======================================
Generates a structured SOC shift handover report in Markdown.
Covers open incidents, pending actions, completed work, and watch items.

Usage:
    python shift_handover_generator.py --input handover.json
    python shift_handover_generator.py --interactive
    python shift_handover_generator.py --input handover.json --output handover_report.md
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


HANDOVER_TEMPLATE = """\
# SOC Shift Handover Report

| Field | Value |
|---|---|
| **Shift Date** | {shift_date} |
| **Shift** | {shift} |
| **Outgoing Analyst** | {outgoing_analyst} |
| **Incoming Analyst** | {incoming_analyst} |
| **Customer / Tenant** | {customer} |
| **Report Generated** | {generated_at} UTC |

---

## Shift Summary

{shift_summary}

---

## Open Incidents (Requires Action)

| Incident ID | Severity | Title | Status | Next Action |
|---|---|---|---|---|
{open_incidents_rows}

---

## Completed During Shift

| Incident ID | Title | Verdict | Closed At |
|---|---|---|---|
{completed_rows}

---

## Pending Actions

{pending_actions}

---

## Watch Items

Items to monitor closely during the next shift:

{watch_items}

---

## Threat Intelligence Notes

{ti_notes}

---

## Escalations

{escalations}

---

## Notes for Incoming Analyst

{notes}

---

*Report generated: {generated_at} UTC*
"""


def fmt_table(items, cols):
    if not items:
        return "| " + " | ".join(["—"] * len(cols)) + " |"
    return "\n".join(
        "| " + " | ".join(str(row.get(c, "—")) for c in cols) + " |"
        for row in items
    )


def fmt_list(items):
    if not items:
        return "_None._"
    return "\n".join(f"- {i}" for i in items)


def build_handover(data):
    return HANDOVER_TEMPLATE.format(
        shift_date=data.get("shift_date", datetime.now(timezone.utc).strftime("%Y-%m-%d")),
        shift=data.get("shift", "Unknown"),
        outgoing_analyst=data.get("outgoing_analyst", "Unknown"),
        incoming_analyst=data.get("incoming_analyst", "Unknown"),
        customer=data.get("customer", "Unknown"),
        shift_summary=data.get("shift_summary", "_No summary provided._"),
        open_incidents_rows=fmt_table(
            data.get("open_incidents", []),
            ["incident_id", "severity", "title", "status", "next_action"]
        ),
        completed_rows=fmt_table(
            data.get("completed", []),
            ["incident_id", "title", "verdict", "closed_at"]
        ),
        pending_actions=fmt_list(data.get("pending_actions", [])),
        watch_items=fmt_list(data.get("watch_items", [])),
        ti_notes=data.get("ti_notes", "_No TI notes._"),
        escalations=fmt_list(data.get("escalations", [])),
        notes=data.get("notes", "_No additional notes._"),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    )


def interactive_mode():
    print("\n=== Shift Handover Generator (Interactive Mode) ===\n")
    data = {}
    data["shift_date"]        = input("Shift date (YYYY-MM-DD): ").strip()
    data["shift"]             = input("Shift [Morning/Afternoon/Night]: ").strip()
    data["outgoing_analyst"]  = input("Outgoing analyst name: ").strip()
    data["incoming_analyst"]  = input("Incoming analyst name: ").strip()
    data["customer"]          = input("Customer / Tenant: ").strip()
    data["shift_summary"]     = input("Shift summary: ").strip()
    data["ti_notes"]          = input("Threat intelligence notes: ").strip()
    data["notes"]             = input("Notes for incoming analyst: ").strip()

    print("\nOpen incidents (blank Incident ID to stop):")
    data["open_incidents"] = []
    while True:
        inc_id = input("  Incident ID: ").strip()
        if not inc_id:
            break
        data["open_incidents"].append({
            "incident_id": inc_id,
            "severity":    input("  Severity: ").strip(),
            "title":       input("  Title: ").strip(),
            "status":      input("  Status: ").strip(),
            "next_action": input("  Next action: ").strip(),
        })

    print("\nPending actions (blank to stop):")
    data["pending_actions"] = []
    while True:
        action = input("  Action: ").strip()
        if not action:
            break
        data["pending_actions"].append(action)

    print("\nWatch items (blank to stop):")
    data["watch_items"] = []
    while True:
        item = input("  Watch item: ").strip()
        if not item:
            break
        data["watch_items"].append(item)

    return data


def main():
    parser = argparse.ArgumentParser(description="Generate SOC shift handover reports")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--input", type=str, help="Path to handover JSON file")
    mode.add_argument("--interactive", action="store_true")
    parser.add_argument("--output", type=str, default=None)
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

    report = build_handover(data)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"[+] Handover report saved to: {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
