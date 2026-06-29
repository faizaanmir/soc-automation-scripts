#!/usr/bin/env python3
"""
utils/watchlist_manager.py
===========================
Manage Microsoft Sentinel watchlists via the Azure REST API.
Add, remove, and query IOCs in Sentinel watchlists without
opening the Azure portal.

Usage:
    python watchlist_manager.py --list                          # List all watchlists
    python watchlist_manager.py --query MyWatchlist             # Show items in watchlist
    python watchlist_manager.py --add MyWatchlist --ioc 1.2.3.4 --type ip --note "C2 IP"
    python watchlist_manager.py --remove MyWatchlist --ioc 1.2.3.4
    python watchlist_manager.py --bulk-add MyWatchlist --file iocs.csv

Requires config.ini with [azure] section populated.
"""

import argparse
import configparser
import csv
import json
import sys
import requests
from pathlib import Path
from datetime import datetime, timezone


CONFIG_PATH = Path(__file__).parent.parent / "config.ini"
MGMT_BASE   = "https://management.azure.com"
API_VERSION = "2021-10-01"


# ── Auth ──────────────────────────────────────────────────────────────────────

def get_access_token(config: configparser.ConfigParser) -> str:
    """Get Azure AD access token via client credentials flow."""
    tenant_id     = config.get("azure", "tenant_id")
    client_id     = config.get("azure", "client_id")
    client_secret = config.get("azure", "client_secret")

    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    payload = {
        "grant_type":    "client_credentials",
        "client_id":     client_id,
        "client_secret": client_secret,
        "scope":         "https://management.azure.com/.default",
    }

    resp = requests.post(url, data=payload, timeout=15)
    resp.raise_for_status()
    return resp.json()["access_token"]


def get_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }


def get_workspace_path(config: configparser.ConfigParser) -> str:
    sub  = config.get("azure", "subscription_id")
    rg   = config.get("azure", "resource_group")
    ws   = config.get("azure", "workspace_name")
    return (
        f"{MGMT_BASE}/subscriptions/{sub}/resourceGroups/{rg}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
        f"/providers/Microsoft.SecurityInsights"
    )


# ── Watchlist Operations ───────────────────────────────────────────────────────

def list_watchlists(base_url: str, headers: dict):
    """List all watchlists in the workspace."""
    url  = f"{base_url}/watchlists?api-version={API_VERSION}"
    resp = requests.get(url, headers=headers, timeout=15)
    resp.raise_for_status()
    wls  = resp.json().get("value", [])

    if not wls:
        print("No watchlists found.")
        return

    print(f"\n{'Watchlist Name':<30} {'Items':<8} {'Description'}")
    print("-" * 70)
    for wl in wls:
        props = wl.get("properties", {})
        print(
            f"{props.get('watchlistAlias','?'):<30} "
            f"{props.get('numberOfItems','?'):<8} "
            f"{props.get('description','')}"
        )


def query_watchlist(base_url: str, headers: dict, watchlist_name: str):
    """Print all items in a watchlist."""
    url  = f"{base_url}/watchlists/{watchlist_name}/watchlistItems?api-version={API_VERSION}"
    resp = requests.get(url, headers=headers, timeout=15)
    resp.raise_for_status()
    items = resp.json().get("value", [])

    if not items:
        print(f"Watchlist '{watchlist_name}' is empty.")
        return

    print(f"\nItems in '{watchlist_name}' ({len(items)} total):\n")
    for item in items:
        props = item.get("properties", {}).get("itemsKeyValue", {})
        print(f"  {json.dumps(props)}")


def add_ioc(base_url: str, headers: dict, watchlist_name: str, ioc: str, ioc_type: str, note: str):
    """Add a single IOC to a watchlist."""
    import uuid
    item_id = str(uuid.uuid4())
    url     = f"{base_url}/watchlists/{watchlist_name}/watchlistItems/{item_id}?api-version={API_VERSION}"

    payload = {
        "properties": {
            "itemsKeyValue": {
                "IOC":       ioc,
                "Type":      ioc_type,
                "Note":      note,
                "AddedBy":   "watchlist_manager.py",
                "AddedAt":   datetime.now(timezone.utc).isoformat(),
            }
        }
    }

    resp = requests.put(url, headers=headers, json=payload, timeout=15)
    resp.raise_for_status()
    print(f"[+] Added {ioc_type.upper()} '{ioc}' to '{watchlist_name}'")


def bulk_add_from_csv(base_url: str, headers: dict, watchlist_name: str, filepath: str):
    """Bulk add IOCs from a CSV file (columns: ioc, type, note)."""
    path = Path(filepath)
    if not path.exists():
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    added = 0
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ioc      = row.get("ioc", "").strip()
            ioc_type = row.get("type", "unknown").strip()
            note     = row.get("note", "").strip()
            if ioc:
                add_ioc(base_url, headers, watchlist_name, ioc, ioc_type, note)
                added += 1

    print(f"\n[+] Added {added} IOCs to '{watchlist_name}'")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Manage Microsoft Sentinel Watchlists")
    parser.add_argument("--list",      action="store_true",  help="List all watchlists")
    parser.add_argument("--query",     type=str, metavar="WATCHLIST", help="Show items in watchlist")
    parser.add_argument("--add",       type=str, metavar="WATCHLIST", help="Add IOC to watchlist")
    parser.add_argument("--remove",    type=str, metavar="WATCHLIST", help="Remove IOC from watchlist (by value)")
    parser.add_argument("--bulk-add",  type=str, metavar="WATCHLIST", help="Bulk add from CSV file")
    parser.add_argument("--ioc",       type=str, help="IOC value")
    parser.add_argument("--type",      type=str, default="unknown", help="IOC type [ip/domain/hash/url]")
    parser.add_argument("--note",      type=str, default="", help="Note/context for the IOC")
    parser.add_argument("--file",      type=str, help="CSV file for bulk operations")
    args = parser.parse_args()

    if not CONFIG_PATH.exists():
        print(f"[ERROR] config.ini not found at {CONFIG_PATH}")
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(CONFIG_PATH)

    print("[*] Authenticating to Azure...")
    token    = get_access_token(config)
    headers  = get_headers(token)
    base_url = get_workspace_path(config)

    if args.list:
        list_watchlists(base_url, headers)
    elif args.query:
        query_watchlist(base_url, headers, args.query)
    elif args.add:
        if not args.ioc:
            print("[ERROR] --ioc required with --add")
            sys.exit(1)
        add_ioc(base_url, headers, args.add, args.ioc, args.type, args.note)
    elif args.bulk_add:
        if not args.file:
            print("[ERROR] --file required with --bulk-add")
            sys.exit(1)
        bulk_add_from_csv(base_url, headers, args.bulk_add, args.file)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
