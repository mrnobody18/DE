#!/usr/bin/env python3
"""
sysmon_attack_coverage.py (robust)
Usage: python3 sysmon_attack_coverage.py sysmon-config.xml
Parses real-world Sysmon configs (EventFiltering / RuleGroup) and maps enabled
events to ATT&CK techniques. Prints a coverage summary.
"""

import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

# Map Sysmon event *element names* to Event IDs (common set; extend as needed)
EVENT_NAME_TO_ID = {
    "ProcessCreate": "1",
    "FileCreateTime": "2",
    "NetworkConnect": "3",
    "ProcessTerminate": "5",
    "DriverLoad": "6",
    "ImageLoad": "7",
    "CreateRemoteThread": "8",
    "RawAccessRead": "9",
    "ProcessAccess": "10",
    "FileCreate": "11",
    "RegistryEvent": "12",          # parent for CreateKey/SetValue/Delete*
    "RegistryKeyCreate": "12",
    "RegistryValueSet": "13",
    "RegistryKeyRename": "13",      # varies by schema; keep both for safety
    "FileCreateStreamHash": "14",
    "PipeEvent": "17",
    "WmiEvent": "19",
    "DnsQuery": "22",
    "FileDelete": "23",
    "FileDeleteDetected": "23",     # some configs reference the older name
    "ClipboardChange": "24",
    "ProcessTampering": "25",
    # Add any others you use
}

# Representative Sysmon -> ATT&CK mapping (trim/extend for your environment)
SYS_TO_ATTACK = {
    "1":  ["T1059", "T1204"],
    "3":  ["T1071.001", "T1071.002"],
    "5":  [],
    "6":  ["T1574"],
    "7":  ["T1055"],
    "8":  ["T1055"],
    "9":  ["T1005"],
    "10": ["T1055"],
    "11": ["T1105"],
    "12": ["T1547"],
    "13": ["T1547"],
    "14": ["T1070"],
    "22": ["T1043", "T1071.004"],
    "23": ["T1070"]
}

def _local(tag: str) -> str:
    """Return the local (namespace-stripped) tag name."""
    return tag.split('}', 1)[-1] if '}' in tag else tag

def _collect_event_names(elem):
    """
    Given an <EventFiltering> element (or a subtree), collect event element names
    such as ProcessCreate, NetworkConnect, etc., whether directly present or
    nested under <RuleGroup>.
    """
    names = set()
    for child in elem.iter():
        name = _local(child.tag)
        if name in EVENT_NAME_TO_ID:
            # Consider enabled if the element exists at all; optionally check onmatch
            onmatch = child.attrib.get("onmatch", "").lower()
            # Either include or exclude means logging is active (direction differs)
            if onmatch in ("include", "exclude") or onmatch == "" or list(child):
                names.add(name)
    return names

def parse_sysmon_enabled_events(path):
    """Return sorted list of enabled Sysmon Event IDs from a Sysmon XML config."""
    tree = ET.parse(path)
    root = tree.getroot()

    enabled_names = set()

    # Find EventFiltering anywhere (config styles vary)
    event_filtering_nodes = [n for n in root.iter() if _local(n.tag) == "EventFiltering"]

    for ef in event_filtering_nodes:
        enabled_names |= _collect_event_names(ef)

    # Fallback: some configs declare RuleGroup at root level
    if not enabled_names:
        for rg in root.iter():
            if _local(rg.tag) == "RuleGroup":
                enabled_names |= _collect_event_names(rg)

    # Last resort: heuristic scan of text for known event names
    if not enabled_names:
        text = ET.tostring(root, encoding="unicode", method="text").lower()
        for k in EVENT_NAME_TO_ID:
            if k.lower() in text:
                enabled_names.add(k)

    # Map names to IDs
    enabled_ids = set()
    for name in enabled_names:
        ev_id = EVENT_NAME_TO_ID.get(name)
        if ev_id:
            enabled_ids.add(ev_id)

    return sorted(enabled_ids, key=lambda x: int(x))

def map_events_to_attack(event_ids):
    mapping = {}
    for eid in event_ids:
        mapping[eid] = SYS_TO_ATTACK.get(eid, [])
    return mapping

def report(path):
    ev_ids = parse_sysmon_enabled_events(path)
    mapping = map_events_to_attack(ev_ids)
    total = len(ev_ids)
    covered = sum(1 for v in mapping.values() if v)
    pct = (covered / total * 100) if total else 0.0

    print("="*64)
    print(f"Sysmon config: {path}")
    print(f"Enabled Sysmon Event IDs: {', '.join(ev_ids) if ev_ids else '(none found)'}")
    print("-"*64)
    print("EventID -> ATT&CK techniques")
    if not ev_ids:
        print("  No event IDs detected. Try: verify <EventFiltering> exists, or share a sample.")
    for ev in ev_ids:
        tlist = mapping.get(ev, [])
        print(f"  {ev:>2} -> {', '.join(tlist) if tlist else '(no mapping yet)'}")
    print("-"*64)
    print(f"Mapped events: {covered}/{total}  (~{pct:.1f}% of enabled events have ATT&CK tags)")
    print("="*64)
        # Identify potential coverage gaps (events not enabled but available in mapping) ---
    mapped_event_ids = set(SYS_TO_ATTACK.keys())
    not_enabled = sorted(mapped_event_ids - set(ev_ids), key=int)
    if not_enabled:
        print(f"Not enabled but available in MITRE mapping: {', '.join(not_enabled)}")
    else:
        print("All mapped Sysmon event types are enabled in your config!")

    print("="*64)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 sysmon_attack_coverage.py sysmon-config.xml")
        sys.exit(1)
    report(sys.argv[1])
