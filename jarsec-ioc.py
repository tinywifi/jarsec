#!/usr/bin/env python3
"""
Jarsec IOC Export — generates STIX 2.1 and MISP JSON from analysis findings.

Usage:
    python3 jarsec-ioc.py /path/to/analysis_workspace /path/to/target.jar

Reads findings from the workspace and outputs:
    - stix_bundle.json
    - misp_event.json
"""

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_extracted_strings(path: Path) -> list:
    """Parse extracted_strings.txt for URLs, IPs, tokens."""
    iocs = {"urls": set(), "ips": set(), "domains": set(), "eth": set()}
    if not path.exists():
        return iocs

    text = path.read_text(errors="replace")

    # URLs
    for m in re.finditer(r'https?://[^\s"<>|\\^`\[\]]+', text):
        url = m.group(0)
        iocs["urls"].add(url)
        # Extract domain
        domain = re.sub(r'^https?://', '', url).split('/')[0].split(':')[0]
        if domain and '.' in domain:
            iocs["domains"].add(domain)

    # IPs
    for m in re.finditer(r'\b(\d{1,3}\.){3}\d{1,3}\b', text):
        iocs["ips"].add(m.group(0))

    # Ethereum addresses
    for m in re.finditer(r'0x[a-fA-F0-9]{40}', text):
        iocs["eth"].add(m.group(0))

    return {k: list(v) for k, v in iocs.items()}


def parse_pcap_hosts(path: Path) -> set:
    """Parse tshark output for hosts."""
    hosts = set()
    if not path.exists():
        return hosts
    text = path.read_text(errors="replace")
    for line in text.splitlines():
        for host in line.strip().split(","):
            host = host.strip()
            if host and '.' in host and not host.startswith("("):
                hosts.add(host)
    return hosts


def build_stix(target_jar: Path, workspace: Path, iocs: dict, pcap_hosts: set) -> dict:
    target_sha = sha256_file(target_jar)
    now = datetime.now(timezone.utc).isoformat()
    bundle_id = f"bundle--{uuid4()}"

    objects = [
        {
            "type": "malware",
            "id": f"malware--{uuid4()}",
            "created": now,
            "modified": now,
            "name": target_jar.name,
            "description": f"Minecraft mod analyzed by Jarsec",
            "malware_types": ["remote-access-trojan"],
            "is_family": False,
            "hashes": {"SHA-256": target_sha},
        }
    ]

    # File object
    objects.append({
        "type": "file",
        "id": f"file--{uuid4()}",
        "hashes": {"SHA-256": target_sha},
        "size": target_jar.stat().st_size,
        "name": target_jar.name,
    })

    # Network IOCs
    for url in iocs.get("urls", [])[:50]:
        objects.append({
            "type": "url",
            "id": f"url--{uuid4()}",
            "value": url,
        })

    for domain in iocs.get("domains", [])[:50]:
        objects.append({
            "type": "domain-name",
            "id": f"domain-name--{uuid4()}",
            "value": domain,
        })

    for ip in iocs.get("ips", [])[:20]:
        objects.append({
            "type": "ipv4-addr",
            "id": f"ipv4-addr--{uuid4()}",
            "value": ip,
        })

    for pcap_host in list(pcap_hosts)[:30]:
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', pcap_host):
            objects.append({
                "type": "ipv4-addr",
                "id": f"ipv4-addr--{uuid4()}",
                "value": pcap_host,
            })
        else:
            objects.append({
                "type": "domain-name",
                "id": f"domain-name--{uuid4()}",
                "value": pcap_host,
            })

    for eth in iocs.get("eth", [])[:10]:
        objects.append({
            "type": "cryptocurrency-wallet",
            "id": f"cryptocurrency-wallet--{uuid4()}",
            "currency": "ETH",
            "address": eth,
        })

    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects,
    }


def build_misp(target_jar: Path, workspace: Path, iocs: dict, pcap_hosts: set) -> dict:
    target_sha = sha256_file(target_jar)
    event_uuid = str(uuid4())
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    attributes = []

    # File hash
    attributes.append({
        "uuid": str(uuid4()),
        "type": "sha256",
        "category": "Payload delivery",
        "to_ids": True,
        "value": target_sha,
        "comment": f"Jarsec analysis: {target_jar.name}",
    })

    # Network IOCs
    for url in iocs.get("urls", [])[:50]:
        attributes.append({
            "uuid": str(uuid4()),
            "type": "url",
            "category": "Network activity",
            "to_ids": True,
            "value": url,
        })

    for domain in iocs.get("domains", [])[:50]:
        attributes.append({
            "uuid": str(uuid4()),
            "type": "domain",
            "category": "Network activity",
            "to_ids": True,
            "value": domain,
        })

    for ip in list(iocs.get("ips", [])) + list(pcap_hosts)[:30]:
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
            attributes.append({
                "uuid": str(uuid4()),
                "type": "ip-dst",
                "category": "Network activity",
                "to_ids": True,
                "value": ip,
            })

    for eth in iocs.get("eth", [])[:10]:
        attributes.append({
            "uuid": str(uuid4()),
            "type": "btc",
            "category": "Financial fraud",
            "to_ids": False,
            "value": eth,
            "comment": "Ethereum wallet",
        })

    return {
        "Event": {
            "uuid": event_uuid,
            "info": f"Jarsec: {target_jar.name}",
            "threat_level_id": "1",
            "analysis": "2",
            "date": now.split()[0],
            "timestamp": int(datetime.now(timezone.utc).timestamp()),
            "Attribute": attributes,
            "Tag": [{"name": "jarsec"}, {"name": "minecraft"}, {"name": "malware"}],
        }
    }


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} /path/to/workspace /path/to/target.jar")
        sys.exit(1)

    workspace = Path(sys.argv[1])
    target_jar = Path(sys.argv[2])

    extracted_strings = workspace / "extracted_strings.txt"
    pcap_hosts = workspace / "pcap_hosts.txt"

    iocs = parse_extracted_strings(extracted_strings)
    hosts = parse_pcap_hosts(pcap_hosts)

    # Write STIX
    stix = build_stix(target_jar, workspace, iocs, hosts)
    stix_path = workspace / "stix_bundle.json"
    with open(stix_path, "w") as f:
        json.dump(stix, f, indent=2)
    print(f"STIX bundle: {stix_path} ({len(stix['objects'])} objects)")

    # Write MISP
    misp = build_misp(target_jar, workspace, iocs, hosts)
    misp_path = workspace / "misp_event.json"
    with open(misp_path, "w") as f:
        json.dump(misp, f, indent=2)
    print(f"MISP event: {misp_path} ({len(misp['Event']['Attribute'])} attributes)")

    # Summary
    print(f"\nIOC Summary:")
    print(f"  URLs: {len(iocs['urls'])}")
    print(f"  Domains: {len(iocs['domains'])}")
    print(f"  IPs: {len(iocs['ips'])}")
    print(f"  PCAP hosts: {len(hosts)}")
    print(f"  ETH wallets: {len(iocs['eth'])}")


if __name__ == "__main__":
    main()
