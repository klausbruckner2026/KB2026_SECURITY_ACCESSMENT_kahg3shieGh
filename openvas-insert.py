#!/usr/bin/env python3
"""
Import OpenVAS / Greenbone XML report results into MongoDB.

Stores:
- vulnerabilities collection: one doc per unique (oid + port/proto combo, but deduped by oid here)
- hosts collection: one doc per IP with list of found OIDs/ports

Usage:
    python3 openvas-insert.py report.xml
    # or with custom MongoDB URI:
    MONGO_URI=mongodb://user:pass@host:27017 python3 openvas-insert.py report.xml
"""

import argparse
import datetime
import os
import sys
from collections import defaultdict
from contextlib import contextmanager
from typing import Dict, List, Optional
from xml.etree import ElementTree as ET

from pymongo import MongoClient, UpdateOne
from pymongo.errors import ConnectionFailure


@contextmanager
def get_mongo_client():
    uri = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
    client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    try:
        client.admin.command("ping")  # test connection
        yield client
    except ConnectionFailure as e:
        print(f"Error: Cannot connect to MongoDB: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        client.close()


def parse_tags(tags_str: Optional[str]) -> Dict[str, str]:
    """Parse NVT <tags> string like 'cvss_base_vector=...|summary=...|...' """
    if not tags_str:
        return {}
    result = {}
    for part in tags_str.split("|"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def extract_result_data(result_elem: ET.Element) -> Optional[Dict]:
    """Extract vulnerability data from a <result> element."""
    host_elem = result_elem.find("host")
    if host_elem is None or not host_elem.text:
        return None
    ip = host_elem.text.strip()

    port_elem = result_elem.find("port")
    if port_elem is None or not port_elem.text:
        return None
    port_text = port_elem.text.strip()
    if "/" not in port_text:
        return None
    port, proto = port_text.split("/", 1)

    nvt = result_elem.find("nvt")
    if nvt is None:
        return None

    oid = nvt.get("oid")
    if not oid:
        return None

    name_elem = nvt.find("name")
    name = name_elem.text.strip() if name_elem is not None and name_elem.text else "Unknown"

    family_elem = nvt.find("family")
    family = family_elem.text.strip() if family_elem is not None and family_elem.text else ""

    cvss_elem = nvt.find("cvss_base")
    try:
        cvss = float(cvss_elem.text) if cvss_elem is not None and cvss_elem.text else 0.0
    except (ValueError, TypeError):
        cvss = 0.0

    if cvss == 0.0:
        return None  # skip as per original

    # References (can be "NOCVE", "NOBID", "NOXREF" or comma-separated)
    def safe_split(elem_name: str) -> List[str]:
        e = nvt.find(elem_name)
        txt = e.text.strip() if e is not None and e.text else ""
        if txt in ("NOCVE", "NOBID", "NOXREF", ""):
            return []
        return [x.strip() for x in txt.split(",") if x.strip()]

    cves = safe_split("cve")
    bids = safe_split("bid")
    xrefs = safe_split("xref")

    # Tags
    tags_elem = nvt.find("tags")
    tags_dict = parse_tags(tags_elem.text if tags_elem is not None and tags_elem.text else None)

    threat_elem = result_elem.find("threat")
    threat = threat_elem.text.strip() if threat_elem is not None and threat_elem.text else "Unknown"

    return {
        "ip": ip,
        "port": port,
        "proto": proto,
        "oid": oid,
        "name": name,
        "family": family,
        "cvss": cvss,
        "cves": cves,
        "bids": bids,
        "xrefs": xrefs,
        **tags_dict,  # cvss_base_vector, summary, insight, solution, etc.
        "threat": threat,
        "inserted": datetime.datetime.now(datetime.UTC),
        "updated": datetime.datetime.now(datetime.UTC),
    }


def main():
    parser = argparse.ArgumentParser(description="Import OpenVAS XML report to MongoDB")
    parser.add_argument("infile", help="Path to OpenVAS XML report file")
    args = parser.parse_args()

    if not os.path.isfile(args.infile):
        print(f"Error: File not found: {args.infile}", file=sys.stderr)
        sys.exit(1)

    # Collect data first → then bulk write
    vuln_ops = []               # list of UpdateOne for vulnerabilities
    host_oids: Dict[str, List[Dict]] = defaultdict(list)   # ip → list of {'port':,'proto':,'oid':}

    print(f"Parsing {args.infile} ...")

    try:
        with open(args.infile, "rb") as f:   # binary for safety
            context = ET.iterparse(f, events=("end",))
            _, root = next(context)  # get root

            for event, elem in context:
                if elem.tag != "result":
                    elem.clear()
                    continue

                data = extract_result_data(elem)
                if not data:
                    elem.clear()
                    continue

                ip = data["ip"]
                oid = data["oid"]

                # Deduplicate vulnerabilities by oid (original logic)
                vuln_ops.append(
                    UpdateOne(
                        {"oid": oid},
                        {"$setOnInsert": data, "$set": {"updated": datetime.datetime.now(datetime.UTC)}},
                        upsert=True,
                    )
                )

                # Collect per-host OIDs/ports
                host_oids[ip].append({"proto": data["proto"], "port": data["port"], "oid": oid})

                elem.clear()  # free memory

        print(f"Found {len(host_oids)} hosts and {len(vuln_ops)} unique vulnerabilities.")

        with get_mongo_client() as client:
            db = client["vulnmgt"]

            if vuln_ops:
                db.vulnerabilities.bulk_write(vuln_ops)
                print(f"Inserted/updated {len(vuln_ops)} vulnerability documents.")

            host_ops = []
            now = datetime.datetime.now(datetime.UTC)
            for ip, oids_list in host_oids.items():
                host_ops.append(
                    UpdateOne(
                        {"ip": ip},
                        {
                            "$set": {
                                "oids": oids_list,
                                "updated": now,
                            },
                            "$setOnInsert": {
                                "ip": ip,
                                "mac": {"addr": "", "vendor": "Unknown"},
                                "ports": [],
                                "hostnames": [],
                                "os": [],
                                "inserted": now,
                            },
                        },
                        upsert=True,
                    )
                )

            if host_ops:
                db.hosts.bulk_write(host_ops)
                print(f"Inserted/updated {len(host_ops)} host documents.")

    except ET.ParseError as e:
        print(f"XML parsing error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)

    print("Import complete.")


if __name__ == "__main__":
    main()