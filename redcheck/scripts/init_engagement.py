#!/usr/bin/env python3
"""
RedCheck Engagement Initializer

Create a new engagement directory with proper structure, metadata,
and evidence encryption setup.

Usage:
    python3 init_engagement.py --id <engagement-id> --client <name> \
        --targets targets.yaml --roe /path/to/roe.pdf \
        [--evidence-dir /var/lib/redcheck/evidence]

Produces:
    <evidence-dir>/engagements/<engagement-id>/
        metadata.yaml      - Engagement metadata
        roe/                - Signed RoE copy
        evidence/           - Encrypted evidence artifacts
        logs/               - Engagement-specific logs
        reports/            - Generated reports
"""

import argparse
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required. Install with: pip install pyyaml")
    sys.exit(1)


DEFAULT_EVIDENCE_DIR = "/var/lib/redcheck/evidence"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def init_engagement(
    engagement_id: str,
    client_name: str,
    targets_file: Path,
    roe_file: Path,
    evidence_dir: Path,
    contact_name: str = "",
    contact_phone: str = "",
    contact_email: str = "",
    start_time: str = "",
    end_time: str = "",
):
    engagement_path = evidence_dir / "engagements" / engagement_id

    if engagement_path.exists():
        print(f"ERROR: Engagement directory already exists: {engagement_path}")
        sys.exit(1)

    # Validate inputs
    if not targets_file.exists():
        print(f"ERROR: Targets file not found: {targets_file}")
        sys.exit(1)

    if not roe_file.exists():
        print(f"ERROR: RoE file not found: {roe_file}")
        sys.exit(1)

    # Parse targets
    with open(targets_file) as f:
        targets = yaml.safe_load(f)

    # Create directory structure
    print(f"Creating engagement: {engagement_id}")
    dirs = ["roe", "evidence", "logs", "reports"]
    for d in dirs:
        (engagement_path / d).mkdir(parents=True, exist_ok=True)
        print(f"  Created: {engagement_path / d}")

    # Copy and hash RoE
    roe_dest = engagement_path / "roe" / roe_file.name
    shutil.copy2(roe_file, roe_dest)
    roe_hash = sha256_file(roe_dest)
    print(f"  RoE copied: {roe_dest}")
    print(f"  RoE SHA-256: {roe_hash}")

    now = datetime.now(timezone.utc).isoformat()

    # Build metadata
    metadata = {
        "engagement_id": engagement_id,
        "client_name": client_name,
        "created_utc": now,
        "authorized_targets": targets if isinstance(targets, list) else targets.get("targets", []),
        "rules_of_engagement": {
            "file": str(roe_dest),
            "sha256": roe_hash,
        },
        "contact": {
            "escalation_name": contact_name,
            "phone": contact_phone,
            "email": contact_email,
        },
        "start_time_utc": start_time or now,
        "end_time_utc": end_time or "",
        "status": "initialized",
        "safety_mode": "dry-run",
    }

    meta_path = engagement_path / "metadata.yaml"
    with open(meta_path, "w") as f:
        yaml.dump(metadata, f, default_flow_style=False, sort_keys=False)
    print(f"  Metadata written: {meta_path}")

    # Create initial audit log entry
    audit_entry = {
        "timestamp": now,
        "action": "engagement_initialized",
        "operator": os.environ.get("USER", "unknown"),
        "details": f"Engagement {engagement_id} created for {client_name}",
    }
    audit_path = evidence_dir / "audit" / f"{engagement_id}.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with open(audit_path, "a") as f:
        f.write(json.dumps(audit_entry) + "\n")
    print(f"  Audit log started: {audit_path}")

    print(f"\nEngagement {engagement_id} initialized successfully.")
    print(f"  Directory: {engagement_path}")
    print(f"  Status: initialized (dry-run mode)")
    print(f"\nNext steps:")
    print(f"  1. Review metadata.yaml and verify targets")
    print(f"  2. Confirm RoE integrity (SHA-256: {roe_hash})")
    print(f"  3. Set safety_mode in metadata.yaml to 'authorized-active' when ready")
    return engagement_path


def main():
    parser = argparse.ArgumentParser(description="Initialize a RedCheck engagement")
    parser.add_argument("--id", required=True, help="Unique engagement identifier")
    parser.add_argument("--client", required=True, help="Client / sole authorizer name")
    parser.add_argument("--targets", required=True, help="YAML file listing authorized targets")
    parser.add_argument("--roe", required=True, help="Path to signed Rules of Engagement document")
    parser.add_argument("--evidence-dir", default=DEFAULT_EVIDENCE_DIR, help="Evidence base directory")
    parser.add_argument("--contact-name", default="", help="Escalation contact name")
    parser.add_argument("--contact-phone", default="", help="Escalation contact phone")
    parser.add_argument("--contact-email", default="", help="Escalation contact email")
    parser.add_argument("--start", default="", help="Engagement start time (ISO 8601 UTC)")
    parser.add_argument("--end", default="", help="Engagement end time (ISO 8601 UTC)")

    args = parser.parse_args()

    init_engagement(
        engagement_id=args.id,
        client_name=args.client,
        targets_file=Path(args.targets),
        roe_file=Path(args.roe),
        evidence_dir=Path(args.evidence_dir),
        contact_name=args.contact_name,
        contact_phone=args.contact_phone,
        contact_email=args.contact_email,
        start_time=args.start,
        end_time=args.end,
    )


if __name__ == "__main__":
    main()
