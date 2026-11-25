"""Open-source dependency license compliance audit and CycloneDX 1.5 SBOM exporter."""

from __future__ import annotations

import importlib.metadata as meta
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

FORBIDDEN = ("GPL", "AGPL", "SSPL", "BUSL", "PROPRIETARY")


def _extract_license(dist: meta.Distribution) -> str:
    val = dist.metadata.get("License-Expression") or dist.metadata.get("License") or ""
    if val and val.strip().upper() != "UNKNOWN":
        return val.strip().splitlines()[0][:120]
    for classifier in dist.metadata.get_all("Classifier") or []:
        if classifier.startswith("License ::"):
            return classifier.split("::")[-1].strip()
    return "UNKNOWN"


def main() -> None:
    packages: list[dict[str, str]] = []
    flagged: list[dict[str, str]] = []
    for dist in sorted(meta.distributions(), key=lambda x: (x.metadata["Name"] or "").lower()):
        name = dist.metadata["Name"] or "unknown"
        version = dist.version
        lic = _extract_license(dist)
        upper = lic.upper()
        if any(marker in upper for marker in FORBIDDEN) and "LGPL" not in upper:
            flagged.append({"package": name, "version": version, "license": lic})
        packages.append({"package": name, "version": version, "license": lic})

    sec_dir = Path(__file__).resolve().parent.parent / "results" / "security"
    sec_dir.mkdir(parents=True, exist_ok=True)
    (sec_dir / "license_audit.json").write_text(
        json.dumps(
            {
                "total_audited": len(packages),
                "flagged": flagged,
                "status": "PASS" if not flagged else "FAIL",
                "packages": packages,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "component": {
                "type": "application",
                "name": "self-healing-agentic-data-platform",
                "version": "1.0.0",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
        },
        "components": [
            {
                "type": "library",
                "name": p["package"],
                "version": p["version"],
                "purl": f"pkg:pypi/{p['package'].lower()}@{p['version']}",
            }
            for p in packages
        ],
    }
    (sec_dir / "sbom.cdx.json").write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    print(json.dumps({"total_audited": len(packages), "flagged": len(flagged), "status": "PASS" if not flagged else "FAIL"}))
    if flagged:
        sys.exit(1)


if __name__ == "__main__":
    main()
