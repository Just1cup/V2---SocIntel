from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any


ROOT_DIR = Path(__file__).resolve().parents[3]
SOURCE_JS = ROOT_DIR / "apps" / "web" / "src" / "data" / "mitre-enterprise-data.js"
OUTPUT_DIR = ROOT_DIR / "apps" / "api" / "app" / "static" / "mitre"
DETAILS_DIR = OUTPUT_DIR / "techniques"


def load_catalog() -> dict[str, Any]:
    raw = SOURCE_JS.read_text(encoding="utf-8").strip()
    payload = raw.removeprefix("export default ").rstrip(";")
    return json.loads(payload)


def write_gzip_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))


def build_index(catalog: dict[str, Any]) -> dict[str, Any]:
    tactics = []
    for tactic in catalog["tactics"]:
        techniques = []
        for technique in tactic["techniques"]:
            techniques.append(
                {
                    "id": technique["id"],
                    "externalId": technique["externalId"],
                    "name": technique["name"],
                    "namePt": technique.get("namePt"),
                    "platforms": technique.get("platforms", []),
                    "subtechniqueCount": len(technique.get("subtechniques", [])),
                    "subtechniques": [
                        {
                            "id": sub["id"],
                            "externalId": sub["externalId"],
                            "name": sub["name"],
                            "namePt": sub.get("namePt"),
                            "platforms": sub.get("platforms", []),
                        }
                        for sub in technique.get("subtechniques", [])
                    ],
                }
            )

        tactics.append(
            {
                "id": tactic["id"],
                "externalId": tactic["externalId"],
                "name": tactic["name"],
                "shortname": tactic.get("shortname"),
                "description": tactic.get("description"),
                "descriptionPt": tactic.get("descriptionPt"),
                "techniqueCount": len(techniques),
                "subtechniqueCount": sum(item["subtechniqueCount"] for item in techniques),
                "techniques": techniques,
            }
        )

    return {
        "source": catalog["source"],
        "domain": catalog["domain"],
        "version": catalog["version"],
        "tacticCount": catalog["tacticCount"],
        "techniqueCount": catalog["techniqueCount"],
        "subtechniqueCount": catalog["subtechniqueCount"],
        "tactics": tactics,
    }


def build_details(catalog: dict[str, Any]) -> None:
    for tactic in catalog["tactics"]:
        for technique in tactic["techniques"]:
            detail_payload = {
                "tactic": {
                    "id": tactic["id"],
                    "externalId": tactic["externalId"],
                    "name": tactic["name"],
                    "description": tactic.get("description"),
                    "descriptionPt": tactic.get("descriptionPt"),
                },
                "technique": {
                    "id": technique["id"],
                    "externalId": technique["externalId"],
                    "name": technique["name"],
                    "namePt": technique.get("namePt"),
                    "description": technique.get("description"),
                    "descriptionPt": technique.get("descriptionPt"),
                    "platforms": technique.get("platforms", []),
                },
                "subtechniques": [
                    {
                        "id": sub["id"],
                        "externalId": sub["externalId"],
                        "name": sub["name"],
                        "namePt": sub.get("namePt"),
                        "description": sub.get("description"),
                        "descriptionPt": sub.get("descriptionPt"),
                        "platforms": sub.get("platforms", []),
                    }
                    for sub in technique.get("subtechniques", [])
                ],
            }
            write_gzip_json(DETAILS_DIR / f"{technique['externalId']}.json.gz", detail_payload)


def main() -> None:
    catalog = load_catalog()
    index_payload = build_index(catalog)
    write_gzip_json(OUTPUT_DIR / "index.json.gz", index_payload)
    build_details(catalog)
    print(f"MITRE static catalog generated in {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
