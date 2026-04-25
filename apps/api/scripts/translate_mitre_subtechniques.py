from __future__ import annotations

import json
from pathlib import Path

from deep_translator import GoogleTranslator


ROOT_DIR = Path(__file__).resolve().parents[3]
SOURCE_JS = ROOT_DIR / "apps" / "web" / "src" / "data" / "mitre-enterprise-data.js"


def load_catalog() -> dict:
    raw = SOURCE_JS.read_text(encoding="utf-8").strip()
    payload = raw.removeprefix("export default ").rstrip(";")
    return json.loads(payload)


def save_catalog(catalog: dict) -> None:
    SOURCE_JS.write_text(
        "export default " + json.dumps(catalog, ensure_ascii=False, separators=(",", ":")) + ";\n",
        encoding="utf-8",
    )


def chunk_text(text: str, limit: int = 4200) -> list[str]:
    normalized = text.strip()
    if len(normalized) <= limit:
        return [normalized]

    chunks: list[str] = []
    current = []
    current_length = 0
    for paragraph in normalized.split("\n\n"):
        paragraph_length = len(paragraph) + 2
        if current and current_length + paragraph_length > limit:
            chunks.append("\n\n".join(current))
            current = [paragraph]
            current_length = len(paragraph)
        else:
            current.append(paragraph)
            current_length += paragraph_length
    if current:
        chunks.append("\n\n".join(current))
    return chunks


def translate_text(translator: GoogleTranslator, text: str) -> str:
    return "\n\n".join(translator.translate(chunk) for chunk in chunk_text(text))


def main() -> None:
    catalog = load_catalog()
    translator = GoogleTranslator(source="en", target="pt")

    subtechniques = [
        sub
        for tactic in catalog["tactics"]
        for technique in tactic["techniques"]
        for sub in technique.get("subtechniques", [])
    ]

    total = len(subtechniques)
    translated = 0

    for index, sub in enumerate(subtechniques, start=1):
        changed = False
        if not sub.get("namePt"):
            sub["namePt"] = translator.translate(sub["name"])
            changed = True
        if not sub.get("descriptionPt"):
            sub["descriptionPt"] = translate_text(translator, sub["description"])
            changed = True
        if changed:
            translated += 1
            if translated % 25 == 0:
                save_catalog(catalog)
        print(f"[{index}/{total}] {sub['externalId']} {'translated' if changed else 'cached'}")

    save_catalog(catalog)
    print(f"Completed. Updated {translated} sub-techniques.")


if __name__ == "__main__":
    main()
