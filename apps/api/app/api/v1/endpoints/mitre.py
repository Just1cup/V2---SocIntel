from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter()

MITRE_STATIC_DIR = Path(__file__).resolve().parents[3] / "static" / "mitre"
MITRE_INDEX_PATH = MITRE_STATIC_DIR / "index.json.gz"
MITRE_TECHNIQUE_DIR = MITRE_STATIC_DIR / "techniques"

RESPONSE_HEADERS = {
    "Content-Encoding": "gzip",
    "Cache-Control": "public, max-age=3600",
    "Vary": "Accept-Encoding",
}


@router.get("/index")
def get_mitre_index(_: User = Depends(get_current_user)) -> FileResponse:
    if not MITRE_INDEX_PATH.exists():
        raise HTTPException(status_code=503, detail="MITRE catalog is not available.")
    return FileResponse(
        MITRE_INDEX_PATH,
        media_type="application/json",
        filename="mitre-index.json",
        headers=RESPONSE_HEADERS,
    )


@router.get("/techniques/{technique_external_id}")
def get_mitre_technique_detail(
    technique_external_id: str,
    _: User = Depends(get_current_user),
) -> FileResponse:
    safe_name = "".join(char for char in technique_external_id if char.isalnum() or char in {".", "-", "_"})
    detail_path = MITRE_TECHNIQUE_DIR / f"{safe_name}.json.gz"
    if not detail_path.exists():
        raise HTTPException(status_code=404, detail="MITRE technique not found.")
    return FileResponse(
        detail_path,
        media_type="application/json",
        filename=f"{safe_name}.json",
        headers=RESPONSE_HEADERS,
    )
