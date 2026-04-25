from fastapi import APIRouter

from app.api.v1.endpoints import analysis, auth, mitre, threat_feeds, users

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(analysis.router, prefix="/analysis-jobs", tags=["analysis"])
api_router.include_router(mitre.router, prefix="/mitre", tags=["mitre"])
api_router.include_router(threat_feeds.router, prefix="/threat-feeds", tags=["threat-feeds"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
