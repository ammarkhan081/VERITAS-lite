"""Health check route."""

from fastapi import APIRouter, Depends

from backend.api.dependencies import get_campaign_store
from backend.memory.campaign_store import CampaignStore

router = APIRouter()


@router.get("/health")
async def health_check(
    store: CampaignStore = Depends(get_campaign_store),
) -> dict:
    """Report API and database availability, including on an empty database."""
    try:
        try:
            store.get_campaign("nonexistent")
        except KeyError:
            pass
    except Exception as exc:
        return {"status": "unhealthy", "error": str(exc)}
    return {"status": "healthy", "version": "0.1.0"}
