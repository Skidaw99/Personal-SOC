"""SOC API route modules."""
from soc.api.routes.ws import router as ws_router
from soc.api.routes.ai import router as ai_router

__all__ = ["ws_router", "ai_router"]
