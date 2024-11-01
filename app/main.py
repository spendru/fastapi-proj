from fastapi import FastAPI
from .config.settings import settings
from .api.v1.router import api_router
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title=settings.APP_NAME)

@app.on_event("startup")
async def startup_event():
    # Load secrets at startup
    settings.load_secrets()
    logger.info("Application started, secrets loaded")

# Include API router
app.include_router(api_router, prefix=settings.API_V1_STR)