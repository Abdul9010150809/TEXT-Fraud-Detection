from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from backend.routers.ingest import router as ingest_router
from backend.routers.analyze import router as analyze_router
from backend.routers.datasets import router as datasets_router
from backend.routers.link_analyzer import router as link_router
from backend.routers.email_analyzer import router as email_router
from backend.routers.image_analyzer import router as image_router
from contextlib import asynccontextmanager
import logging
from backend.ai_modules.database.mongodb import mongodb_conn
from backend.ai_modules.database.redis import redis_conn
# Note: simple in-app rate limiting implemented in router for demo

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load .env keys into environment
    from dotenv import load_dotenv
    load_dotenv(dotenv_path="backend/.env", override=False)

    # Startup
    logger.info("Starting up the application...")
    try:
        logger.info("Database connections skipped for text pivot testing")
    except Exception as e:
        logger.error(f"Failed to establish database connections: {e}")
        raise

    # Start Telegram bot if configured
    try:
        from backend.integrations.telegram_bot import start_bot
        await start_bot()
    except Exception as e:
        logger.warning(f"Telegram bot could not start: {e}")

    yield

    # Shutdown
    logger.info("Shutting down the application...")
    logger.info("Application closed")

app = FastAPI(
    title="AI Fraud Detection API",
    description="Backend API for AI-powered fraud detection system",
    version="1.0.0",
    lifespan=lifespan
)

# Basic security / CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(ingest_router)
app.include_router(analyze_router)
app.include_router(datasets_router)
app.include_router(link_router)
app.include_router(email_router)
app.include_router(image_router)

@app.get("/")
async def root():
    return {"message": "AI Fraud Detection API is running"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)