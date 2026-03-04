from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from backend.routers.ingest import router as ingest_router
from backend.routers.analyze import router as analyze_router
from contextlib import asynccontextmanager
import logging
from backend.database.mongodb import mongodb_conn
from backend.database.redis import redis_conn
# Note: simple in-app rate limiting implemented in router for demo

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting up the application...")
    try:
        # Allow skipping DB connects in test mode
        import os
        if os.environ.get('SKIP_DB') != '1':
            await mongodb_conn.connect()
            await redis_conn.connect()
            logger.info("Database connections established successfully")
        else:
            logger.info("SKIP_DB set — skipping DB connects for testing")
    except Exception as e:
        logger.error(f"Failed to establish database connections: {e}")
        raise

    yield

    # Shutdown
    logger.info("Shutting down the application...")
    await redis_conn.close()
    await mongodb_conn.close()
    logger.info("Database connections closed")

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

@app.get("/")
async def root():
    return {"message": "AI Fraud Detection API is running"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)