from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.config import settings
from app.database import init_db
from app.api import routes

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("🚀 Starting PhishGuard Pro...")
    init_db()
    print("✓ Database initialized")
    yield
    # Shutdown
    print("👋 Shutting down PhishGuard Pro...")

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(routes.router, prefix=settings.API_PREFIX, tags=["Analysis"])

@app.get("/")
def root():
    return {
        "message": "PhishGuard Pro API",
        "version": settings.VERSION,
        "docs": "/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=False)