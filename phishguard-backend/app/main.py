from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import routes
from app.database import init_db

app = FastAPI(title="PhishGuard Pro")

# ==========================================
# 🛡️ CORS CONFIGURATION (THE FIX)
# ==========================================
# We use ["*"] to allow ALL connections. 
# This fixes the "Analysis Failed" network error.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# ==========================================

@app.on_event("startup")
def on_startup():
    init_db()

# Include Routes
app.include_router(routes.router, prefix="/api/v1")

if __name__ == "__main__":
    import uvicorn
    # reload=False prevents "spawn" errors with heavy AI models
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=False)