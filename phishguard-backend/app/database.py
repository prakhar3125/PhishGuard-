from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import settings

# 1. Create Engine (MySQL Connection)
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """Dependency for FastAPI routes"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initialize database tables"""
    # ⚠️ CRITICAL FIX: Import models here so they register with 'Base'
    # If you remove these imports, no tables will be created!
    import app.models  
    
    print("🔄 Connecting to MySQL to create tables...")
    Base.metadata.create_all(bind=engine)
    print("✅ Tables created successfully!")