"""FastAPI application entry point for VulnAssess Pro."""
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import init_db
from app.routers import auth, scanner, dashboard, reports, admin

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Advanced Web and APK Vulnerability Assessment System",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS middleware — allow all origins for local file:// and dev server access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)
app.include_router(scanner.router)
app.include_router(dashboard.router)
app.include_router(reports.router)
app.include_router(admin.router)


@app.on_event("startup")
async def startup():
    """Initialize database on startup."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    init_db()
    logger.info("Database initialized")
    _seed_admin_user()


def _seed_admin_user():
    """Create a default admin user if none exists."""
    from app.database import SessionLocal
    from app.models.user import User, UserRole
    from app.auth.jwt_handler import get_password_hash

    db = SessionLocal()
    try:
        existing_admin = db.query(User).filter(User.role == UserRole.ADMIN).first()
        if not existing_admin:
            admin = User(
                email="admin@vulnassess.local",
                username="admin",
                hashed_password=get_password_hash("VulnAdmin@2025!"),
                full_name="System Administrator",
                role=UserRole.ADMIN,
                is_active=True,
                is_verified=True,
            )
            db.add(admin)
            db.commit()
            logger.info("Default admin user created: admin / VulnAdmin@2025!")
        else:
            logger.info(f"Admin user already exists: {existing_admin.username}")
    except Exception as e:
        logger.error(f"Admin seed error: {e}")
    finally:
        db.close()


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "app": settings.APP_NAME, "version": settings.APP_VERSION}
