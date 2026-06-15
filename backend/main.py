from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from backend.database import engine, Base
from routes import auth, dashboard, event, threat, user

# Create all database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="GraphSec API",
    description="Security Event & Threat Management System",
    version="1.0.0"
)

# CORS - allows frontend to talk to backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files (HTML frontend)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Register all routers
app.include_router(auth.router,      prefix="/auth",      tags=["Auth"])
app.include_router(user.router,      prefix="/users",     tags=["Users"])
app.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
app.include_router(event.router,     prefix="/events",    tags=["Events"])
app.include_router(threat.router,    prefix="/threats",   tags=["Threats"])

@app.get("/")
def home():
    return {"message": "GraphSec API Running", "docs": "/docs"}
