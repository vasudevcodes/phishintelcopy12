"""
API v1 Router aggregation.
"""

from fastapi import APIRouter
from app.api.v1.endpoints import email

api_router = APIRouter()
api_router.include_router(email.router, prefix="/email", tags=["Email Forensics"])
