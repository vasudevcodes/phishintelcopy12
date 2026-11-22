"""
Email analysis endpoint for PhishIntel (Phase 1).
Validates upload constraints, parses RFC 5322 .eml files, and returns forensic artifacts.
"""

from fastapi import APIRouter, File, HTTPException, UploadFile, status
from starlette.concurrency import run_in_threadpool
from app.core.config import settings
from app.schemas.email import EmailAnalysisResponse, ErrorResponse
from app.services.email_parser import parse_email_message

router = APIRouter()


@router.post(
    "/analyze",
    response_model=EmailAnalysisResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Bad Request - Invalid file or format"},
        413: {"model": ErrorResponse, "description": "Payload Too Large - Exceeds 10 MB"},
    },
    summary="Analyze an .eml email file forensically",
    description="Accepts a single .eml file up to 10 MB, extracts RFC 5322 headers, body, URLs, attachments, and candidate IPs.",
)
async def analyze_email(
    file: UploadFile = File(..., description="An RFC 5322 compliant .eml email file")
) -> EmailAnalysisResponse:
    # 1. Validate file extension
    filename = file.filename or ""
    if not filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file extension for '{filename}'. Only .eml files are accepted.",
        )

    # 2. Read file with size enforcement (stream-capped to prevent memory exhaustion)
    max_bytes = settings.MAX_UPLOAD_SIZE_BYTES
    chunk_size = 1024 * 1024  # 1 MB chunks
    total_bytes_read = 0
    chunks = []

    try:
        while True:
            chunk = await file.read(chunk_size)
            if not chunk:
                break
            total_bytes_read += len(chunk)
            if total_bytes_read > max_bytes:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail=f"File exceeds maximum upload limit of 10 MB ({total_bytes_read} bytes read).",
                )
            chunks.append(chunk)
    except HTTPException:
        raise
    except Exception as read_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file: {str(read_err)}",
        )
    finally:
        await file.close()

    # 3. Check for empty file
    if total_bytes_read == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty (0 bytes).",
        )

    file_bytes = b"".join(chunks)

    # 4. Parse forensic data
    try:
        # Parsing now performs blocking DNS lookups (live SPF/DKIM/DMARC); run it in a worker
        # thread so the async event loop stays responsive.
        analysis_result = await run_in_threadpool(parse_email_message, file_bytes, filename)
        return analysis_result
    except Exception as parse_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to parse email forensic structure: {str(parse_err)}",
        )
