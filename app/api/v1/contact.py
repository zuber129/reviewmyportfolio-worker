"""
Contact form endpoint for ReviewMyPortfolio.
Handles contact form submissions and sends emails via AWS SES.
"""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from app.core.config import settings
from app.infrastructure.email_service import send_contact_email
import structlog

logger = structlog.get_logger()

router = APIRouter()


class ContactFormRequest(BaseModel):
    """Contact form submission schema"""
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    subject: str = Field(..., pattern="^(general|bug|feature|partnership|other)$")
    message: str = Field(..., min_length=20, max_length=2000)


class ContactFormResponse(BaseModel):
    """Contact form response schema"""
    success: bool
    message: str


@router.post("/contact", response_model=ContactFormResponse, status_code=status.HTTP_200_OK)
async def submit_contact_form(request: ContactFormRequest):
    """
    Submit contact form.
    
    Sends email to appropriate support address based on subject.
    Rate limited to prevent spam (handled by global rate limiter).
    """
    try:
        # Map subject to recipient email
        subject_to_email = {
            "general": "support@reviewmyportfolio.in",
            "bug": "support@reviewmyportfolio.in",
            "feature": "support@reviewmyportfolio.in",
            "partnership": "partnerships@reviewmyportfolio.in",
            "other": "support@reviewmyportfolio.in",
        }
        
        recipient = subject_to_email.get(request.subject, "support@reviewmyportfolio.in")
        
        # Send email via AWS SES
        await send_contact_email(
            from_email=request.email,
            from_name=request.name,
            to_email=recipient,
            subject=f"Contact Form: {request.subject.title()}",
            message=request.message,
        )
        
        logger.info(
            "contact_form_submitted",
            subject=request.subject,
            from_email=request.email,
            to_email=recipient,
        )
        
        return ContactFormResponse(
            success=True,
            message="Thank you for contacting us. We'll respond within 24-48 hours."
        )
        
    except Exception as e:
        logger.error("contact_form_error", error=str(e), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send message. Please try again or email us directly."
        )
