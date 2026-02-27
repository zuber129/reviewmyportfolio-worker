"""
Email service for sending transactional emails via AWS SES.
"""
import boto3
from botocore.exceptions import ClientError
from app.core.config import settings
import structlog

logger = structlog.get_logger()


async def send_contact_email(
    from_email: str,
    from_name: str,
    to_email: str,
    subject: str,
    message: str,
) -> None:
    """
    Send contact form email via AWS SES.
    
    Args:
        from_email: User's email address
        from_name: User's name
        to_email: Recipient email (support@, partnerships@, etc.)
        subject: Email subject line
        message: Email body content
    """
    # If AWS SES not configured, log and skip (dev mode)
    if not settings.aws_access_key_id or not settings.aws_secret_access_key:
        logger.warning(
            "aws_ses_not_configured",
            message="Email not sent - AWS SES credentials missing",
            to_email=to_email,
        )
        return
    
    try:
        ses_client = boto3.client(
            'ses',
            region_name=settings.aws_ses_region,
            aws_access_key_id=settings.aws_access_key_id,
            aws_secret_access_key=settings.aws_secret_access_key,
        )
        
        # Email body with user details
        body_text = f"""
Contact Form Submission

From: {from_name} <{from_email}>
Subject: {subject}

Message:
{message}

---
Reply directly to this email to respond to the user.
        """.strip()
        
        body_html = f"""
<html>
<body>
    <h2>Contact Form Submission</h2>
    <p><strong>From:</strong> {from_name} &lt;{from_email}&gt;</p>
    <p><strong>Subject:</strong> {subject}</p>
    <hr>
    <p><strong>Message:</strong></p>
    <p style="white-space: pre-wrap;">{message}</p>
    <hr>
    <p style="color: #666; font-size: 12px;">Reply directly to this email to respond to the user.</p>
</body>
</html>
        """.strip()
        
        response = ses_client.send_email(
            Source=settings.email_from,
            Destination={'ToAddresses': [to_email]},
            ReplyToAddresses=[from_email],
            Message={
                'Subject': {'Data': subject, 'Charset': 'UTF-8'},
                'Body': {
                    'Text': {'Data': body_text, 'Charset': 'UTF-8'},
                    'Html': {'Data': body_html, 'Charset': 'UTF-8'},
                }
            }
        )
        
        logger.info(
            "email_sent",
            message_id=response['MessageId'],
            to_email=to_email,
            from_email=from_email,
        )
        
    except ClientError as e:
        logger.error(
            "ses_error",
            error=e.response['Error']['Message'],
            to_email=to_email,
        )
        raise
