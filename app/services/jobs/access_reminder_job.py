"""Background job to send access control reminder emails."""

import asyncio
from datetime import datetime, timezone

import structlog
from app.core.config import settings
from app.infrastructure.supabase_client import supabase_client

logger = structlog.get_logger()


async def send_access_reminders():
    """
    Send reminder emails to users approaching access restrictions.
    Runs daily via cron/scheduler.
    - 50 days: First reminder (10 days until restricted)
    - 60 days: Final warning (entering 14-day grace period)
    """
    try:
        # Get all profiles with their auth user data
        # Using raw SQL query to efficiently filter by days since upload
        query = """
        SELECT 
            p.id,
            p.username,
            p.last_upload_date,
            u.email,
            EXTRACT(DAY FROM NOW() - p.last_upload_date)::INTEGER as days_since_upload
        FROM profiles p
        INNER JOIN auth.users u ON p.id = u.id
        WHERE p.last_upload_date IS NOT NULL
        AND (
            (EXTRACT(DAY FROM NOW() - p.last_upload_date)::INTEGER = 50) OR
            (EXTRACT(DAY FROM NOW() - p.last_upload_date)::INTEGER = 60)
        )
        """

        response = supabase_client.client.rpc("exec_sql", {"query": query}).execute()

        # Fallback to Python filtering if RPC not available
        if not response.data:
            response = (
                supabase_client.client.table("profiles")
                .select("id, username, last_upload_date")
                .not_.is_("last_upload_date", "null")
                .execute()
            )

            profiles = response.data if response.data else []
            now = datetime.now(timezone.utc)

            day_50_reminders = []
            day_60_reminders = []

            for profile in profiles:
                # Fetch email from auth.users
                user = await supabase_client.verify_token_and_get_user(profile["id"])
                email = user.get("email")

                last_upload = datetime.fromisoformat(
                    profile["last_upload_date"].replace("Z", "+00:00")
                )
                days_since = (now - last_upload).days

                if days_since == 50:
                    day_50_reminders.append({**profile, "email": email})
                elif days_since == 60:
                    day_60_reminders.append({**profile, "email": email})
        else:
            # Process RPC results
            day_50_reminders = [
                p for p in response.data if p["days_since_upload"] == 50
            ]
            day_60_reminders = [
                p for p in response.data if p["days_since_upload"] == 60
            ]

        # Send 50-day reminders (first warning)
        for profile in day_50_reminders:
            await send_reminder_email(
                email=profile["email"],
                username=profile["username"],
                days_remaining=10,
                reminder_type="first_warning",
            )
            logger.info("sent_50day_reminder", user_id=profile["id"])

        # Send 60-day reminders (final warning - grace period starts)
        for profile in day_60_reminders:
            await send_reminder_email(
                email=profile["email"],
                username=profile["username"],
                days_remaining=14,  # Grace period
                reminder_type="final_warning",
            )
            logger.info("sent_60day_reminder", user_id=profile["id"])

        logger.info(
            "access_reminders_sent",
            day_50_count=len(day_50_reminders),
            day_60_count=len(day_60_reminders),
        )

        return {
            "success": True,
            "day_50_sent": len(day_50_reminders),
            "day_60_sent": len(day_60_reminders),
        }

    except Exception as e:
        logger.error("access_reminder_job_error", error=str(e), exc_info=True)
        return {"success": False, "error": str(e)}


async def send_reminder_email(
    email: str, username: str, days_remaining: int, reminder_type: str
):
    """
    Send reminder email via AWS SES.
    Feature-flagged: only sends if AWS_ACCESS_KEY_ID is configured.
    Uses exponential backoff for transient SES failures [G-07].
    """
    from app.core.config import settings

    if not settings.aws_access_key_id:
        logger.warning(
            "reminder_email_skipped_no_ses_config",
            email=email,
            reminder_type=reminder_type,
        )
        return

    subject = (
        "Portfolio Upload Reminder — Action Required"
        if reminder_type == "first_warning"
        else "URGENT: Portfolio Upload Required"
    )
    body_text = (
        f"Hi {username},\n\n"
        f"Your last portfolio upload was more than "
        f"{'50' if reminder_type == 'first_warning' else '60'} days ago.\n"
        f"You have {days_remaining} days remaining to upload a fresh portfolio "
        f"before your account access is restricted.\n\n"
        f"Upload now at https://reviewmyportfolio.in/upload\n\n"
        f"Thanks,\nReviewMyPortfolio Team"
    )

    import boto3
    from botocore.exceptions import ClientError

    ses = boto3.client(
        "ses",
        region_name=settings.aws_ses_region,
        aws_access_key_id=settings.aws_access_key_id,
        aws_secret_access_key=settings.aws_secret_access_key,
    )

    max_attempts = 4
    for attempt in range(max_attempts):
        try:
            ses.send_email(
                Source=settings.email_from,
                Destination={"ToAddresses": [email]},
                Message={
                    "Subject": {"Data": subject, "Charset": "UTF-8"},
                    "Body": {"Text": {"Data": body_text, "Charset": "UTF-8"}},
                },
            )
            logger.info(
                "reminder_email_sent",
                email=email,
                reminder_type=reminder_type,
                days_remaining=days_remaining,
            )
            return
        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            if error_code in ("Throttling", "ServiceUnavailable") and attempt < max_attempts - 1:
                wait = 2 ** attempt
                logger.warning(
                    "reminder_email_retry",
                    attempt=attempt + 1,
                    wait_seconds=wait,
                    error=error_code,
                )
                await asyncio.sleep(wait)
            else:
                logger.error(
                    "reminder_email_failed",
                    email=email,
                    reminder_type=reminder_type,
                    error=str(exc),
                    exc_info=True,
                )
                return
