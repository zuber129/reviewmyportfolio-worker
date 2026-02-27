"""
Gmail Client Service for Auto-Fetching CAS Statements

Handles:
- Gmail OAuth flow (authorization, token exchange, refresh)
- Email scanning for CAS statements
- PDF attachment downloading
- Incremental sync using Gmail history API
"""

import base64
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import structlog
from app.core.config import settings
from app.utils.encryption import decrypt_token, encrypt_token
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = structlog.get_logger()


class GmailClient:
    """Gmail API client for fetching CAS statements"""

    # CAS email patterns
    CAS_SENDERS = [
        "statement@camsonline.com",
        "cams@camsonline.com",
        "statement@kfintech.com",
        "kfintech@kfintech.com",
        "cas@nsdl.co.in",
        "nsdl@nsdl.co.in",
        "statement@cams.com",
        "cas@cams.com",
    ]

    CAS_SUBJECT_PATTERNS = [
        r"consolidated account statement",
        r"cas statement",
        r"portfolio statement",
        r"investment statement",
        r"mutual fund statement",
        r"demat statement",
    ]

    SCOPES = [
        "https://www.googleapis.com/auth/gmail.readonly",
    ]

    def __init__(self):
        self.client_id = getattr(settings, "google_oauth_client_id", None)
        self.client_secret = getattr(settings, "google_oauth_client_secret", None)
        self.redirect_uri = getattr(settings, "google_oauth_redirect_uri", None)

        if not all([self.client_id, self.client_secret, self.redirect_uri]):
            logger.warning(
                "gmail_oauth_not_configured",
                has_client_id=bool(self.client_id),
                has_client_secret=bool(self.client_secret),
                has_redirect_uri=bool(self.redirect_uri),
            )

    def get_authorization_url(self, state: str) -> str:
        """
        Generate Gmail OAuth authorization URL.

        Args:
            state: CSRF protection token

        Returns:
            Authorization URL for user to visit
        """
        from google_auth_oauthlib.flow import Flow

        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [self.redirect_uri],
                }
            },
            scopes=self.SCOPES,
        )
        flow.redirect_uri = self.redirect_uri

        authorization_url, _ = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            state=state,
            prompt="consent",
        )

        logger.info("gmail_authorization_url_generated", state=state)
        return authorization_url

    async def exchange_code_for_tokens(
        self, code: str
    ) -> Tuple[str, str, datetime, str]:
        """
        Exchange authorization code for access and refresh tokens.

        Args:
            code: Authorization code from OAuth callback

        Returns:
            Tuple of (access_token, refresh_token, expires_at, email)

        Raises:
            Exception: If token exchange fails
        """
        from google_auth_oauthlib.flow import Flow

        try:
            flow = Flow.from_client_config(
                {
                    "web": {
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "redirect_uris": [self.redirect_uri],
                    }
                },
                scopes=self.SCOPES,
            )
            flow.redirect_uri = self.redirect_uri

            flow.fetch_token(code=code)

            credentials = flow.credentials

            # Get user email
            service = build("gmail", "v1", credentials=credentials)
            profile = service.users().getProfile(userId="me").execute()
            email = profile.get("emailAddress")

            # Calculate expiry
            expires_at = datetime.utcnow() + timedelta(
                seconds=credentials.expiry.timestamp() - datetime.utcnow().timestamp()
                if credentials.expiry
                else 3600
            )

            logger.info(
                "gmail_tokens_exchanged",
                email=email,
                has_refresh_token=bool(credentials.refresh_token),
            )

            return (
                credentials.token,
                credentials.refresh_token,
                expires_at,
                email,
            )

        except Exception as e:
            logger.error("gmail_token_exchange_failed", error=str(e), exc_info=True)
            raise

    async def refresh_access_token(
        self, encrypted_refresh_token: str
    ) -> Tuple[str, datetime]:
        """
        Refresh access token using refresh token.

        Args:
            encrypted_refresh_token: Encrypted refresh token

        Returns:
            Tuple of (new_access_token, expires_at)

        Raises:
            Exception: If refresh fails
        """
        try:
            refresh_token = decrypt_token(encrypted_refresh_token)

            credentials = Credentials(
                token=None,
                refresh_token=refresh_token,
                token_uri="https://oauth2.googleapis.com/token",
                client_id=self.client_id,
                client_secret=self.client_secret,
            )

            credentials.refresh(Request())

            expires_at = datetime.utcnow() + timedelta(
                seconds=credentials.expiry.timestamp() - datetime.utcnow().timestamp()
                if credentials.expiry
                else 3600
            )

            logger.info("gmail_access_token_refreshed")
            return credentials.token, expires_at

        except Exception as e:
            logger.error("gmail_token_refresh_failed", error=str(e), exc_info=True)
            raise

    def _build_service(self, access_token: str):
        """Build Gmail API service with access token"""
        credentials = Credentials(token=access_token)
        return build("gmail", "v1", credentials=credentials)

    async def scan_for_cas_emails(
        self,
        access_token: str,
        last_history_id: Optional[str] = None,
        days_back: int = 180,
    ) -> Tuple[List[Dict], Optional[str]]:
        """
        Scan Gmail for CAS statement emails.

        Args:
            access_token: Gmail access token
            last_history_id: Last history ID for incremental sync
            days_back: How many days back to scan (for initial sync)

        Returns:
            Tuple of (list of CAS email metadata, new history ID)
        """
        try:
            service = self._build_service(access_token)

            # Build search query
            sender_query = " OR ".join([f"from:{sender}" for sender in self.CAS_SENDERS])
            date_query = f"newer_than:{days_back}d"
            attachment_query = "has:attachment"
            
            query = f"({sender_query}) {date_query} {attachment_query}"

            logger.info("gmail_scan_started", query=query, last_history_id=last_history_id)

            # List messages
            messages = []
            page_token = None

            while True:
                results = (
                    service.users()
                    .messages()
                    .list(userId="me", q=query, pageToken=page_token)
                    .execute()
                )

                if "messages" in results:
                    messages.extend(results["messages"])

                page_token = results.get("nextPageToken")
                if not page_token:
                    break

            logger.info("gmail_messages_found", count=len(messages))

            # Get full message details
            cas_emails = []
            for msg in messages:
                try:
                    full_msg = (
                        service.users()
                        .messages()
                        .get(userId="me", id=msg["id"], format="full")
                        .execute()
                    )

                    # Extract metadata
                    headers = {
                        h["name"].lower(): h["value"]
                        for h in full_msg.get("payload", {}).get("headers", [])
                    }

                    sender = headers.get("from", "")
                    subject = headers.get("subject", "")
                    date_str = headers.get("date", "")

                    # Parse date
                    from email.utils import parsedate_to_datetime
                    try:
                        received_at = parsedate_to_datetime(date_str)
                    except:
                        received_at = datetime.utcnow()

                    # Detect CAS provider
                    cas_provider = self._detect_cas_provider(sender, subject)

                    # Check for PDF attachments
                    has_pdf, attachment_count = self._check_pdf_attachments(full_msg)

                    if has_pdf:
                        cas_emails.append(
                            {
                                "gmail_message_id": msg["id"],
                                "gmail_thread_id": full_msg.get("threadId"),
                                "sender_email": sender,
                                "subject": subject,
                                "received_at": received_at,
                                "cas_provider": cas_provider,
                                "has_pdf_attachment": has_pdf,
                                "attachment_count": attachment_count,
                            }
                        )

                except HttpError as e:
                    logger.warning(
                        "gmail_message_fetch_failed",
                        message_id=msg["id"],
                        error=str(e),
                    )
                    continue

            # Get current history ID for next sync
            profile = service.users().getProfile(userId="me").execute()
            new_history_id = profile.get("historyId")

            logger.info(
                "gmail_scan_completed",
                total_messages=len(messages),
                cas_emails_found=len(cas_emails),
                new_history_id=new_history_id,
            )

            return cas_emails, new_history_id

        except HttpError as e:
            logger.error("gmail_scan_failed", error=str(e), exc_info=True)
            raise
        except Exception as e:
            logger.error("gmail_scan_error", error=str(e), exc_info=True)
            raise

    async def download_pdf_attachments(
        self, access_token: str, message_id: str
    ) -> List[Tuple[str, bytes]]:
        """
        Download PDF attachments from a Gmail message.

        Args:
            access_token: Gmail access token
            message_id: Gmail message ID

        Returns:
            List of (filename, pdf_bytes) tuples
        """
        try:
            service = self._build_service(access_token)

            message = (
                service.users()
                .messages()
                .get(userId="me", id=message_id, format="full")
                .execute()
            )

            attachments = []

            def process_part(part):
                if part.get("filename") and part.get("filename", "").lower().endswith(".pdf"):
                    if "data" in part.get("body", {}):
                        data = part["body"]["data"]
                        pdf_bytes = base64.urlsafe_b64decode(data)
                        attachments.append((part["filename"], pdf_bytes))
                    elif "attachmentId" in part.get("body", {}):
                        attachment_id = part["body"]["attachmentId"]
                        attachment = (
                            service.users()
                            .messages()
                            .attachments()
                            .get(userId="me", messageId=message_id, id=attachment_id)
                            .execute()
                        )
                        data = attachment["data"]
                        pdf_bytes = base64.urlsafe_b64decode(data)
                        attachments.append((part["filename"], pdf_bytes))

            # Process message parts
            payload = message.get("payload", {})
            if "parts" in payload:
                for part in payload["parts"]:
                    process_part(part)
                    if "parts" in part:
                        for subpart in part["parts"]:
                            process_part(subpart)
            else:
                process_part(payload)

            logger.info(
                "gmail_attachments_downloaded",
                message_id=message_id,
                count=len(attachments),
            )

            return attachments

        except HttpError as e:
            logger.error(
                "gmail_attachment_download_failed",
                message_id=message_id,
                error=str(e),
                exc_info=True,
            )
            raise
        except Exception as e:
            logger.error(
                "gmail_attachment_error",
                message_id=message_id,
                error=str(e),
                exc_info=True,
            )
            raise

    def _detect_cas_provider(self, sender: str, subject: str) -> str:
        """Detect CAS provider from email sender and subject"""
        sender_lower = sender.lower()
        subject_lower = subject.lower()

        if "nsdl" in sender_lower or "nsdl" in subject_lower:
            return "NSDL"
        elif "cams" in sender_lower or "cams" in subject_lower:
            return "CAMS"
        elif "karvy" in sender_lower or "kfintech" in sender_lower:
            return "KARVY"
        else:
            return "UNKNOWN"

    def _check_pdf_attachments(self, message: Dict) -> Tuple[bool, int]:
        """Check if message has PDF attachments"""
        pdf_count = 0

        def count_pdfs(part):
            nonlocal pdf_count
            filename = part.get("filename", "")
            if filename.lower().endswith(".pdf"):
                pdf_count += 1

        payload = message.get("payload", {})
        if "parts" in payload:
            for part in payload["parts"]:
                count_pdfs(part)
                if "parts" in part:
                    for subpart in part["parts"]:
                        count_pdfs(subpart)
        else:
            count_pdfs(payload)

        return pdf_count > 0, pdf_count


gmail_client = GmailClient()
