from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta

import structlog  # type: ignore[import-not-found]
from app.core.config import settings
from app.core.exceptions import (
    AuthenticationError,
    PortfolioNotFoundError,
    ProfileNotFoundError,
    SupabaseError,
    UserNotFoundError,
)
from pybreaker import CircuitBreaker  # type: ignore[import-not-found]
from tenacity import retry  # type: ignore[import-not-found]
from tenacity import stop_after_attempt, wait_exponential

import supabase  # type: ignore[import-not-found]

logger = structlog.get_logger()

# Circuit breaker for Supabase calls
supabase_breaker = CircuitBreaker(fail_max=5, reset_timeout=60)


class SupabaseClient:
    def __init__(self):
        # Use supabase module to avoid mypy attr-defined errors when stubs are missing
        # Disable auto_refresh_token, persist_session and realtime to avoid client issues
        client_options: Any = None
        # Use ClientOptions if present in the installed supabase package; otherwise pass None
        if hasattr(supabase, "ClientOptions"):
            try:
                client_options = supabase.ClientOptions(  # type: ignore[attr-defined]
                    auto_refresh_token=False,
                    persist_session=False,
                    realtime={"enabled": False},  # Explicitly disable realtime
                )
            except Exception:
                client_options = None
        self.client: Any = supabase.create_client(  # type: ignore[attr-defined]
            settings.supabase_url, settings.supabase_service_key, options=client_options
        )
        self.anon_client: Any = supabase.create_client(  # type: ignore[attr-defined]
            settings.supabase_url, settings.supabase_anon_key, options=client_options
        )
        self._client_created_at = datetime.utcnow()
        self._client_options = client_options

        # Monkey-patch realtime to avoid NoneType errors
        if self.client.realtime is None:

            class MockRealtime:
                def set_auth(self, *args, **kwargs):
                    pass  # No-op

            self.client.realtime = MockRealtime()

        if self.anon_client.realtime is None:

            class MockRealtime:
                def set_auth(self, *args, **kwargs):
                    pass  # No-op

            self.anon_client.realtime = MockRealtime()

    def _refresh_client_if_needed(self) -> None:
        """
        Refresh the Supabase client if it's been running for more than 12 hours.
        This prevents JWT token expiration issues in Storage API.
        """
        hours_since_creation = (datetime.utcnow() - self._client_created_at).total_seconds() / 3600
        
        if hours_since_creation > 12:
            logger.info(
                "refreshing_supabase_client",
                hours_since_creation=hours_since_creation,
                reason="token_refresh"
            )
            
            # Recreate the client with fresh tokens
            self.client = supabase.create_client(  # type: ignore[attr-defined]
                settings.supabase_url,
                settings.supabase_service_key,
                options=self._client_options
            )
            self._client_created_at = datetime.utcnow()
            
            # Re-apply realtime monkey-patch if needed
            if self.client.realtime is None:
                class MockRealtime:
                    def set_auth(self, *args, **kwargs):
                        pass
                self.client.realtime = MockRealtime()
            
            logger.info("supabase_client_refreshed")

    def get_client_health(self) -> Dict[str, Any]:
        """
        Get health status of the Supabase client.
        Useful for monitoring and debugging token issues.
        """
        hours_since_creation = (datetime.utcnow() - self._client_created_at).total_seconds() / 3600
        
        return {
            "client_age_hours": round(hours_since_creation, 2),
            "client_created_at": self._client_created_at.isoformat(),
            "needs_refresh": hours_since_creation > 12,
            "status": "healthy" if hours_since_creation < 12 else "needs_refresh"
        }

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def signup_user(
        self, email: str, password: str, username: str
    ) -> Dict[str, Any]:
        try:
            # Create auth user using anon client (correct for signup)
            auth_response = self.anon_client.auth.sign_up(
                {
                    "email": email,
                    "password": password,
                    "options": {"data": {"username": username}},
                }
            )

            if not auth_response or not auth_response.user:
                logger.error("user_signup_failed", email=email)
                raise AuthenticationError("Signup failed - no user returned")

            user_id = auth_response.user.id
            
            # Create profile using service_role client (bypasses RLS)
            try:
                self.client.table("profiles").insert({
                    "id": str(user_id),
                    "username": username,
                    "email": email,
                    "access_status": "active"
                }).execute()
                logger.info("profile_created", user_id=user_id, username=username)
            except Exception as profile_error:
                # Compensation: delete the orphaned auth user
                logger.error("profile_creation_failed", user_id=user_id, error=str(profile_error))
                try:
                    self.client.auth.admin.delete_user(str(user_id))
                    logger.info("orphaned_user_deleted", user_id=user_id)
                except Exception as delete_error:
                    logger.error("failed_to_delete_orphaned_user", user_id=user_id, error=str(delete_error))
                
                # Raise user-friendly error
                raise SupabaseError("Failed to create user profile. Please try again or contact support.")
            
            logger.info("user_signup_success", user_id=user_id)

            session_data = None
            if hasattr(auth_response, "session") and auth_response.session:
                session_data = {
                    "access_token": auth_response.session.access_token,
                    "refresh_token": auth_response.session.refresh_token,
                    "expires_in": auth_response.session.expires_in,
                }

            return {
                "user": {
                    "id": auth_response.user.id,
                    "email": email,
                    "user_metadata": {"username": username},
                },
                "session": session_data,
            }

        except AuthenticationError:
            raise
        except Exception as e:
            import traceback
            logger.error("signup_error", email=email, error=str(e), error_type=type(e).__name__, traceback=traceback.format_exc())
            raise SupabaseError(f"Database error during signup: {str(e)}")

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def signin_user(self, email: str, password: str) -> Dict[str, Any]:
        try:
            # Use anon client for signin
            auth_response = self.anon_client.auth.sign_in_with_password(
                {"email": email, "password": password}
            )

            if auth_response.user:
                # Get profile using service client (with proper auth)
                profile_response = (
                    self.client.table("profiles")
                    .select("*")
                    .eq("id", auth_response.user.id)
                    .single()
                    .execute()
                )

                logger.info("user_signin_success", user_id=auth_response.user.id)
                return {
                    "user": {
                        "id": auth_response.user.id,
                        "email": email,
                        "user_metadata": auth_response.user.user_metadata or {},
                    },
                    "profile": profile_response.data,
                    "session": (
                        {
                            "access_token": auth_response.session.access_token,
                            "refresh_token": auth_response.session.refresh_token,
                            "expires_in": auth_response.session.expires_in,
                        }
                        if auth_response.session
                        else None
                    ),
                }
            else:
                logger.error("user_signin_failed", email=email)
                raise AuthenticationError("Signin failed - invalid credentials")

        except Exception as e:
            logger.error("signin_error", email=email, error=str(e))
            raise

    @supabase_breaker
    async def signout_user(self) -> None:
        """
        Sign out the current user and revoke their session in Supabase.
        This is a client-side operation that invalidates the session.
        """
        try:
            self.anon_client.auth.sign_out()
            logger.info("user_signout_supabase_success")
        except Exception as e:
            logger.error("signout_supabase_error", error=str(e))
            raise SupabaseError(f"Failed to sign out from Supabase: {str(e)}")

    @supabase_breaker
    async def verify_email(self, token: str) -> Dict[str, Any]:
        """
        Verify email address using token from verification email.

        Args:
            token: The verification token from the email link

        Returns:
            Dict containing user data if verification successful

        Raises:
            AuthenticationError: If token is invalid or expired
        """
        try:
            # Verify OTP token with Supabase
            response = self.anon_client.auth.verify_otp(
                {"token_hash": token, "type": "email"}
            )

            if not response or not response.user:
                raise AuthenticationError("Invalid or expired verification token")

            logger.info("email_verification_success", user_id=response.user.id)

            return {
                "user": {
                    "id": response.user.id,
                    "email": response.user.email,
                    "email_confirmed_at": response.user.email_confirmed_at,
                }
            }
        except AuthenticationError:
            raise
        except Exception as e:
            logger.error("verify_email_error", error=str(e))
            raise AuthenticationError(f"Email verification failed: {str(e)}")

    @supabase_breaker
    async def resend_verification_email(self, email: str) -> None:
        """
        Resend verification email to user.

        Args:
            email: User's email address

        Note:
            This method does not raise exceptions if email doesn't exist
            to prevent email enumeration attacks.
        """
        try:
            self.anon_client.auth.resend({"type": "signup", "email": email})
            logger.info("verification_email_resent", email=email)
        except Exception as e:
            # Log error but don't raise to prevent email enumeration
            logger.warning("resend_verification_error", email=email, error=str(e))

    @supabase_breaker
    async def request_password_reset(self, email: str, redirect_url: str) -> None:
        """
        Request password reset email for user.

        Args:
            email: User's email address
            redirect_url: URL to redirect to after clicking reset link

        Note:
            This method does not raise exceptions if email doesn't exist
            to prevent email enumeration attacks.
        """
        try:
            self.anon_client.auth.reset_password_for_email(
                email, options={"redirect_to": redirect_url}
            )
            logger.info("password_reset_requested", email=email)
        except Exception as e:
            # Log error but don't raise to prevent email enumeration
            logger.warning("password_reset_request_error", email=email, error=str(e))

    @supabase_breaker
    async def reset_password(
        self, access_token: str, new_password: str
    ) -> Dict[str, Any]:
        """
        Reset user password using access token from reset email.

        Args:
            access_token: The access token from the password reset email
            new_password: The new password to set

        Returns:
            Dict containing user data if reset successful

        Raises:
            AuthenticationError: If token is invalid or password reset fails
        """
        try:
            # Update password via Supabase
            response = self.anon_client.auth.update_user(
                {"password": new_password}, access_token=access_token
            )

            if not response or not response.user:
                raise AuthenticationError("Invalid or expired reset token")

            logger.info("password_reset_success", user_id=response.user.id)

            return {
                "user": {
                    "id": response.user.id,
                    "email": response.user.email,
                }
            }
        except AuthenticationError:
            raise
        except Exception as e:
            logger.error("reset_password_error", error=str(e))
            raise AuthenticationError(f"Password reset failed: {str(e)}")

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def get_user_profile(self, user_id: str) -> Dict[str, Any]:
        """Get user profile by ID. Raises ProfileNotFoundError if not found."""
        try:
            response = (
                self.client.table("profiles")
                .select("*")
                .eq("id", user_id)
                .single()
                .execute()
            )
            if not response.data:
                raise ProfileNotFoundError(f"Profile not found for user: {user_id}")
            return response.data
        except ProfileNotFoundError:
            raise
        except Exception as e:
            logger.error("get_profile_error", user_id=user_id, error=str(e))
            raise SupabaseError(f"Failed to fetch profile: {str(e)}")

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def update_user_profile(
        self, user_id: str, updates: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update a user profile by id. Raises ProfileNotFoundError if profile doesn't exist."""
        try:
            response = (
                self.client.table("profiles")
                .update(updates)
                .eq("id", user_id)
                .execute()
            )
            logger.info(
                "profile_updated", user_id=user_id, updates=list(updates.keys())
            )
            # Return the first item from response data
            if response.data and len(response.data) > 0:
                return response.data[0]
            raise ProfileNotFoundError(
                f"Profile not found or update failed for user: {user_id}"
            )
        except ProfileNotFoundError:
            raise
        except Exception as e:
            logger.error("update_profile_error", user_id=user_id, error=str(e))
            raise SupabaseError(f"Failed to update profile: {str(e)}")

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def update_portfolio(
        self, portfolio_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update a portfolio by id. Returns {id, ...} or {error: str}."""
        try:
            response = (
                self.client.table("portfolios")
                .update(data)
                .eq("id", portfolio_id)
                .select("*")
                .single()
                .execute()
            )

            if response.data:
                logger.info("portfolio_updated", portfolio_id=portfolio_id)
                return response.data
            return {"error": "Update returned no data"}
        except Exception as e:
            logger.error(
                "update_portfolio_error", portfolio_id=portfolio_id, error=str(e)
            )
            return {"error": str(e)}

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def get_pending_portfolio_files(self, user_id: str) -> List[Dict[str, Any]]:
        """Fetch user's portfolio files that are still processing or recently completed."""
        try:
            # Get files from last 10 minutes that are not in final state
            from datetime import datetime, timedelta
            cutoff = (datetime.utcnow() - timedelta(minutes=10)).isoformat()
            
            response = (
                self.client.table("portfolio_files")
                .select("*")
                .eq("user_id", user_id)
                .gte("uploaded_at", cutoff)
                .in_("status", ["uploaded", "validating", "scanning", "parsing", "completed", "failed"])
                .order("uploaded_at", desc=True)
                .limit(5)
                .execute()
            )
            return response.data or []
        except Exception as e:
            logger.error("get_pending_portfolio_files_error", user_id=user_id, error=str(e))
            return []

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def get_portfolio(self, portfolio_id: str) -> Dict[str, Any]:
        """Fetch a portfolio by id. Raises PortfolioNotFoundError if not found."""
        try:
            response = (
                self.client.table("portfolios")
                .select("*")
                .eq("id", portfolio_id)
                .single()
                .execute()
            )
            if not response.data:
                raise PortfolioNotFoundError(f"Portfolio not found: {portfolio_id}")
            return response.data
        except PortfolioNotFoundError:
            raise
        except Exception as e:
            logger.error("get_portfolio_error", portfolio_id=portfolio_id, error=str(e))
            raise SupabaseError(f"Failed to fetch portfolio: {str(e)}")

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def verify_token_and_get_user(self, token: str) -> Dict[str, Any]:
        """Verify a Supabase access token and return the user. Raises AuthenticationError if invalid."""
        try:
            # Get user from token
            response = self.client.auth.get_user(token)
            if response.user:
                # Convert user object to dict - Supabase returns a User object
                user_data = {
                    "id": response.user.id,
                    "email": response.user.email,
                    "user_metadata": response.user.user_metadata,
                }
                return user_data
            raise AuthenticationError("Invalid or expired token")
        except AuthenticationError:
            raise
        except Exception as e:
            logger.error("verify_token_error", error=str(e))
            raise AuthenticationError(f"Token verification failed: {str(e)}")

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def signin_with_provider(
        self, provider: str, id_token: str
    ) -> Dict[str, Any]:
        """Sign in with OAuth provider (Google, etc.)"""
        try:
            # Sign in with OAuth provider token
            auth_response = self.client.auth.sign_in_with_id_token(
                {"provider": provider, "token": id_token}
            )

            if auth_response.user:
                session_data = None
                if auth_response.session:
                    session_data = {
                        "access_token": auth_response.session.access_token,
                        "refresh_token": auth_response.session.refresh_token,
                        "expires_in": auth_response.session.expires_in,
                    }
                return {
                    "user": {
                        "id": auth_response.user.id,
                        "email": auth_response.user.email,
                        "user_metadata": auth_response.user.user_metadata,
                    },
                    "session": session_data,
                }
            raise AuthenticationError(f"Provider signin failed for {provider}")
        except Exception as e:
            logger.error("provider_signin_error", provider=provider, error=str(e))
            raise

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def signup_with_provider(
        self, provider: str, id_token: str, user_metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Sign up with OAuth provider (Google, etc.)"""
        try:
            # Sign up with OAuth provider token
            auth_response = self.client.auth.sign_in_with_id_token(
                {
                    "provider": provider,
                    "token": id_token,
                    "options": {"data": user_metadata},
                }
            )

            if auth_response.user:
                # Create profile record if new user
                existing_profile = await self.get_user_profile(auth_response.user.id)
                if not existing_profile:
                    (
                        self.client.table("profiles")
                        .insert(
                            {
                                "id": auth_response.user.id,
                                "username": user_metadata.get("username"),
                                "avatar_url": user_metadata.get("avatar_url"),
                            }
                        )
                        .execute()
                    )
                    # Fetch the newly created profile
                    existing_profile = await self.get_user_profile(
                        auth_response.user.id
                    )

                # Use actual profile data for response (not the passed-in metadata)
                session_data = None
                if auth_response.session:
                    session_data = {
                        "access_token": auth_response.session.access_token,
                        "refresh_token": auth_response.session.refresh_token,
                        "expires_in": auth_response.session.expires_in,
                    }

                # Build user metadata from actual profile
                actual_metadata = {
                    "username": (
                        existing_profile.get("username")
                        if existing_profile
                        else user_metadata.get("username")
                    ),
                    "avatar_url": (
                        existing_profile.get("avatar_url")
                        if existing_profile
                        else user_metadata.get("avatar_url")
                    ),
                    "full_name": user_metadata.get("full_name"),  # Keep from Google
                }

                return {
                    "user": {
                        "id": auth_response.user.id,
                        "email": auth_response.user.email,
                        "user_metadata": actual_metadata,
                    },
                    "session": session_data,
                }
            raise AuthenticationError(f"Provider signup failed for {provider}")
        except Exception as e:
            logger.error("provider_signup_error", provider=provider, error=str(e))
            raise

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def upload_to_storage(
        self, bucket: str, path: str, file_data: bytes, content_type: str
    ) -> Optional[str]:
        try:
            self.client.storage.from_(bucket).upload(
                path=path, file=file_data, file_options={"content-type": content_type}
            )

            # Get public URL
            public_url = self.client.storage.from_(bucket).get_public_url(path)
            logger.info("file_upload_success", bucket=bucket, path=path)
            return public_url
        except Exception as e:
            logger.error("file_upload_error", bucket=bucket, path=path, error=str(e))
            return None

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def create_portfolio(
        self, user_id: str, data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        try:
            response = (
                self.client.table("portfolios")
                .insert({**data, "user_id": user_id})
                .execute()
            )

            # Update last_upload_date to reset access control timer
            await self.update_last_upload_date(user_id)

            logger.info(
                "portfolio_created",
                user_id=user_id,
                portfolio_id=response.data[0]["id"] if response.data else None,
            )
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error("create_portfolio_error", user_id=user_id, error=str(e))
            return None

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def create_presigned_upload_url(
        self, bucket: str, path: str, expires_in: int = 300
    ) -> Optional[str]:
        """
        Create a presigned URL for direct file upload to Supabase Storage.

        Args:
            bucket: Storage bucket name
            path: File path within the bucket
            expires_in: URL expiration time in seconds (default 5 minutes)

        Returns:
            Presigned URL string or None if error
        """
        try:
            # Refresh client if needed to prevent token expiration
            self._refresh_client_if_needed()
            
            # Supabase Storage uses signed URLs for uploads
            # Returns: {"signed_url": str, "token": str, "path": str}
            response = self.client.storage.from_(bucket).create_signed_upload_url(path)

            if response and "signed_url" in response:
                logger.info("presigned_url_created", bucket=bucket, path=path)
                return response["signed_url"]

            logger.error(
                "presigned_url_creation_failed",
                bucket=bucket,
                path=path,
                response=response,
            )
            return None
        except Exception as e:
            logger.error("presigned_url_error", bucket=bucket, path=path, error=str(e))
            return None

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def download_from_storage(self, bucket: str, path: str) -> Optional[bytes]:
        """Download file from Supabase Storage"""
        try:
            response = self.client.storage.from_(bucket).download(path)
            logger.info("file_downloaded", bucket=bucket, path=path)
            return response
        except Exception as e:
            logger.error("file_download_error", bucket=bucket, path=path, error=str(e))
            return None

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def create_portfolio_snapshot(
        self, data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Create a new portfolio snapshot record"""
        try:
            response = self.client.table("portfolio_snapshots").insert(data).execute()

            logger.info(
                "snapshot_created",
                snapshot_id=response.data[0]["id"] if response.data else None,
                user_id=data.get("user_id"),
            )
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error("create_snapshot_error", error=str(e))
            return {"error": str(e)}

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def create_portfolio_transactions(
        self, snapshot_id: str, user_id: str, transactions: List[Dict[str, Any]]
    ) -> int:
        """Bulk-insert transactions for a snapshot. Returns count of inserted rows."""
        if not transactions:
            return 0
        try:
            rows = [
                {
                    "snapshot_id": snapshot_id,
                    "user_id": user_id,
                    "isin": t["isin"],
                    "asset_name": t.get("asset_name"),
                    "transaction_type": t["transaction_type"],
                    "date": t["date"],
                    "quantity": t["quantity"],
                    "amount": t.get("amount"),
                    "price": t.get("price"),
                    "reference": t.get("reference"),
                    "op_bal": t.get("op_bal"),
                    "cl_bal": t.get("cl_bal"),
                }
                for t in transactions
            ]
            response = (
                self.client.table("portfolio_transactions").insert(rows).execute()
            )
            count = len(response.data) if response.data else 0
            logger.info(
                "portfolio_transactions_saved",
                snapshot_id=snapshot_id,
                count=count,
            )
            return count
        except Exception as e:
            logger.error(
                "create_portfolio_transactions_error",
                snapshot_id=snapshot_id,
                error=str(e),
            )
            return 0

    @supabase_breaker
    async def check_snapshot_exists(
        self, user_id: str, pdf_hash: str
    ) -> Optional[Dict[str, Any]]:
        """Check if a snapshot with this PDF hash already exists for the user"""
        try:
            response = (
                self.client.table("portfolio_snapshots")
                .select("id, upload_time, statement_date")
                .eq("user_id", user_id)
                .eq("pdf_hash", pdf_hash)
                .execute()
            )

            if response.data and len(response.data) > 0:
                return response.data[0]
            return None
        except Exception as e:
            logger.error("check_snapshot_error", error=str(e))
            return None

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def check_pii_hash_exists(self, pii_hash: str) -> Optional[Dict[str, Any]]:
        """Check if PII hash exists in any portfolio"""
        try:
            response = (
                self.client.table("portfolios")
                .select("id, user_id, created_at")
                .eq("pii_hash", pii_hash)
                .is_("deleted_at", "null")
                .execute()
            )
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error("check_pii_hash_error", error=str(e))
            return None

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def get_user_pii_hash(self, user_id: str) -> Optional[str]:
        """Get the PII hash for a user's existing portfolio"""
        try:
            response = (
                self.client.table("portfolios")
                .select("pii_hash")
                .eq("user_id", user_id)
                .is_("deleted_at", "null")
                .limit(1)
                .execute()
            )
            if response.data and response.data[0].get("pii_hash"):
                return response.data[0]["pii_hash"]
            return None
        except Exception as e:
            logger.error("get_user_pii_hash_error", error=str(e))
            return None

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def get_portfolios_feed(
        self, offset: int = 0, limit: int = 20, filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        try:
            query = (
                self.client.table("portfolios")
                .select("*")
                .is_("deleted_at", "null")
                .eq("is_public", True)
                .eq("moderation_status", "visible")
            )

            if filters:
                if "risk_level" in filters:
                    query = query.eq("risk_level", filters["risk_level"])
                if "min_xirr" in filters:
                    query = query.gte("xirr", filters["min_xirr"])
                if "max_xirr" in filters:
                    query = query.lte("xirr", filters["max_xirr"])

            response = query.range(offset, offset + limit - 1).execute()
            return response.data
        except Exception as e:
            logger.error("get_feed_error", error=str(e))
            return []

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def create_portfolio_review(
        self,
        portfolio_id: str,
        user_id: str,
        rating: int,
        content: str,
        review_type: str = "community",
    ) -> Optional[Dict[str, Any]]:
        try:
            response = (
                self.client.table("portfolio_reviews")
                .insert(
                    {
                        "portfolio_id": portfolio_id,
                        "user_id": user_id,
                        "rating": rating,
                        "content": content,
                        "review_type": review_type,
                    }
                )
                .execute()
            )

            logger.info("review_created", portfolio_id=portfolio_id, user_id=user_id)
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error("create_review_error", portfolio_id=portfolio_id, error=str(e))
            return None

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def get_leaderboard(
        self, time_range: str = "all_time", limit: int = 100
    ) -> List[Dict[str, Any]]:
        try:
            # This can be optimized with a materialized view or cached query
            query = (
                self.client.table("user_stats")
                .select("*, profiles!user_stats_user_id_fkey(username, avatar_url)")
                .order("xirr", desc=True)
            )

            # Apply time filtering if needed
            if time_range == "monthly":
                from datetime import datetime, timedelta, timezone

                thirty_days_ago = (
                    datetime.now(timezone.utc) - timedelta(days=30)
                ).isoformat()
                query = query.gte("created_at", thirty_days_ago)

            response = query.limit(limit).execute()
            return response.data
        except Exception as e:
            logger.error("get_leaderboard_error", error=str(e))
            return []

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def check_username_exists(self, username: str) -> bool:
        """
        Check if a username already exists in the profiles table.
        Returns True if username is taken, False if available.
        """
        try:
            response = (
                self.client.table("profiles")
                .select("username")
                .eq("username", username)
                .execute()
            )

            # Check if any rows returned
            exists = response.data is not None and len(response.data) > 0
            logger.info("username_check", username=username, exists=exists)
            return exists
        except Exception as e:
            logger.error("check_username_error", username=username, error=str(e))
            # On error, assume username might be taken (fail safe)
            return True

    # ========== OLD OPINION/COMMENT METHODS - DEPRECATED ==========
    # These methods are for the old portfolio-scoped opinions system
    # New instrument-scoped opinions use different methods below

    @supabase_breaker
    async def check_user_voted_helpful(self, opinion_id: str, user_id: str) -> bool:
        """Check if user has voted an opinion as helpful."""
        try:
            response = (
                self.client.table("opinion_votes")
                .select("id")
                .eq("opinion_id", opinion_id)
                .eq("user_id", user_id)
                .execute()
            )

            return response.data is not None and len(response.data) > 0
        except Exception as e:
            logger.error("check_helpful_vote_error", error=str(e))
            return False

    @supabase_breaker
    async def add_helpful_vote(self, opinion_id: str, user_id: str) -> bool:
        """Add a helpful vote to an opinion."""
        try:
            response = (
                self.client.table("opinion_votes")
                .insert(
                    {
                        "opinion_id": opinion_id,
                        "user_id": user_id,
                    }
                )
                .execute()
            )

            logger.info("helpful_vote_added", opinion_id=opinion_id, user_id=user_id)
            return True
        except Exception as e:
            logger.error("add_helpful_vote_error", error=str(e))
            raise SupabaseError(f"Failed to add helpful vote: {str(e)}")

    @supabase_breaker
    async def remove_helpful_vote(self, opinion_id: str, user_id: str) -> bool:
        """Remove a helpful vote from an opinion."""
        try:
            response = (
                self.client.table("opinion_votes")
                .delete()
                .eq("opinion_id", opinion_id)
                .eq("user_id", user_id)
                .execute()
            )

            logger.info("helpful_vote_removed", opinion_id=opinion_id, user_id=user_id)
            return True
        except Exception as e:
            logger.error("remove_helpful_vote_error", error=str(e))
            raise SupabaseError(f"Failed to remove helpful vote: {str(e)}")

    @supabase_breaker
    async def get_opinion_helpful_count(self, opinion_id: str) -> int:
        """Get the count of helpful votes for an opinion (opinions table)."""
        try:
            response = (
                self.client.table("opinions")
                .select("helpful_count")
                .eq("id", opinion_id)
                .single()
                .execute()
            )

            if not response.data:
                return 0

            return response.data.get("helpful_count", 0)
        except Exception as e:
            logger.error("get_helpful_count_error", error=str(e))
            return 0

    # ========== REACTION METHODS ==========

    @supabase_breaker
    async def check_user_reacted(self, portfolio_id: str, user_id: str) -> bool:
        """Check if user has reacted to a portfolio."""
        try:
            response = (
                self.client.table("reactions")
                .select("id")
                .eq("portfolio_id", portfolio_id)
                .eq("user_id", user_id)
                .is_("deleted_at", "null")
                .execute()
            )

            return response.data is not None and len(response.data) > 0
        except Exception as e:
            logger.error("check_user_reacted_error", error=str(e))
            return False

    @supabase_breaker
    async def add_reaction(self, portfolio_id: str, user_id: str) -> bool:
        """Add a reaction to a portfolio."""
        try:
            response = (
                self.client.table("reactions")
                .insert(
                    {
                        "portfolio_id": portfolio_id,
                        "user_id": user_id,
                        "reaction_type": "upvote",
                    }
                )
                .execute()
            )

            logger.info("reaction_added_db", portfolio_id=portfolio_id, user_id=user_id)
            return True
        except Exception as e:
            logger.error("add_reaction_error", error=str(e))
            raise SupabaseError(f"Failed to add reaction: {str(e)}")

    @supabase_breaker
    async def remove_reaction(self, portfolio_id: str, user_id: str) -> bool:
        """Remove a reaction from a portfolio (soft delete)."""
        try:
            from datetime import datetime

            response = (
                self.client.table("reactions")
                .update({"deleted_at": datetime.utcnow().isoformat()})
                .eq("portfolio_id", portfolio_id)
                .eq("user_id", user_id)
                .is_("deleted_at", "null")
                .execute()
            )

            logger.info(
                "reaction_removed_db", portfolio_id=portfolio_id, user_id=user_id
            )
            return True
        except Exception as e:
            logger.error("remove_reaction_error", error=str(e))
            raise SupabaseError(f"Failed to remove reaction: {str(e)}")

    @supabase_breaker
    async def get_reaction_count(self, portfolio_id: str) -> int:
        """Get the count of reactions for a portfolio."""
        try:
            response = (
                self.client.table("reactions")
                .select("id", count="exact")
                .eq("portfolio_id", portfolio_id)
                .is_("deleted_at", "null")
                .execute()
            )

            return response.count or 0
        except Exception as e:
            logger.error("get_reaction_count_error", error=str(e))
            return 0

    # ========== LEADERBOARD METHODS ==========

    @supabase_breaker
    async def get_contribution_leaderboard(
        self, time_range: str = "all_time", limit: int = 100, offset: int = 0
    ) -> list[Dict[str, Any]]:
        """
        Get contribution leaderboard ranked by opinion count + helpful votes.

        Contribution score = opinion_count + helpful_votes_received

        This is a simplified implementation that calculates scores in Python.
        For production, this should be a Postgres stored function for performance.
        """
        try:
            # Get all users with their comments and helpful counts
            # First get comments with time filtering
            comments_query = (
                self.client.table("comments")
                .select("user_id, helpful_count, created_at")
                .is_("deleted_at", "null")
            )

            # Add time range filter
            if time_range == "daily":
                from datetime import datetime, timedelta

                cutoff = (datetime.utcnow() - timedelta(days=1)).isoformat()
                comments_query = comments_query.gte("created_at", cutoff)
            elif time_range == "weekly":
                from datetime import datetime, timedelta

                cutoff = (datetime.utcnow() - timedelta(days=7)).isoformat()
                comments_query = comments_query.gte("created_at", cutoff)
            elif time_range == "monthly":
                from datetime import datetime, timedelta

                cutoff = (datetime.utcnow() - timedelta(days=30)).isoformat()
                comments_query = comments_query.gte("created_at", cutoff)

            comments_response = comments_query.execute()

            if not comments_response.data:
                return []

            # Aggregate contributions by user
            user_contributions = {}
            for comment in comments_response.data:
                user_id = comment["user_id"]
                if user_id not in user_contributions:
                    user_contributions[user_id] = {
                        "opinion_count": 0,
                        "helpful_votes_received": 0,
                    }
                user_contributions[user_id]["opinion_count"] += 1
                user_contributions[user_id]["helpful_votes_received"] += comment.get(
                    "helpful_count", 0
                )

            # Get user profiles
            user_ids = list(user_contributions.keys())
            if not user_ids:
                return []

            profiles_response = (
                self.client.table("profiles")
                .select("id, username, avatar_url")
                .in_("id", user_ids)
                .execute()
            )

            # Build leaderboard entries
            leaderboard = []
            for profile in profiles_response.data:
                user_id = profile["id"]
                contrib = user_contributions[user_id]
                leaderboard.append(
                    {
                        "user_id": user_id,
                        "username": profile["username"],
                        "avatar_url": profile.get("avatar_url"),
                        "opinion_count": contrib["opinion_count"],
                        "helpful_votes_received": contrib["helpful_votes_received"],
                        "contribution_score": contrib["opinion_count"]
                        + contrib["helpful_votes_received"],
                    }
                )

            # Sort by contribution score descending
            leaderboard.sort(
                key=lambda x: (x["contribution_score"], x["opinion_count"]),
                reverse=True,
            )

            # Apply pagination and add rank
            paginated = leaderboard[offset : offset + limit]
            for idx, entry in enumerate(paginated):
                entry["rank"] = offset + idx + 1

            logger.info(
                "contribution_leaderboard_fetched",
                count=len(paginated),
                time_range=time_range,
            )
            return paginated

        except Exception as e:
            logger.error("get_contribution_leaderboard_error", error=str(e))
            # Return empty leaderboard on error rather than raising
            return []

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def update_last_upload_date(self, user_id: str) -> None:
        """Update last_upload_date to NOW for access control."""
        try:
            self.client.table("profiles").update({"last_upload_date": "now()"}).eq(
                "id", user_id
            ).execute()
            logger.info("last_upload_date_updated", user_id=user_id)
        except Exception as e:
            logger.error("update_last_upload_date_error", user_id=user_id, error=str(e))

    # ============ Login Attempt Tracking (Issue #22) ============

    @supabase_breaker
    async def record_login_attempt(
        self, email: str, ip_address: str, user_agent: str, success: bool
    ) -> None:
        """Record a login attempt for brute-force protection."""
        try:
            self.client.table("login_attempts").insert(
                {
                    "email": email,
                    "ip_address": ip_address,
                    "user_agent": user_agent,
                    "success": success,
                }
            ).execute()
            logger.info(
                "login_attempt_recorded",
                email=email,
                success=success,
                ip_address=ip_address,
            )
        except Exception as e:
            # Don't fail login if tracking fails
            logger.error("record_login_attempt_error", email=email, error=str(e))

    @supabase_breaker
    async def count_failed_login_attempts(
        self, email: str, minutes_window: int = 15
    ) -> int:
        """Count failed login attempts in the last N minutes."""
        try:
            # Use the database function for accurate time-based counting
            result = self.client.rpc(
                "count_failed_login_attempts",
                {"target_email": email, "minutes_window": minutes_window},
            ).execute()
            count = result.data if isinstance(result.data, int) else 0
            logger.debug("failed_attempts_counted", email=email, count=count)
            return count
        except Exception as e:
            logger.error("count_failed_attempts_error", email=email, error=str(e))
            # Return 0 on error to avoid blocking legitimate users
            return 0

    @supabase_breaker
    async def clear_failed_login_attempts(self, email: str) -> None:
        """Clear failed login attempts after successful login."""
        try:
            self.client.rpc(
                "clear_failed_login_attempts", {"target_email": email}
            ).execute()
            logger.info("failed_attempts_cleared", email=email)
        except Exception as e:
            # Don't fail login if cleanup fails
            logger.error("clear_failed_attempts_error", email=email, error=str(e))

    # ============ Portfolio Files Tracking ============

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def create_portfolio_file(self, file_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new file tracking record. Raises SupabaseError on failure."""
        try:
            response = (
                self.client.table("portfolio_files")
                .insert(file_data)
                .execute()
            )
            if response.data and len(response.data) > 0:
                logger.info(
                    "portfolio_file_created",
                    file_id=response.data[0]["id"],
                    user_id=file_data.get("user_id"),
                    file_hash=file_data.get("file_hash"),
                )
                return response.data[0]
            raise SupabaseError("Failed to create portfolio file record")
        except Exception as e:
            logger.error("create_portfolio_file_error", error=str(e), file_data=file_data)
            raise SupabaseError(f"Failed to create portfolio file: {str(e)}")

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def update_file_status(
        self, file_id: str, status: str, **kwargs
    ) -> Dict[str, Any]:
        """Update file processing status and metadata. Raises SupabaseError on failure."""
        try:
            update_data = {"status": status, **kwargs}
            response = (
                self.client.table("portfolio_files")
                .update(update_data)
                .eq("id", file_id)
                .execute()
            )
            if response.data and len(response.data) > 0:
                logger.info(
                    "file_status_updated",
                    file_id=file_id,
                    status=status,
                    updates=list(kwargs.keys()),
                )
                return response.data[0]
            raise SupabaseError(f"File not found: {file_id}")
        except Exception as e:
            logger.error("update_file_status_error", file_id=file_id, error=str(e))
            raise SupabaseError(f"Failed to update file status: {str(e)}")

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def get_file_by_id(self, file_id: str) -> Dict[str, Any]:
        """Get file record by ID. Raises SupabaseError if not found."""
        try:
            response = (
                self.client.table("portfolio_files")
                .select("*")
                .eq("id", file_id)
                .single()
                .execute()
            )
            if not response.data:
                raise SupabaseError(f"File not found: {file_id}")
            
            # Convert to dict if it's a Pydantic model
            data = response.data
            if hasattr(data, 'model_dump'):
                return data.model_dump()
            elif hasattr(data, 'dict'):
                return data.dict()
            elif isinstance(data, dict):
                return data
            else:
                return dict(data)
        except Exception as e:
            logger.error("get_file_by_id_error", file_id=file_id, error=str(e))
            raise SupabaseError(f"Failed to get file: {str(e)}")

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def get_user_files(
        self,
        user_id: str,
        status: Optional[str] = None,
        include_deleted: bool = False,
        offset: int = 0,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Get all files for a user with optional filtering."""
        try:
            query = (
                self.client.table("portfolio_files")
                .select("*")
                .eq("user_id", user_id)
            )

            if not include_deleted:
                query = query.is_("deleted_at", "null")

            if status:
                query = query.eq("status", status)

            response = (
                query.order("uploaded_at", desc=True)
                .range(offset, offset + limit - 1)
                .execute()
            )

            logger.info(
                "user_files_fetched",
                user_id=user_id,
                count=len(response.data) if response.data else 0,
                status=status,
            )
            return response.data if response.data else []
        except Exception as e:
            logger.error("get_user_files_error", user_id=user_id, error=str(e))
            raise SupabaseError(f"Failed to get user files: {str(e)}")

    @supabase_breaker
    async def check_file_hash_exists(
        self, user_id: str, file_hash: str
    ) -> Optional[Dict[str, Any]]:
        """Check if a file with this hash already exists for the user (early deduplication).
        
        Only returns files that were successfully processed (completed status).
        Failed uploads are allowed to retry with the same file.
        """
        try:
            response = (
                self.client.table("portfolio_files")
                .select("id, uploaded_at, status, snapshot_id")
                .eq("user_id", user_id)
                .eq("file_hash", file_hash)
                .eq("status", "completed")  # Only block if previous upload succeeded
                .is_("deleted_at", "null")
                .execute()
            )

            if response.data and len(response.data) > 0:
                logger.info(
                    "duplicate_file_detected",
                    user_id=user_id,
                    file_hash=file_hash,
                    existing_file_id=response.data[0]["id"],
                )
                return response.data[0]
            return None
        except Exception as e:
            logger.error("check_file_hash_error", error=str(e))
            return None

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def soft_delete_file(
        self, file_id: str, delete_reason: str = "user_requested"
    ) -> Dict[str, Any]:
        """Soft delete a file record. Raises SupabaseError on failure."""
        try:
            response = (
                self.client.table("portfolio_files")
                .update({"deleted_at": "now()", "delete_reason": delete_reason})
                .eq("id", file_id)
                .execute()
            )
            if response.data and len(response.data) > 0:
                logger.info(
                    "file_soft_deleted", file_id=file_id, delete_reason=delete_reason
                )
                return response.data[0]
            raise SupabaseError(f"File not found: {file_id}")
        except Exception as e:
            logger.error("soft_delete_file_error", file_id=file_id, error=str(e))
            raise SupabaseError(f"Failed to delete file: {str(e)}")

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def count_user_files(
        self, user_id: str, status: Optional[str] = None, include_deleted: bool = False
    ) -> int:
        """Count total files for a user with optional filtering."""
        try:
            query = (
                self.client.table("portfolio_files")
                .select("id", count="exact")
                .eq("user_id", user_id)
            )

            if not include_deleted:
                query = query.is_("deleted_at", "null")

            if status:
                query = query.eq("status", status)

            response = query.execute()
            return response.count if response.count is not None else 0
        except Exception as e:
            logger.error("count_user_files_error", user_id=user_id, error=str(e))
            return 0


    # ============================================================================
    # INSTRUMENTS METHODS
    # ============================================================================

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def search_instruments(
        self, query: str, limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Search instruments by symbol or name across all symbols."""
        try:
            # Search in instruments table by name or primary_symbol
            instruments_response = (
                self.client.table("instruments")
                .select("id, name, asset_type, primary_symbol, current_price")
                .or_(f"name.ilike.%{query}%,primary_symbol.ilike.%{query}%")
                .eq("active", True)
                .limit(limit)
                .execute()
            )
            
            # Also search in instrument_symbols table
            symbols_response = (
                self.client.table("instrument_symbols")
                .select("instrument_id, symbol, instruments(id, name, asset_type, primary_symbol, current_price)")
                .ilike("symbol", f"%{query}%")
                .limit(limit)
                .execute()
            )
            
            # Combine and deduplicate results
            results = {}
            for inst in instruments_response.data:
                results[inst["id"]] = {
                    "id": inst["id"],
                    "name": inst["name"],
                    "asset_type": inst["asset_type"],
                    "primary_symbol": inst["primary_symbol"],
                    "current_price": inst.get("current_price"),
                    "all_symbols": [inst["primary_symbol"]],
                }
            
            for sym in symbols_response.data:
                if sym.get("instruments"):
                    inst = sym["instruments"]
                    if inst["id"] not in results:
                        results[inst["id"]] = {
                            "id": inst["id"],
                            "name": inst["name"],
                            "asset_type": inst["asset_type"],
                            "primary_symbol": inst["primary_symbol"],
                            "current_price": inst.get("current_price"),
                            "all_symbols": [inst["primary_symbol"]],
                        }
                    if sym["symbol"] not in results[inst["id"]]["all_symbols"]:
                        results[inst["id"]]["all_symbols"].append(sym["symbol"])
            
            return list(results.values())[:limit]
        except Exception as e:
            logger.error("search_instruments_error", error=str(e), query=query)
            raise SupabaseError(f"Failed to search instruments: {str(e)}")

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def get_instrument_by_symbol(self, symbol: str) -> Optional[Dict[str, Any]]:
        """Get instrument by any symbol (primary or alternate)."""
        try:
            # First try to find the symbol in instrument_symbols
            sym_response = (
                self.client.table("instrument_symbols")
                .select("instrument_id")
                .eq("symbol", symbol)
                .limit(1)
                .execute()
            )
            
            instrument_id = None
            if sym_response.data:
                instrument_id = sym_response.data[0]["instrument_id"]
            else:
                # Try primary_symbol in instruments table
                inst_response = (
                    self.client.table("instruments")
                    .select("id")
                    .eq("primary_symbol", symbol)
                    .eq("active", True)
                    .limit(1)
                    .execute()
                )
                if inst_response.data:
                    instrument_id = inst_response.data[0]["id"]
            
            if not instrument_id:
                return None
            
            return await self.get_instrument_by_id(instrument_id)
        except Exception as e:
            logger.error("get_instrument_by_symbol_error", error=str(e), symbol=symbol)
            raise SupabaseError(f"Failed to get instrument: {str(e)}")

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def get_instrument_by_id(self, instrument_id: str) -> Optional[Dict[str, Any]]:
        """Get instrument by ID with all symbols."""
        try:
            # Get instrument
            inst_response = (
                self.client.table("instruments")
                .select("*")
                .eq("id", instrument_id)
                .eq("active", True)
                .limit(1)
                .execute()
            )
            
            if not inst_response.data:
                return None
            
            instrument = inst_response.data[0]
            
            # Get all symbols
            symbols_response = (
                self.client.table("instrument_symbols")
                .select("*")
                .eq("instrument_id", instrument_id)
                .execute()
            )
            
            instrument["symbols"] = symbols_response.data
            return instrument
        except Exception as e:
            logger.error("get_instrument_by_id_error", error=str(e), instrument_id=instrument_id)
            raise SupabaseError(f"Failed to get instrument: {str(e)}")

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def add_instrument_symbol(
        self, instrument_id: str, symbol: str, exchange: str, source: str, is_primary: bool = False
    ) -> Dict[str, Any]:
        """Add a new symbol to an instrument."""
        try:
            response = (
                self.client.table("instrument_symbols")
                .insert({
                    "instrument_id": instrument_id,
                    "symbol": symbol,
                    "exchange": exchange,
                    "source": source,
                    "is_primary": is_primary,
                })
                .execute()
            )
            
            if response.data:
                logger.info("instrument_symbol_added", instrument_id=instrument_id, symbol=symbol)
                return response.data[0]
            raise SupabaseError("Failed to add symbol")
        except Exception as e:
            logger.error("add_instrument_symbol_error", error=str(e))
            raise SupabaseError(f"Failed to add symbol: {str(e)}")

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def get_instrument_symbol(self, symbol_id: str) -> Optional[Dict[str, Any]]:
        """Get instrument symbol by ID."""
        try:
            response = (
                self.client.table("instrument_symbols")
                .select("*")
                .eq("id", symbol_id)
                .limit(1)
                .execute()
            )
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error("get_instrument_symbol_error", error=str(e))
            return None

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def delete_instrument_symbol(self, symbol_id: str) -> None:
        """Delete an instrument symbol."""
        try:
            self.client.table("instrument_symbols").delete().eq("id", symbol_id).execute()
            logger.info("instrument_symbol_deleted", symbol_id=symbol_id)
        except Exception as e:
            logger.error("delete_instrument_symbol_error", error=str(e))
            raise SupabaseError(f"Failed to delete symbol: {str(e)}")

    # ============================================================================
    # OPINIONS METHODS (Instrument-scoped)
    # ============================================================================

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def create_opinion(
        self,
        user_id: str,
        instrument_id: str,
        content: str,
        opinion_type: str,
        parent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new opinion on an instrument."""
        try:
            response = (
                self.client.table("opinions")
                .insert({
                    "user_id": user_id,
                    "instrument_id": instrument_id,
                    "content": content,
                    "opinion_type": opinion_type,
                    "parent_id": parent_id,
                })
                .execute()
            )
            
            if response.data:
                opinion = response.data[0]
                # Fetch user details
                user_response = (
                    self.client.table("profiles")
                    .select("username, avatar_url, reputation_tier")
                    .eq("id", user_id)
                    .limit(1)
                    .execute()
                )
                if user_response.data:
                    opinion["username"] = user_response.data[0]["username"]
                    opinion["avatar_url"] = user_response.data[0].get("avatar_url")
                    opinion["reputation_tier"] = user_response.data[0].get("reputation_tier")
                
                logger.info("opinion_created", opinion_id=opinion["id"])
                return opinion
            raise SupabaseError("Failed to create opinion")
        except Exception as e:
            logger.error("create_opinion_error", error=str(e))
            raise SupabaseError(f"Failed to create opinion: {str(e)}")

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def get_opinion_by_id(self, opinion_id: str) -> Optional[Dict[str, Any]]:
        """Get opinion by ID."""
        try:
            response = (
                self.client.table("opinions")
                .select("*, profiles(username, avatar_url, reputation_tier)")
                .eq("id", opinion_id)
                .is_("deleted_at", "null")
                .limit(1)
                .execute()
            )
            
            if response.data:
                opinion = response.data[0]
                if opinion.get("profiles"):
                    opinion["username"] = opinion["profiles"]["username"]
                    opinion["avatar_url"] = opinion["profiles"].get("avatar_url")
                    opinion["reputation_tier"] = opinion["profiles"].get("reputation_tier")
                    del opinion["profiles"]
                return opinion
            return None
        except Exception as e:
            logger.error("get_opinion_by_id_error", error=str(e))
            return None

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def get_all_opinions(
        self,
        opinion_type: Optional[str] = None,
        sort_by: str = "newest",
        page: int = 1,
        page_size: int = 20,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get all opinions across all instruments with pagination and filtering."""
        try:
            offset = (page - 1) * page_size

            query = (
                self.client.table("opinions")
                .select("*, instruments(primary_symbol, name)", count="exact")
                .is_("deleted_at", "null")
                .eq("moderation_status", "visible")
                .is_("parent_id", "null")
            )

            if opinion_type:
                query = query.eq("opinion_type", opinion_type)

            if sort_by == "most_helpful":
                query = query.order("helpful_count", desc=True)
            else:
                query = query.order("created_at", desc=True)

            query = query.range(offset, offset + page_size - 1)
            response = query.execute()

            opinions = []
            for op in response.data:
                profile = await self.get_user_profile(op["user_id"])
                op["username"] = profile.get("username", "Anonymous")
                op["avatar_url"] = profile.get("avatar_url")
                op["reputation_tier"] = profile.get("reputation_tier", "beginner")

                if op.get("instruments"):
                    op["instrument_symbol"] = op["instruments"].get("primary_symbol")
                    op["instrument_name"] = op["instruments"].get("name")
                    del op["instruments"]
                else:
                    op["instrument_symbol"] = None
                    op["instrument_name"] = None

                if user_id:
                    vote_response = (
                        self.client.table("opinion_helpful_votes")
                        .select("id")
                        .eq("opinion_id", op["id"])
                        .eq("user_id", user_id)
                        .limit(1)
                        .execute()
                    )
                    op["has_voted"] = len(vote_response.data) > 0
                else:
                    op["has_voted"] = False

                op["replies"] = await self._get_opinion_replies(op["id"], user_id)
                opinions.append(op)

            return {
                "opinions": opinions,
                "total": response.count or 0,
                "page": page,
                "page_size": page_size,
            }
        except Exception as e:
            logger.error("get_all_opinions_error", error=str(e))
            raise SupabaseError(f"Failed to get opinions: {str(e)}")

    async def get_instrument_opinions(
        self,
        instrument_id: str,
        opinion_type: Optional[str] = None,
        sort_by: str = "newest",
        page: int = 1,
        page_size: int = 20,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get opinions for an instrument with pagination and filtering."""
        try:
            offset = (page - 1) * page_size
            
            # Build query
            query = (
                self.client.table("opinions")
                .select("*", count="exact")
                .eq("instrument_id", instrument_id)
                .is_("deleted_at", "null")
                .eq("moderation_status", "visible")
                .is_("parent_id", "null")
            )
            
            if opinion_type:
                query = query.eq("opinion_type", opinion_type)
            
            # Sort
            if sort_by == "most_helpful":
                query = query.order("helpful_count", desc=True)
            else:  # newest
                query = query.order("created_at", desc=True)
            
            query = query.range(offset, offset + page_size - 1)
            response = query.execute()
            
            opinions = []
            for op in response.data:
                profile = await self.get_user_profile(op["user_id"])
                op["username"] = profile.get("username", "Anonymous")
                op["avatar_url"] = profile.get("avatar_url")
                op["reputation_tier"] = profile.get("reputation_tier", "beginner")

                if user_id:
                    vote_response = (
                        self.client.table("opinion_helpful_votes")
                        .select("id")
                        .eq("opinion_id", op["id"])
                        .eq("user_id", user_id)
                        .limit(1)
                        .execute()
                    )
                    op["has_voted"] = len(vote_response.data) > 0
                else:
                    op["has_voted"] = False
                
                # Get replies
                op["replies"] = await self._get_opinion_replies(op["id"], user_id)
                opinions.append(op)
            
            return {
                "opinions": opinions,
                "total": response.count or 0,
                "page": page,
                "page_size": page_size,
            }
        except Exception as e:
            logger.error("get_instrument_opinions_error", error=str(e))
            raise SupabaseError(f"Failed to get opinions: {str(e)}")

    async def _get_opinion_replies(
        self, parent_id: str, user_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get replies for an opinion (recursive up to depth 3)."""
        try:
            response = (
                self.client.table("opinions")
                .select("*")
                .eq("parent_id", parent_id)
                .is_("deleted_at", "null")
                .eq("moderation_status", "visible")
                .order("created_at", desc=False)
                .execute()
            )
            
            replies = []
            for reply in response.data:
                profile = await self.get_user_profile(reply["user_id"])
                reply["username"] = profile.get("username", "Anonymous")
                reply["avatar_url"] = profile.get("avatar_url")
                reply["reputation_tier"] = profile.get("reputation_tier", "beginner")
                
                # Check if user has voted
                if user_id:
                    vote_response = (
                        self.client.table("opinion_helpful_votes")
                        .select("id")
                        .eq("opinion_id", reply["id"])
                        .eq("user_id", user_id)
                        .limit(1)
                        .execute()
                    )
                    reply["has_voted"] = len(vote_response.data) > 0
                else:
                    reply["has_voted"] = False
                
                # Recursively get nested replies (up to depth 3)
                if reply.get("thread_depth", 0) < 3:
                    reply["replies"] = await self._get_opinion_replies(reply["id"], user_id)
                else:
                    reply["replies"] = []
                
                replies.append(reply)
            
            return replies
        except Exception as e:
            logger.error("get_opinion_replies_error", error=str(e))
            return []

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def toggle_opinion_helpful_vote(
        self, opinion_id: str, user_id: str
    ) -> Dict[str, Any]:
        """Toggle helpful vote on an opinion."""
        try:
            # Check if vote exists
            existing = (
                self.client.table("opinion_helpful_votes")
                .select("id")
                .eq("opinion_id", opinion_id)
                .eq("user_id", user_id)
                .limit(1)
                .execute()
            )
            
            if existing.data:
                # Remove vote
                self.client.table("opinion_helpful_votes").delete().eq("id", existing.data[0]["id"]).execute()
                return {"action": "removed", "opinion_id": opinion_id}
            else:
                # Add vote
                self.client.table("opinion_helpful_votes").insert({
                    "opinion_id": opinion_id,
                    "user_id": user_id,
                }).execute()
                return {"action": "added", "opinion_id": opinion_id}
        except Exception as e:
            logger.error("toggle_opinion_helpful_vote_error", error=str(e))
            raise SupabaseError(f"Failed to toggle vote: {str(e)}")

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def delete_opinion(self, opinion_id: str) -> None:
        """Soft delete an opinion."""
        try:
            self.client.table("opinions").update({"deleted_at": "now()"}).eq("id", opinion_id).execute()
            logger.info("opinion_deleted", opinion_id=opinion_id)
        except Exception as e:
            logger.error("delete_opinion_error", error=str(e))
            raise SupabaseError(f"Failed to delete opinion: {str(e)}")

    # ============================================================================
    # PORTFOLIO REVIEWS METHODS (reviews table, portfolio-scoped reviews)
    # ============================================================================

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def list_portfolio_reviews(
        self, portfolio_id: str, offset: int = 0, limit: int = 20
    ) -> tuple:
        """List reviews (reviews table) for a portfolio.
        Returns (reviews_list, total_count)."""
        try:
            response = (
                self.client.table("reviews")
                .select("*", count="exact")
                .eq("portfolio_id", portfolio_id)
                .is_("deleted_at", "null")
                .order("helpful_count", desc=True)
                .order("created_at", desc=True)
                .range(offset, offset + limit - 1)
                .execute()
            )
            return response.data or [], response.count or 0
        except Exception as e:
            logger.error("list_portfolio_reviews_error", error=str(e), portfolio_id=portfolio_id)
            raise SupabaseError(f"Failed to list portfolio reviews: {str(e)}")

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def list_recent_opinions(
        self, page: int = 1, page_size: int = 20
    ) -> tuple:
        """List recent opinions (from opinions table).
        Returns (opinions_list, total_count)."""
        try:
            offset = (page - 1) * page_size
            response = (
                self.client.table("opinions")
                .select("*, instruments(primary_symbol, name)", count="exact")
                .is_("deleted_at", "null")
                .eq("moderation_status", "visible")
                .is_("parent_id", "null")
                .order("created_at", desc=True)
                .range(offset, offset + page_size - 1)
                .execute()
            )
            return response.data or [], response.count or 0
        except Exception as e:
            logger.error("list_recent_opinions_error", error=str(e))
            raise SupabaseError(f"Failed to list recent opinions: {str(e)}")

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def create_review(
        self, portfolio_id: str, user_id: str, content: str, opinion_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a new review on a portfolio (reviews table)."""
        try:
            row: Dict[str, Any] = {
                "user_id": user_id,
                "portfolio_id": portfolio_id,
                "content": content,
            }
            if opinion_type:
                row["opinion_type"] = opinion_type
            response = self.client.table("reviews").insert(row).execute()

            if response.data:
                review = response.data[0]
                user_response = (
                    self.client.table("profiles")
                    .select("username, avatar_url, reputation_tier")
                    .eq("id", user_id)
                    .limit(1)
                    .execute()
                )
                if user_response.data:
                    review["username"] = user_response.data[0]["username"]
                    review["avatar_url"] = user_response.data[0].get("avatar_url")
                    review["reputation_tier"] = user_response.data[0].get("reputation_tier")
                logger.info("portfolio_review_created", review_id=review["id"])
                return review
            raise SupabaseError("Failed to create portfolio review")
        except Exception as e:
            logger.error("create_review_error", error=str(e))
            raise SupabaseError(f"Failed to create portfolio review: {str(e)}")

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def get_portfolio_reviews(
        self, portfolio_id: str, page: int = 1, page_size: int = 20
    ) -> Dict[str, Any]:
        """Get reviews for a portfolio with pagination."""
        try:
            offset = (page - 1) * page_size
            
            response = (
                self.client.table("reviews")
                .select("*", count="exact")
                .eq("portfolio_id", portfolio_id)
                .is_("deleted_at", "null")
                .order("created_at", desc=True)
                .range(offset, offset + page_size - 1)
                .execute()
            )
            
            reviews = []
            for review in response.data:
                user_profile = await self.get_user_profile(review["user_id"])
                review["username"] = user_profile.get("username", "Unknown")
                review["avatar_url"] = user_profile.get("avatar_url")
                review["reputation_tier"] = user_profile.get("reputation_tier", "beginner")
                reviews.append(review)
            
            return {
                "reviews": reviews,
                "total": response.count or 0,
                "page": page,
                "page_size": page_size,
            }
        except Exception as e:
            logger.error("get_portfolio_reviews_error", error=str(e))
            raise SupabaseError(f"Failed to get reviews: {str(e)}")

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def get_review_by_id(self, review_id: str) -> Optional[Dict[str, Any]]:
        """Get review by ID."""
        try:
            response = (
                self.client.table("reviews")
                .select("*")
                .eq("id", review_id)
                .is_("deleted_at", "null")
                .limit(1)
                .execute()
            )
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error("get_review_by_id_error", error=str(e))
            return None

    @supabase_breaker
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3)
    )
    async def delete_review(self, review_id: str) -> None:
        """Soft delete a review."""
        try:
            self.client.table("reviews").update({"deleted_at": "now()"}).eq("id", review_id).execute()
            logger.info("review_deleted", review_id=review_id)
        except Exception as e:
            logger.error("delete_review_error", error=str(e))
            raise SupabaseError(f"Failed to delete review: {str(e)}")


supabase_client = SupabaseClient()
