from datetime import timedelta, datetime, timezone

import structlog
from app.api.dependencies import get_current_user
from app.core.config import settings
from app.core.security import security
from app.services.auth.auth_session_service import (
    create_auth_session,
    derive_initial_session_state,
    get_session_id_from_token,
    get_session_machine,
    save_session_state,
    signout_all_user_sessions,
)
from app.domain.schemas import (
    ErrorResponse,
    GoogleAuthRequest,
    TokenResponse,
    UserProfile,
    UserSignin,
    UserSignup,
)
from app.infrastructure.supabase_client import supabase_client
from app.utils.access_control import get_access_info
from app.utils.auth_validation import validate_auth_inputs, validate_email
from app.utils.sanitize import sanitize_html, sanitize_plain_text
from app.utils.username_generator import generate_username
from app.utils.username_validation import validate_username
from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

logger = structlog.get_logger()
router = APIRouter(prefix="/auth", tags=["Authentication"])

# OAuth client for Google
oauth = OAuth()
oauth.register(
    name="google",
    client_id=settings.google_client_id,
    client_secret=settings.google_client_secret,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


@router.post(
    "/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED
)
@limiter.limit(
    f"{settings.rate_limit_auth_requests}/{settings.rate_limit_auth_period} seconds"
)
async def signup(request: Request, user_data: UserSignup):
    """
    Register a new user with email and password.
    Automatically generates a Reddit-style anonymous username (e.g., BraveShark472).
    Retries if collision occurs (extremely rare with 100M+ combinations).
    """
    try:
        # Validate email and password on backend (defense in depth)
        is_valid, error_msg = validate_auth_inputs(user_data.email, user_data.password)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_msg,
            )

        # Generate unique username with retry logic
        max_attempts = 5
        username = None

        for attempt in range(max_attempts):
            candidate = generate_username()
            # Check if username already exists
            exists = await supabase_client.check_username_exists(candidate)
            if not exists:
                username = candidate
                break

        if not username:
            # Fallback: add extra random digits (should never happen)
            import random

            username = f"{generate_username()}{random.randint(10, 99)}"

        logger.info("generated_username", username=username, attempts=attempt + 1)

        # Create user in Supabase
        result = await supabase_client.signup_user(
            email=user_data.email, password=user_data.password, username=username
        )

        if not result or not result.get("user"):
            logger.error(
                "signup_failed",
                email=user_data.email,
                username=username,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to create user account",
            )
        
        logger.info(
            "user_signup_successful",
            user_id=result["user"]["id"],
            username=username,
        )

        # Use Supabase session token
        if not result.get("session"):
            logger.info(
                "signup_email_confirmation_required",
                user_id=result["user"]["id"],
                email=user_data.email,
            )
            return JSONResponse(
                status_code=status.HTTP_202_ACCEPTED,
                content={
                    "email_confirmation_required": True,
                    "message": "Account created! Please check your email to confirm your account before signing in.",
                    "email": user_data.email,
                },
            )

        logger.info("user_signup_success", email=user_data.email, username=username)

        # Create auth session with state machine
        session_id = get_session_id_from_token(result["session"]["access_token"])
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=result["session"]["expires_in"])
        
        # New users start in needs_consent state (username is auto-generated during signup)
        await create_auth_session(
            session_id=session_id,
            user_id=result["user"]["id"],
            state="needs_consent",
            expires_at=expires_at,
            supabase_client=supabase_client
        )

        # New users get 60 days to upload first portfolio
        return TokenResponse(
            access_token=result["session"]["access_token"],
            token_type="bearer",
            expires_in=result["session"]["expires_in"],
            refresh_token=result["session"].get("refresh_token"),
            user={
                "id": result["user"]["id"],
                "email": user_data.email,
                "username": username,
                "privacy_consent_given": False,
                "onboarding_completed": False,
                "avatar_url": None,
            },
            access_status="active",
            days_until_restricted=60,
        )

    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e).lower()

        # Handle "user already registered" gracefully
        if "already registered" in error_msg or "user already exists" in error_msg:
            logger.info("signup_attempt_existing_user", email=user_data.email)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An account with this email already exists. Please sign in instead.",
            )

        # Handle Supabase email rate limit
        if "email rate limit" in error_msg or "over_email_send_rate_limit" in error_msg or "rate limit" in error_msg:
            logger.warning("signup_email_rate_limit", email=user_data.email)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many signup attempts. Please wait a few minutes and try again.",
            )

        # Handle invalid email (Supabase email validation)
        if "email address" in error_msg and "invalid" in error_msg:
            logger.info("signup_invalid_email", email=user_data.email)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This email address is not accepted. Please use a valid email address.",
            )

        # Handle other errors
        logger.error("signup_error", email=user_data.email, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to create account. Please try again or contact support.",
        )


@router.post("/signin", response_model=TokenResponse)
@limiter.limit(
    f"{settings.rate_limit_auth_requests}/{settings.rate_limit_auth_period} seconds"
)
async def signin(request: Request, user_data: UserSignin):
    """
    Sign in with email and password
    """
    # Get client info for logging
    ip_address = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    try:
        # Validate email format on backend (defense in depth)
        is_valid, error_msg = validate_email(user_data.email)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_msg,
            )

        # Check for account lockout (Issue #22)
        failed_attempts = await supabase_client.count_failed_login_attempts(
            user_data.email, minutes_window=15
        )
        if failed_attempts >= 5:
            logger.warning(
                "account_locked",
                email=user_data.email,
                failed_attempts=failed_attempts,
                ip_address=ip_address,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Account temporarily locked due to too many failed attempts. Please try again in 15 minutes.",
            )

        # Authenticate with Supabase
        result = await supabase_client.signin_user(
            email=user_data.email, password=user_data.password
        )

        if not result or not result.get("user"):
            # Log failed attempt
            await supabase_client.log_failed_login_attempt(user_data.email)
            logger.warning(
                "signin_failed",
                email=user_data.email,
                ip_address=ip_address,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )

        # Use Supabase session token
        if not result.get("session"):
            logger.error(
                "signin_session_creation_failed",
                user_id=result["user"]["id"],
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Failed to create session",
            )
        
        logger.info(
            "user_signin_successful",
            user_id=result["user"]["id"],
        )

        # Check if email is verified (DISABLED FOR DEVELOPMENT)
        # user_metadata = result["user"].get("user_metadata", {})
        # email_confirmed = result["user"].get("email_confirmed_at")

        # if not email_confirmed:
        #     logger.warning("signin_unverified_email", email=user_data.email)
        #     raise HTTPException(
        #         status_code=status.HTTP_403_FORBIDDEN,
        #         detail="Please verify your email before signing in. Check your inbox for the verification link.",
        #     )

        logger.info("user_signin_success", email=user_data.email)

        # Record successful login and clear failed attempts (Issue #22)
        await supabase_client.record_login_attempt(
            email=user_data.email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
        )
        await supabase_client.clear_failed_login_attempts(user_data.email)

        # Fetch full profile data
        profile = await supabase_client.get_user_profile(result["user"]["id"])

        # Calculate access status based on last upload date
        profile_with_access = get_access_info(profile)

        # Create/update auth session with derived state
        session_id = get_session_id_from_token(result["session"]["access_token"])
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=result["session"]["expires_in"])
        
        # Derive initial state from user flags + portfolio freshness
        initial_state = await derive_initial_session_state(
            user_id=result["user"]["id"],
            supabase_client=supabase_client
        )
        
        await create_auth_session(
            session_id=session_id,
            user_id=result["user"]["id"],
            state=initial_state,
            expires_at=expires_at,
            supabase_client=supabase_client
        )

        return TokenResponse(
            access_token=result["session"]["access_token"],
            token_type="bearer",
            expires_in=result["session"]["expires_in"],
            refresh_token=result["session"].get("refresh_token"),
            user={
                "id": result["user"]["id"],
                "email": user_data.email,
                "username": profile.get("username") if profile else None,
                "privacy_consent_given": (
                    profile.get("privacy_consent_given", False) if profile else False
                ),
                "onboarding_completed": (
                    profile.get("onboarding_completed", False) if profile else False
                ),
                "avatar_url": profile.get("avatar_url") if profile else None,
            },
            access_status=profile_with_access["access_status"],
            days_until_restricted=profile_with_access["days_until_restricted"],
            days_until_blocked=profile_with_access["days_until_blocked"],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("signin_error", email=user_data.email, error=str(e))
        # Check if it's an invalid credentials error from Supabase
        error_msg = str(e).lower()
        if "invalid" in error_msg or "credentials" in error_msg or "password" in error_msg:
            detail = "Invalid email or password. Please try again."
        else:
            detail = "Unable to sign in. Please try again later."
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=detail
        )


@router.post("/google", response_model=TokenResponse)
async def google_auth(request: GoogleAuthRequest):
    """
    Authenticate with Google OAuth through Supabase
    """
    try:
        # Verify Google ID token
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token

        # Verify the token with Google
        idinfo = id_token.verify_oauth2_token(
            request.id_token, google_requests.Request(), settings.google_client_id
        )

        if idinfo["iss"] not in ["accounts.google.com", "https://accounts.google.com"]:
            raise ValueError("Invalid issuer.")

        email = idinfo.get("email")
        name = idinfo.get("name", "")
        picture = idinfo.get("picture", "")

        # Supabase sign_in_with_id_token handles both new and existing users automatically
        # It will create a new user if email doesn't exist, or sign in if it does
        # Generate Reddit-style username for new users
        username = generate_username()
        result = await supabase_client.signup_with_provider(
            provider="google",
            id_token=request.id_token,
            user_metadata={
                "username": username,
                "avatar_url": picture,
                "full_name": name,
            },
        )

        if not result or not result.get("session"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to authenticate with Google",
            )

        logger.info("google_auth_success", email=email)

        # Fetch profile for access control
        profile = await supabase_client.get_user_profile(result["user"]["id"])
        profile_with_access = get_access_info(profile)

        return TokenResponse(
            access_token=result["session"]["access_token"],
            token_type="bearer",
            expires_in=result["session"]["expires_in"],
            refresh_token=result["session"].get("refresh_token"),
            user={
                "id": result["user"]["id"],
                "email": email,
                "username": result["user"]["user_metadata"].get("username"),
                "privacy_consent_given": (
                    profile.get("privacy_consent_given", False) if profile else False
                ),
                "onboarding_completed": (
                    profile.get("onboarding_completed", False) if profile else False
                ),
                "avatar_url": picture,
            },
            access_status=profile_with_access["access_status"],
            days_until_restricted=profile_with_access["days_until_restricted"],
        )

    except ValueError as e:
        logger.error("google_auth_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Google token"
        )
    except Exception as e:
        logger.error("google_auth_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google authentication failed",
        )


@router.get("/me", response_model=UserProfile)
async def get_current_user_profile(current_user: dict = Depends(get_current_user)):
    """
    Get the current authenticated user's profile.

    Note: Domain exceptions from get_current_user dependency are caught here
    and converted to appropriate HTTP responses.
    """
    try:
        # current_user already includes email from get_current_user dependency
        # Ensure onboarding_completed and privacy_consent_given are explicitly set for frontend routing
        profile_data = {
            **current_user,
            "onboarding_completed": current_user.get("onboarding_completed", False),
            "privacy_consent_given": current_user.get("privacy_consent_given", False),
            "reputation_score": current_user.get("reputation_score", 0),
            "reputation_tier": current_user.get("reputation_tier", "newcomer"),
            "is_admin": current_user.get("is_admin", False),
        }
        return UserProfile(**profile_data)

    except HTTPException:
        # Re-raise HTTP exceptions from dependency
        raise
    except Exception as e:
        logger.error("get_profile_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch user profile",
        )


@router.put("/me")
async def update_current_user_profile(
    request: Request,
    profile_data: dict = Body(...),
    current_user: dict = Depends(get_current_user),
):
    try:
        if "username" in profile_data:
            profile_data["username"] = sanitize_plain_text(profile_data["username"])

        if "full_name" in profile_data:
            profile_data["full_name"] = sanitize_plain_text(profile_data["full_name"])

        if "bio" in profile_data:
            profile_data["bio"] = sanitize_html(profile_data["bio"])

        # If username is being set/confirmed, also set username_confirmed flag
        if "username" in profile_data:
            profile_data["username_confirmed"] = True

        result = await supabase_client.update_user_profile(
            user_id=current_user["id"], updates=profile_data
        )

        if not result:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to update profile",
            )

        # Fire state machine transitions based on what was updated
        session_id = current_user.get("session_id")
        if session_id:
            try:
                machine = await get_session_machine(session_id, current_user["id"], supabase_client)
                
                # Username confirmed → transition username_selection → needs_consent
                if "username" in profile_data and machine.current_state.id == "username_selection":
                    machine.confirm_username()
                    await save_session_state(machine, supabase_client)
                
                # Privacy consent given → transition needs_consent → active
                if profile_data.get("privacy_consent_given") and machine.current_state.id == "needs_consent":
                    machine.give_consent()
                    await save_session_state(machine, supabase_client)
                    
            except Exception as e:
                logger.warning("state_transition_failed", user_id=current_user["id"], error=str(e))

        logger.info("profile_updated", user_id=current_user["id"])
        return {"success": True, "message": "Profile updated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("update_profile_error", user_id=current_user["id"], error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update profile",
        )


@router.post("/signout")
async def signout(current_user: dict = Depends(get_current_user)):
    """
    Sign out the current user and revoke their session in Supabase.
    
    Session-scoped: Only affects THIS device/browser session.
    Other sessions remain active.

    This endpoint:
    - Updates session state to signed_out
    - Revokes the session in Supabase
    - Logs the signout event

    Note: The Next.js proxy will clear HttpOnly cookies after this call.
    """
    try:
        user_id = current_user.get("id")
        session_id = current_user.get("session_id")

        # Update session state to signed_out
        if session_id:
            try:
                machine = await get_session_machine(session_id, user_id, supabase_client)
                machine.signout()
                await save_session_state(machine, supabase_client)
            except Exception as e:
                logger.warning("session_state_update_failed", user_id=user_id, error=str(e))

        # Revoke the session in Supabase
        try:
            await supabase_client.signout_user()
        except Exception as e:
            logger.warning("supabase_signout_error", user_id=user_id, error=str(e))

        logger.info("user_signout_success", user_id=user_id)

        return {"message": "Signed out successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("signout_error", error=str(e))
        return {"message": "Signed out successfully"}


@router.post("/signout-all-devices")
async def signout_all_devices(current_user: dict = Depends(get_current_user)):
    """
    Sign out all sessions for the current user across all devices.
    
    User-level action: Affects ALL active sessions.
    Useful for security (e.g., lost device, suspicious activity).
    
    This endpoint:
    - Updates ALL user sessions to signed_out state
    - Revokes current Supabase session
    - Logs the action
    """
    try:
        user_id = current_user.get("id")
        
        # Update ALL sessions for this user to signed_out
        await signout_all_user_sessions(user_id, supabase_client)
        
        # Revoke current Supabase session
        try:
            await supabase_client.signout_user()
        except Exception as e:
            logger.warning("supabase_signout_error", user_id=user_id, error=str(e))
        
        logger.info("signout_all_devices", user_id=user_id)
        
        return {"message": "Signed out from all devices"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error("signout_all_devices_error", error=str(e))
        return {"message": "Signed out from all devices"}


@router.get("/session/state")
async def get_session_state(current_user: dict = Depends(get_current_user)):
    """
    Get current session state from state machine.
    
    Returns:
    - state: Current state (active, needs_username, etc.)
    - allowed_events: Events that can be triggered from current state
    - metadata: State-specific data
    """
    try:
        session_id = current_user.get("session_id")
        user_id = current_user.get("id")
        
        if not session_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Session ID not found"
            )
        
        machine = await get_session_machine(session_id, user_id, supabase_client)
        return machine.get_flow_info()
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_session_state_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get session state"
        )


@router.post("/verify-email")
async def verify_email(token: str = Body(..., embed=True)):
    """
    Verify email address using token from verification email.

    The token is sent via email when user signs up.
    This endpoint validates the token and marks the email as verified in Supabase.
    """
    try:
        # Verify email via Supabase
        result = await supabase_client.verify_email(token)

        if not result or not result.get("user"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification token",
            )

        logger.info("email_verified", user_id=result["user"]["id"])

        return {"message": "Email verified successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("verify_email_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to verify email. Token may be invalid or expired.",
        )


@router.post("/resend-verification")
@limiter.limit("3/hour")  # Prevent abuse: Max 3 resends per hour per IP
async def resend_verification(request: Request, email: str = Body(..., embed=True)):
    """
    Resend verification email to user.

    Rate limited to 3 requests per hour to prevent abuse.
    Returns success message even if email doesn't exist (security best practice).
    """
    try:
        await supabase_client.resend_verification_email(email)

        logger.info("verification_resent", email=email)

        # Don't reveal if email exists (security best practice)
        return {"message": "If the email exists, a verification link has been sent"}

    except Exception as e:
        logger.error("resend_verification_error", error=str(e))
        # Still return success to avoid email enumeration
        return {"message": "If the email exists, a verification link has been sent"}


@router.post("/forgot-password")
@limiter.limit(
    f"{settings.rate_limit_auth_requests}/{settings.rate_limit_auth_period} seconds"
)
async def forgot_password(request: Request, email: str = Body(..., embed=True)):
    """
    Request password reset email.

    Sends a password reset link to the user's email via Supabase.
    Rate limited to prevent abuse (5 requests per 60 seconds).

    Returns success message regardless of whether email exists (security best practice).
    """
    try:
        # Validate email format
        if not email or "@" not in email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email address"
            )

        # Call Supabase to send reset email
        redirect_url = f"{settings.frontend_url}/auth/reset-password"
        await supabase_client.request_password_reset(email, redirect_url)

        logger.info("password_reset_requested", email=email)

        # Always return success (don't reveal if email exists)
        return {"message": "If the email exists, a password reset link has been sent"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("forgot_password_error", email=email, error=str(e))
        # Return success anyway for security (don't leak email existence)
        return {"message": "If the email exists, a password reset link has been sent"}


@router.post("/reset-password")
@limiter.limit(
    f"{settings.rate_limit_auth_requests}/{settings.rate_limit_auth_period} seconds"
)
async def reset_password(
    request: Request,
    token: str = Body(...),
    new_password: str = Body(..., alias="newPassword"),
):
    """
    Reset password using token from reset email.

    The token is sent via email when user requests password reset.
    This endpoint validates the token and updates the password in Supabase.
    """
    try:
        # Validate password strength
        if len(new_password) < 8:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password must be at least 8 characters",
            )

        # Update password via Supabase
        result = await supabase_client.reset_password(token, new_password)

        if not result or not result.get("user"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token",
            )

        logger.info("password_reset_success", user_id=result["user"]["id"])

        return {"message": "Password reset successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("reset_password_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to reset password. Token may be invalid or expired.",
        )


@router.get("/check-username")
@limiter.limit("10/minute")  # Prevent DDOS: Max 10 checks per minute per IP
async def check_username(username: str, request: Request):
    """
    Check if a username is available with comprehensive validation.

    Validates:
    - Length (3-20 characters)
    - Format (letters, numbers, underscores, hyphens)
    - Must start with letter
    - No consecutive special chars
    - Not reserved (admin, api, etc.)
    - No profanity
    - Not already taken

    Returns availability status for real-time validation.
    Rate limited to prevent enumeration attacks and DDOS (10 req/min per IP).
    """
    # Comprehensive validation
    is_valid, error_msg = validate_username(username)

    if not is_valid:
        return {
            "available": False,
            "username": username,
            "error": error_msg,
        }

    # Check database availability
    try:
        exists = await supabase_client.check_username_exists(username)
        return {
            "available": not exists,
            "username": username,
            "error": "Username already taken" if exists else None,
        }
    except Exception as e:
        logger.error("check_username_error", username=username, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check username availability",
        )
