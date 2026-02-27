import secrets
import string
from typing import Any, Dict, Optional

import structlog
from app.core.config import settings

from supabase import ClientOptions, create_client  # type: ignore[attr-defined]

logger = structlog.get_logger()


class Security:
    """Security utilities using Supabase Auth as the single source of truth."""

    def __init__(self):
        # Disable auto_refresh_token, persist_session and realtime to avoid client issues
        client_options = ClientOptions(
            auto_refresh_token=False,
            persist_session=False,
            realtime={"enabled": False},  # Explicitly disable realtime
        )
        self.supabase = create_client(
            settings.supabase_url,
            settings.supabase_service_key,  # Service key for admin operations
            options=client_options,
        )
        self.anon_supabase = create_client(
            settings.supabase_url,
            settings.supabase_anon_key,  # Anon key for client operations
            options=client_options,
        )

        # Monkey-patch realtime to avoid NoneType errors
        if self.supabase.realtime is None:

            class MockRealtime:
                def set_auth(self, *args, **kwargs):
                    pass  # No-op

            self.supabase.realtime = MockRealtime()

        if self.anon_supabase.realtime is None:

            class MockRealtime:
                def set_auth(self, *args, **kwargs):
                    pass  # No-op

            self.anon_supabase.realtime = MockRealtime()

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify a Supabase JWT token and return user data.
        This replaces custom JWT validation - Supabase is our auth provider.
        """
        try:
            # Get user from Supabase using the token
            user = self.supabase.auth.get_user(token)
            if user and user.user:
                return {
                    "sub": user.user.id,
                    "email": user.user.email,
                    "user_metadata": user.user.user_metadata,
                    "app_metadata": user.user.app_metadata,
                    "role": user.user.role,
                }
            return None
        except Exception as e:
            logger.error("token_verification_failed", error=str(e))
            return None

    def get_user_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Get full user profile using a Supabase token.
        Used by API endpoints to get current user.
        """
        try:
            user = self.supabase.auth.get_user(token)
            if user and user.user:
                # Also fetch profile from database
                profile = (
                    self.supabase.table("profiles")
                    .select("*")
                    .eq("id", user.user.id)
                    .single()
                    .execute()
                )
                return {
                    "id": user.user.id,
                    "email": user.user.email,
                    "profile": profile.data if profile.data else None,
                }
            return None
        except Exception as e:
            logger.error("get_user_failed", error=str(e))
            return None

    @staticmethod
    def generate_anonymous_username() -> str:
        """Generate Reddit-style anonymous username with high entropy and diversity"""
        import uuid

        # Expanded vocabulary for more diversity (Reddit-style)
        adjectives = [
            "Mysterious",
            "Silent",
            "Hidden",
            "Quiet",
            "Subtle",
            "Ancient",
            "Cosmic",
            "Digital",
            "Phantom",
            "Shadow",
            "Crystal",
            "Golden",
            "Silver",
            "Bronze",
            "Lonely",
            "Happy",
            "Jolly",
            "Grumpy",
            "Sleepy",
            "Dizzy",
            "Clumsy",
            "Brave",
            "Bold",
            "Swift",
            "Quick",
            "Wise",
            "Smart",
            "Clever",
            "Witty",
            "Mighty",
            "Tiny",
            "Giant",
            "Loud",
            "Calm",
            "Wild",
            "Tame",
            "Free",
            "Lost",
            "Found",
            "Rare",
            "Common",
            "Noble",
            "Humble",
            "Proud",
            "Shy",
            "Eager",
            "Lazy",
            "Active",
            "Sleepy",
            "Awake",
            "Dreamy",
            "Real",
            "Fake",
            "Warm",
            "Cold",
            "Hot",
            "Cool",
            "Frozen",
            "Molten",
            "Liquid",
            "Solid",
        ]

        nouns = [
            "Penguin",
            "Raccoon",
            "Otter",
            "Panda",
            "Koala",
            "Sloth",
            "Llama",
            "Dragon",
            "Phoenix",
            "Griffin",
            "Unicorn",
            "Kraken",
            "Hydra",
            "Sphinx",
            "Eagle",
            "Falcon",
            "Hawk",
            "Raven",
            "Owl",
            "Swan",
            "Crow",
            "Dove",
            "Tiger",
            "Lion",
            "Bear",
            "Wolf",
            "Fox",
            "Lynx",
            "Puma",
            "Jaguar",
            "Shark",
            "Whale",
            "Dolphin",
            "Seal",
            "Orca",
            "Manta",
            "Squid",
            "Octopus",
            "Wizard",
            "Knight",
            "Ninja",
            "Pirate",
            "Viking",
            "Samurai",
            "Monk",
            "Bard",
            "Robot",
            "Cyborg",
            "Android",
            "Alien",
            "Ghost",
            "Zombie",
            "Vampire",
            "Witch",
            "Mountain",
            "River",
            "Ocean",
            "Forest",
            "Desert",
            "Valley",
            "Canyon",
            "Peak",
            "Thunder",
            "Lightning",
            "Storm",
            "Blizzard",
            "Tornado",
            "Eclipse",
            "Comet",
            "Star",
        ]

        # Multiple format patterns for variety (Reddit uses these)
        format_choice = secrets.randbelow(3)

        if format_choice == 0:
            # Format: Adjective_Noun_Number (most common)
            adj = secrets.choice(adjectives)
            noun = secrets.choice(nouns)
            # Use 2-4 digit number for readability
            number = secrets.randbelow(10000)
            return f"{adj}{noun}{number}"

        elif format_choice == 1:
            # Format: Adjective_Noun (no number, cleaner)
            adj = secrets.choice(adjectives)
            noun = secrets.choice(nouns)
            # Add short suffix for uniqueness
            suffix = uuid.uuid4().hex[:4]
            return f"{adj}{noun}_{suffix}"

        else:
            # Format: Noun_Number (simple)
            noun = secrets.choice(nouns)
            # Larger number range for uniqueness
            number = secrets.randbelow(100000)
            return f"{noun}{number}"


security = Security()
