from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field, validator


def to_camel(string: str) -> str:
    """Convert snake_case to camelCase"""
    components = string.split("_")
    return components[0] + "".join(x.title() for x in components[1:])


class CamelCaseModel(BaseModel):
    """Base model with camelCase alias configuration"""

    class Config:
        alias_generator = to_camel
        populate_by_name = True  # Allow both snake_case and camelCase
        use_enum_values = True


class RiskLevel(str, Enum):
    CONSERVATIVE = "conservative"
    MODERATE = "moderate"
    AGGRESSIVE = "aggressive"


class TimeRange(str, Enum):
    ALL_TIME = "all_time"
    MONTHLY = "monthly"
    WEEKLY = "weekly"


class OpinionType(str, Enum):
    ANALYSIS = "analysis"
    QUESTION = "question"
    THESIS = "thesis"


class ModerationStatus(str, Enum):
    VISIBLE = "visible"
    HIDDEN = "hidden"


class ReportReason(str, Enum):
    SPAM = "spam"
    ABUSIVE = "abusive"
    MISLEADING = "misleading"
    OTHER = "other"


class ReportTargetType(str, Enum):
    PORTFOLIO = "portfolio"
    OPINION = "opinion"


class ResolutionAction(str, Enum):
    HIDE_CONTENT = "hide_content"
    RESTORE_CONTENT = "restore_content"


class PortfolioFileStatus(str, Enum):
    UPLOADED = "uploaded"
    VALIDATING = "validating"
    SCANNING = "scanning"
    PARSING = "parsing"
    COMPLETED = "completed"
    FAILED = "failed"


# Auth Schemas
class UserSignup(CamelCaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)

    @validator("password")
    def validate_password(cls, v):
        import re
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        # Reduced secure special character set (common, easy to type)
        if not re.search(r"[!@#$%&*]", v):
            raise ValueError("Password must contain at least one special character (!@#$%&*)")
        return v


class UserSignin(CamelCaseModel):
    email: EmailStr
    password: str


class GoogleAuthRequest(CamelCaseModel):
    id_token: str


class TokenResponse(CamelCaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    user: Dict[str, Any]
    access_status: str = "active"
    days_until_restricted: Optional[int] = None
    days_until_blocked: Optional[int] = None


class UserProfile(CamelCaseModel):
    id: str
    email: EmailStr
    username: str
    avatar_url: Optional[str] = None
    bio: Optional[str] = None
    username_confirmed: bool = False
    privacy_consent_given: bool = False
    onboarding_completed: bool = False
    reputation_score: int = 0
    reputation_tier: str = "newcomer"
    is_admin: bool = False
    created_at: datetime
    updated_at: datetime
    total_reviews_given: int = 0
    total_reviews_received: int = 0
    avg_portfolio_rating: Optional[float] = None
    xirr: Optional[float] = None
    badges: List[Dict[str, Any]] = []
    access_status: str = "active"
    last_upload_date: Optional[datetime] = None
    days_until_restricted: Optional[int] = None


class PublicUserProfile(CamelCaseModel):
    """Public user profile - excludes internal identifiers and PII for privacy."""

    username: str
    avatar_url: Optional[str] = None
    bio: Optional[str] = None
    badges: List[Dict[str, Any]] = []


# Portfolio Schemas
class PortfolioTransaction(CamelCaseModel):
    """A single transaction extracted from a CAS statement."""

    isin: str
    asset_name: str
    transaction_type: str  # DEBIT, CREDIT, BUY, SELL, REDEMPTION, etc.
    date: str  # ISO date string
    quantity: float
    amount: Optional[float] = None
    price: Optional[float] = None
    reference: Optional[str] = None
    op_bal: Optional[float] = None
    cl_bal: Optional[float] = None


class Holding(CamelCaseModel):
    symbol: str
    name: str
    quantity: float
    avg_price: float
    current_price: float
    current_value: float
    percentage: float
    isin: Optional[str] = None
    asset_type: str = "equity"  # equity, mutual_fund, insurance, bond, debt, gold_etf, sgb, reit, invit, nps, ppf, epf, fd, other
    
    # Insurance-specific fields
    policy_number: Optional[str] = None
    sum_assured: Optional[float] = None
    premium_amount: Optional[float] = None
    maturity_date: Optional[str] = None
    
    # Bond/Debt-specific fields
    face_value: Optional[float] = None
    coupon_rate: Optional[float] = None
    credit_rating: Optional[str] = None
    
    # Retirement account fields
    account_number: Optional[str] = None
    contribution_amount: Optional[float] = None
    
    # Additional metadata
    folio_number: Optional[str] = None
    purchase_date: Optional[str] = None


class PortfolioCreate(CamelCaseModel):
    title: str
    description: Optional[str] = None
    investment_thesis: Optional[str] = Field(None, min_length=30, max_length=2000)
    total_value: float
    risk_level: Optional[RiskLevel] = RiskLevel.MODERATE
    holdings: List[Holding]
    transactions: List[PortfolioTransaction] = []
    xirr: Optional[float] = None
    document_url: Optional[str] = None
    # Encrypted PII for ownership verification (Issue #41)
    encrypted_holder_name: Optional[str] = None
    encrypted_pan_last4: Optional[str] = None
    pii_hash: Optional[str] = None


class Portfolio(CamelCaseModel):
    """Internal portfolio model with full fields including user_id."""

    id: str
    user_id: str
    title: str
    description: Optional[str] = None
    investment_thesis: Optional[str] = None
    total_value: float
    risk_level: Optional[RiskLevel] = None
    xirr: Optional[float] = None
    document_url: Optional[str] = None
    visibility: str = "public"
    moderation_status: ModerationStatus = ModerationStatus.VISIBLE
    created_at: datetime
    updated_at: datetime
    deleted_at: Optional[datetime] = None
    holdings: List[Holding] = []
    reviews: List[Dict[str, Any]] = []
    avg_rating: Optional[float] = None
    review_count: int = 0
    owner: Optional[UserProfile] = None


class PublicPortfolio(CamelCaseModel):
    """Public portfolio response - excludes user_id for privacy."""

    id: str
    title: str
    description: Optional[str] = None
    investment_thesis: Optional[str] = None
    total_value: float
    risk_level: Optional[RiskLevel] = None
    xirr: Optional[float] = None
    document_url: Optional[str] = None
    visibility: str = "public"
    moderation_status: ModerationStatus = ModerationStatus.VISIBLE
    created_at: datetime
    updated_at: datetime
    holdings: List[Holding] = []
    avg_rating: Optional[float] = None
    review_count: int = 0
    owner: Optional[PublicUserProfile] = None
    reaction_count: int = 0
    is_reacted: bool = False


class PortfolioFeedRequest(CamelCaseModel):
    offset: int = 0
    limit: int = Field(default=20, le=100)
    risk_level: Optional[RiskLevel] = None
    min_xirr: Optional[float] = None
    max_xirr: Optional[float] = None
    sort_by: str = "created_at"


class PortfolioFeedResponse(CamelCaseModel):
    portfolios: List[PublicPortfolio]
    pagination: Dict[str, Any]
    source: Optional[str] = None


# Leaderboard Schemas
class LeaderboardRequest(CamelCaseModel):
    time_range: TimeRange = TimeRange.ALL_TIME
    limit: int = Field(default=100, le=500)


class LeaderboardEntry(CamelCaseModel):
    """Public leaderboard entry - excludes user_id for privacy."""

    rank: int
    username: str
    avatar_url: Optional[str] = None
    xirr: float
    xirr_1y: Optional[float] = None  # NEW: 1-year XIRR
    consistency_score: Optional[float] = None  # NEW: Consistency score 0-100
    total_value: float
    portfolio_count: int
    avg_rating: float
    tier: Optional[str] = None
    badges: List[Dict[str, Any]] = []
    data_points: Optional[int] = None  # NEW: Number of snapshots used
    history_months: Optional[int] = None  # NEW: Months of history


class LeaderboardResponse(CamelCaseModel):
    entries: List[LeaderboardEntry]
    time_range: TimeRange
    updated_at: datetime


# Opinion/Comment Schemas - moved to end of file (see Instrument Schemas section)


# Moderation Schemas
class ReportCreate(CamelCaseModel):
    reason: ReportReason
    note: Optional[str] = Field(None, max_length=500)


class Report(CamelCaseModel):
    id: str
    reporter_id: str
    target_type: ReportTargetType
    target_id: str
    reason: ReportReason
    note: Optional[str] = None
    is_auto_flagged: bool = False
    status: str  # pending, resolved
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolution_action: Optional[ResolutionAction] = None
    created_at: datetime


class ReportListResponse(CamelCaseModel):
    reports: List[Report]
    total: int


class ModerationAction(CamelCaseModel):
    action: ResolutionAction


# Error Schemas
class ErrorResponse(CamelCaseModel):
    error: str
    message: str
    details: Optional[Dict[str, Any]] = None


# Dashboard Schemas
class RecentPortfolio(CamelCaseModel):
    id: str
    title: str
    created_at: datetime
    total_value: float
    xirr: Optional[float] = None


class ReputationRadar(CamelCaseModel):
    """4-axis reputation breakdown for radar chart visualization."""

    performance_score: int = 0
    portfolio_quality_score: int = 0
    community_score: int = 0
    trust_score: int = 0


class DashboardStats(CamelCaseModel):
    portfolio_count: int
    recent_portfolios: List[RecentPortfolio]
    total_reactions_received: int
    total_opinions_given: int
    total_helpful_votes_received: int
    access_status: str
    days_until_restricted: Optional[int] = None
    days_until_blocked: Optional[int] = None
    can_browse_feed: bool = True
    reputation_score: int = 0
    reputation_tier: str = "newcomer"
    performance_rank: Optional[int] = None
    contribution_rank: Optional[int] = None
    reputation_radar: ReputationRadar = ReputationRadar()
    current_streak: int = 0
    longest_streak: int = 0
    portfolios_rated: int = 0


class AccessStatusResponse(CamelCaseModel):
    access_status: str
    can_upload: bool
    can_browse_feed: bool
    days_until_restricted: Optional[int] = None
    days_until_blocked: Optional[int] = None
    last_upload_date: Optional[datetime] = None
    message: Optional[str] = None


class ReputationResponse(CamelCaseModel):
    reputation_score: int
    total_reviews: int
    avg_rating: float
    helpful_votes: int
    rank: Optional[int] = None


# Portfolio Upload Schemas
class UploadUrlResponse(CamelCaseModel):
    upload_url: str
    file_key: str  # Storage path for debugging
    expires_at: datetime


class ProcessPortfolioRequest(CamelCaseModel):
    file_key: str  # Storage path of uploaded file
    original_filename: Optional[str] = None  # Original filename for debugging
    title: Optional[str] = None
    description: Optional[str] = None
    investment_thesis: Optional[str] = None
    is_public: Optional[bool] = None


class UploadTaskResponse(CamelCaseModel):
    task_id: str
    status: str
    result: Optional[Portfolio] = None
    error: Optional[str] = None


class PortfolioStatusResponse(CamelCaseModel):
    portfolio_id: str
    status: str
    processing_progress: Optional[int] = None
    error: Optional[str] = None


class PortfolioSnapshot(CamelCaseModel):
    id: str
    portfolio_id: str
    snapshot_date: datetime
    total_value: float
    xirr: Optional[float] = None
    holdings: List[Holding]
    created_at: datetime


class SnapshotListResponse(CamelCaseModel):
    snapshots: List[PortfolioSnapshot]
    total: int


class GrowthDataPoint(CamelCaseModel):
    date: datetime
    total_value: float
    xirr: Optional[float] = None


class GrowthTimelineResponse(CamelCaseModel):
    data_points: List[GrowthDataPoint]
    months: int


# Pagination Schema
class PaginationMeta(CamelCaseModel):
    page: int
    page_size: int
    total: int
    total_pages: int
    has_previous: bool
    has_next: bool


# Reaction Schemas
class ReactionResponse(CamelCaseModel):
    portfolio_id: str
    is_reacted: bool
    reaction_count: int


class ReactionStatusResponse(CamelCaseModel):
    portfolio_id: str
    user_has_reacted: bool
    total_reactions: int


# Opinion Schemas
class HelpfulVoteResponse(CamelCaseModel):
    opinion_id: str
    is_helpful: bool
    helpful_count: int


# Comparison Schemas
class PortfolioComparison(CamelCaseModel):
    portfolio_id: str
    title: str
    total_value: float
    xirr: Optional[float] = None
    risk_level: Optional[RiskLevel] = None
    holdings_count: int


class ComparisonResponse(CamelCaseModel):
    portfolios: List[PortfolioComparison]
    comparison_metrics: Dict[str, Any]


class ComparisonMetricsResponse(CamelCaseModel):
    portfolio_ids: List[str]
    metrics: Dict[str, Any]


# Admin Schemas
class SystemStats(CamelCaseModel):
    total_users: int
    total_portfolios: int
    total_opinions: int
    total_reactions: int
    pending_reports: int
    cache_size: Optional[int] = None


class CacheClearResponse(CamelCaseModel):
    cleared: bool
    caches_cleared: List[str]
    message: str


class RecentUser(CamelCaseModel):
    id: str
    email: EmailStr
    username: str
    created_at: datetime
    portfolio_count: int


class RecentUsersResponse(CamelCaseModel):
    users: List[RecentUser]
    total: int


class DeleteResponse(CamelCaseModel):
    deleted: bool
    message: str


class ModerationActionResponse(CamelCaseModel):
    report_id: str
    action: ResolutionAction
    success: bool
    message: str


# Contribution Leaderboard
class ContributionEntry(CamelCaseModel):
    """Public contribution entry - excludes user_id for privacy."""

    rank: int
    username: str
    avatar_url: Optional[str] = None
    total_opinions: int
    total_helpful_votes: int
    contribution_score: int
    tier: Optional[str] = None


class ContributionLeaderboardResponse(CamelCaseModel):
    entries: List[ContributionEntry]
    time_range: str
    updated_at: datetime


# Portfolio File Tracking Schemas
class PortfolioFileCreate(CamelCaseModel):
    """Schema for creating a new file tracking record"""
    user_id: str
    storage_path: str
    storage_bucket: str = "portfolio-documents"
    file_size_bytes: int
    file_hash: str
    original_filename: Optional[str] = None
    mime_type: str = "application/pdf"
    celery_task_id: Optional[str] = None


class PortfolioFile(CamelCaseModel):
    """Complete file tracking record"""
    id: str
    user_id: str
    storage_path: str
    storage_bucket: str
    file_size_bytes: int
    file_hash: str
    original_filename: Optional[str] = None
    mime_type: str
    status: PortfolioFileStatus
    processing_started_at: Optional[datetime] = None
    processing_completed_at: Optional[datetime] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None
    retry_count: int = 0
    last_retry_at: Optional[datetime] = None
    snapshot_id: Optional[str] = None
    celery_task_id: Optional[str] = None
    uploaded_at: datetime
    deleted_at: Optional[datetime] = None
    delete_reason: Optional[str] = None


class PortfolioFileUpdate(CamelCaseModel):
    """Schema for updating file status and metadata"""
    status: Optional[PortfolioFileStatus] = None
    processing_started_at: Optional[datetime] = None
    processing_completed_at: Optional[datetime] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None
    retry_count: Optional[int] = None
    last_retry_at: Optional[datetime] = None
    snapshot_id: Optional[str] = None


class FileUploadHistoryResponse(CamelCaseModel):
    """Response for file upload history listing"""
    files: List[PortfolioFile]
    total: int
    page: int
    page_size: int


# Instrument Schemas
class InstrumentSymbol(CamelCaseModel):
    """Instrument symbol details"""
    id: str
    instrument_id: str
    symbol: str
    exchange: str
    source: str
    is_primary: bool
    created_at: datetime


class InstrumentBase(CamelCaseModel):
    """Base instrument data"""
    name: str
    asset_type: str
    sector: Optional[str] = None
    market_cap: Optional[str] = None
    isin: Optional[str] = None
    primary_symbol: str
    current_price: Optional[float] = None


class InstrumentCreate(InstrumentBase):
    """Schema for creating a new instrument"""
    pass


class Instrument(InstrumentBase):
    """Complete instrument record"""
    id: str
    needs_isin_backfill: bool = False
    active: bool = True
    price_updated_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    symbols: List[InstrumentSymbol] = []


class InstrumentSearchResult(CamelCaseModel):
    """Instrument search result"""
    id: str
    name: str
    asset_type: str
    primary_symbol: str
    current_price: Optional[float] = None
    all_symbols: List[str] = []


class InstrumentSymbolCreate(CamelCaseModel):
    """Schema for adding a new symbol to an instrument"""
    symbol: str
    exchange: str
    source: str
    is_primary: bool = False


# Portfolio Opinion Schemas (stored in comments table)
class PortfolioOpinionCreate(CamelCaseModel):
    """Schema for creating a portfolio opinion (no instrument_id needed)."""
    content: str = Field(..., min_length=20, max_length=2000)
    opinion_type: OpinionType


class PortfolioOpinion(CamelCaseModel):
    """Portfolio opinion response (from comments table)."""
    id: str
    portfolio_id: str
    user_id: str
    content: str
    opinion_type: OpinionType
    helpful_count: int = 0
    created_at: datetime
    updated_at: datetime
    username: Optional[str] = None
    avatar_url: Optional[str] = None
    reputation_tier: Optional[str] = None
    is_helpful_by_user: bool = False


class PortfolioOpinionListResponse(CamelCaseModel):
    """Paginated portfolio opinion list."""
    opinions: List["PortfolioOpinion"] = []
    total: int = 0
    page: int = 1
    page_size: int = 20


# Opinion Schemas
class OpinionCreate(CamelCaseModel):
    """Schema for creating a new opinion"""
    instrument_id: Optional[str] = None
    content: str = Field(..., min_length=100, max_length=2000)
    opinion_type: OpinionType
    parent_id: Optional[str] = None


class OpinionUpdate(CamelCaseModel):
    """Schema for updating an opinion"""
    content: Optional[str] = Field(None, min_length=100, max_length=2000)
    moderation_status: Optional[ModerationStatus] = None


class Opinion(CamelCaseModel):
    """Complete opinion record"""
    id: str
    user_id: str
    instrument_id: Optional[str] = None
    content: str
    opinion_type: OpinionType
    helpful_count: int = 0
    parent_id: Optional[str] = None
    thread_depth: int = 0
    moderation_status: ModerationStatus = ModerationStatus.VISIBLE
    created_at: datetime
    updated_at: datetime
    deleted_at: Optional[datetime] = None
    # Joined data
    username: Optional[str] = None
    avatar_url: Optional[str] = None
    reputation_tier: Optional[str] = None
    instrument_name: Optional[str] = None
    instrument_symbol: Optional[str] = None
    has_voted: Optional[bool] = None
    replies: List["Opinion"] = []


class OpinionListResponse(CamelCaseModel):
    """Response for opinion listing"""
    opinions: List[Opinion]
    total: int
    page: int
    page_size: int


# Review Schemas (portfolio-scoped, stored in reviews table)
class ReviewCreate(CamelCaseModel):
    """Schema for creating a portfolio review"""
    content: str = Field(..., min_length=1, max_length=500)


class ReviewUpdate(CamelCaseModel):
    """Schema for updating a portfolio review"""
    content: str = Field(..., min_length=1, max_length=500)


class Review(CamelCaseModel):
    """Portfolio review record (reviews table)"""
    id: str
    user_id: str
    portfolio_id: str
    content: str
    created_at: datetime
    updated_at: datetime
    deleted_at: Optional[datetime] = None
    # Joined data
    username: Optional[str] = None
    avatar_url: Optional[str] = None
    reputation_tier: Optional[str] = None


class ReviewListResponse(CamelCaseModel):
    """Response for review listing"""
    reviews: List[Review]
    total: int
    page: int
    page_size: int


# User Search Schema
class UserSearchResult(CamelCaseModel):
    """User search result for @mentions"""
    username: str
    avatar_url: Optional[str] = None
    reputation_tier: Optional[str] = None


# Update forward references
Opinion.model_rebuild()
