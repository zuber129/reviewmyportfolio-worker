"""
Custom exceptions for Celery tasks.

These exceptions allow fine-grained control over retry behavior:
- Some errors should retry (transient failures)
- Some errors should NOT retry (permanent failures like duplicates)
"""


class TaskError(Exception):
    """Base exception for all task errors"""

    def __init__(
        self, message: str, user_id: str | None = None, task_id: str | None = None
    ):
        self.message = message
        self.user_id = user_id
        self.task_id = task_id
        super().__init__(message)


class PDFDownloadError(TaskError):
    """Failed to download PDF from storage (should retry)"""

    pass


class PDFParsingError(TaskError):
    """Failed to parse PDF content (should retry with OpenAI fallback)"""

    pass


class DuplicatePDFError(TaskError):
    """PDF already processed (should NOT retry)"""

    def __init__(self, message: str, existing_snapshot_id: str | None = None, **kwargs):
        self.existing_snapshot_id = existing_snapshot_id
        super().__init__(message, **kwargs)


class SnapshotSaveError(TaskError):
    """Failed to save snapshot to database (should retry)"""

    pass


class NoHoldingsFoundError(TaskError):
    """No holdings found in PDF (should NOT retry - bad PDF)"""

    pass
