# ReviewMyPortfolio Worker

RQ background worker for ReviewMyPortfolio. Handles async tasks like PDF parsing, portfolio processing, and scheduled jobs.

## Stack

- **Queue**: RQ (Redis Queue)
- **Scheduler**: rq-scheduler (cron jobs)
- **Runtime**: Python 3.12
- **Deployment**: Railway

## Tasks

### Queues
- `pdf_parsing` - PDF upload processing
- `portfolio_processing` - Portfolio calculations (XIRR, metrics)

### Scheduled Jobs
- Session cleanup (hourly)
- Stale portfolio cleanup (daily)
- Transaction reconciliation (daily)

## Local Development

```bash
# Start Redis (via docker-compose in main repo)
cd ../ReviewMyPortfolio
docker-compose up redis

# Run worker
export REDIS_URL="redis://localhost:6379"
export INTERNAL_API_URL="http://localhost:8000"
export INTERNAL_API_SECRET="your-secret"
# ... other env vars from .env

rq worker --with-scheduler --url $REDIS_URL pdf_parsing portfolio_processing
```

## Deployment

Deploys automatically to Railway on push to `main`. Railway reads `railway.json` for build config.

### Environment Variables

Set these on Railway:
- `REDIS_URL` - Railway Redis connection string
- `SUPABASE_URL` - Supabase project URL
- `SUPABASE_SERVICE_KEY` - Supabase service role key
- `INTERNAL_API_URL` - API internal URL (e.g., `http://api.railway.internal:8080`)
- `INTERNAL_API_SECRET` - Shared secret for worker→API callbacks
- `PII_ENCRYPTION_KEY` - 32-byte hex key for PII encryption
- `PII_HASH_SALT` - 32-byte hex salt for PII hashing
- `ENVIRONMENT` - `production`
- `LOG_LEVEL` - `INFO`

## Architecture

Worker shares the same codebase (`app/`) as the API but runs different entry point:
- API: `uvicorn app.main:app`
- Worker: `rq worker --with-scheduler`

Tasks are defined in `app/services/jobs/tasks.py` and enqueued from API endpoints.
