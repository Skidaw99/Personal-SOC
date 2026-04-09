import asyncio
from datetime import datetime
from sqlalchemy import select
from scheduler.celery_app import celery_app
from database import AsyncSessionLocal
from models.account import SocialAccount, Platform, AccountStatus
from collectors import COLLECTOR_REGISTRY
from analyzers.engine import FraudAnalysisEngine
from utils.crypto import decrypt_token
from utils.logger import get_logger

logger = get_logger(__name__)


def run_async(coro):
    """Run an async coroutine inside a Celery worker (sync context)."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(name="scheduler.tasks.poll_platform", bind=True, max_retries=3)
def poll_platform(self, platform_name: str):
    """
    Poll all active accounts for a given platform.
    Collects events and runs them through the fraud analysis engine.
    """
    logger.info("poll_platform_start", platform=platform_name)
    try:
        run_async(_poll_platform_async(platform_name))
    except Exception as exc:
        logger.error("poll_platform_failed", platform=platform_name, error=str(exc))
        raise self.retry(exc=exc, countdown=60)


async def _poll_platform_async(platform_name: str):
    collector_class = COLLECTOR_REGISTRY.get(platform_name)
    if not collector_class:
        logger.warning("no_collector_for_platform", platform=platform_name)
        return

    collector = collector_class()

    async with AsyncSessionLocal() as db:
        try:
            platform_enum = Platform(platform_name)
        except ValueError:
            logger.error("invalid_platform", platform=platform_name)
            return

        result = await db.execute(
            select(SocialAccount).where(
                SocialAccount.platform == platform_enum,
                SocialAccount.is_active == True,
                SocialAccount.status != AccountStatus.SUSPENDED,
            )
        )
        accounts = result.scalars().all()

        if not accounts:
            logger.info("no_active_accounts", platform=platform_name)
            return

        engine = FraudAnalysisEngine(db)

        for account in accounts:
            try:
                access_token = decrypt_token(account.encrypted_access_token) if account.encrypted_access_token else ""
                raw_events = await collector.fetch_events(account.platform_user_id, access_token)

                alerts = await engine.process_events(account, raw_events)

                account.last_checked_at = datetime.utcnow()
                await db.flush()

                logger.info(
                    "account_polled",
                    account=account.username,
                    platform=platform_name,
                    events=len(raw_events),
                    alerts=len(alerts),
                )
            except Exception as e:
                logger.error("account_poll_error", account=str(account.id), error=str(e))
                continue

        await db.commit()


@celery_app.task(name="scheduler.tasks.validate_all_tokens", bind=True, max_retries=2)
def validate_all_tokens(self):
    """
    Every 6 hours: validate all stored OAuth tokens across all platforms.
    Marks accounts with revoked tokens as COMPROMISED and fires alerts.
    """
    logger.info("token_validation_start")
    try:
        run_async(_validate_all_tokens_async())
    except Exception as exc:
        logger.error("token_validation_failed", error=str(exc))
        raise self.retry(exc=exc, countdown=120)


async def _validate_all_tokens_async():
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(SocialAccount).where(SocialAccount.is_active == True)
        )
        accounts = result.scalars().all()

        for account in accounts:
            try:
                collector_class = COLLECTOR_REGISTRY.get(account.platform.value)
                if not collector_class:
                    continue

                collector = collector_class()
                access_token = decrypt_token(account.encrypted_access_token) if account.encrypted_access_token else ""
                is_valid = await collector.validate_token(access_token)

                if not is_valid and account.status != AccountStatus.COMPROMISED:
                    account.status = AccountStatus.COMPROMISED
                    logger.warning("token_revoked_account_compromised", account=account.username, platform=account.platform.value)

                await db.flush()
            except Exception as e:
                logger.error("token_validation_account_error", account=str(account.id), error=str(e))

        await db.commit()
