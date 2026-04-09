import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from pydantic import BaseModel
from database import get_db
from models.account import SocialAccount, Platform, AccountStatus
from utils.crypto import encrypt_token
from utils.logger import get_logger

router = APIRouter(prefix="/accounts", tags=["Accounts"])
logger = get_logger(__name__)


class AccountCreate(BaseModel):
    platform: Platform
    platform_user_id: str
    username: str
    display_name: str | None = None
    access_token: str


class AccountUpdate(BaseModel):
    username: str | None = None
    display_name: str | None = None
    access_token: str | None = None
    status: AccountStatus | None = None
    is_active: bool | None = None


@router.get("/")
async def list_accounts(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SocialAccount).order_by(SocialAccount.registered_at.desc()))
    accounts = result.scalars().all()
    return [_serialize(a) for a in accounts]


@router.post("/", status_code=201)
async def create_account(body: AccountCreate, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(
        select(SocialAccount).where(
            SocialAccount.platform == body.platform,
            SocialAccount.platform_user_id == body.platform_user_id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Account already registered")

    account = SocialAccount(
        id=uuid.uuid4(),
        platform=body.platform,
        platform_user_id=body.platform_user_id,
        username=body.username,
        display_name=body.display_name,
        encrypted_access_token=encrypt_token(body.access_token),
        status=AccountStatus.MONITORING,
        is_active=True,
    )
    db.add(account)
    await db.commit()
    logger.info("account_registered", platform=body.platform.value, username=body.username)
    return _serialize(account)


@router.get("/{account_id}")
async def get_account(account_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    account = await _get_or_404(db, account_id)
    return _serialize(account)


@router.patch("/{account_id}")
async def update_account(account_id: uuid.UUID, body: AccountUpdate, db: AsyncSession = Depends(get_db)):
    account = await _get_or_404(db, account_id)
    if body.username is not None:
        account.username = body.username
    if body.display_name is not None:
        account.display_name = body.display_name
    if body.access_token is not None:
        account.encrypted_access_token = encrypt_token(body.access_token)
    if body.status is not None:
        account.status = body.status
    if body.is_active is not None:
        account.is_active = body.is_active
    await db.commit()
    return _serialize(account)


@router.delete("/{account_id}", status_code=204)
async def delete_account(account_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    account = await _get_or_404(db, account_id)
    await db.delete(account)
    await db.commit()


async def _get_or_404(db: AsyncSession, account_id: uuid.UUID) -> SocialAccount:
    result = await db.execute(select(SocialAccount).where(SocialAccount.id == account_id))
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    return account


def _serialize(a: SocialAccount) -> dict:
    return {
        "id": str(a.id),
        "platform": a.platform.value,
        "platform_user_id": a.platform_user_id,
        "username": a.username,
        "display_name": a.display_name,
        "status": a.status.value,
        "is_active": a.is_active,
        "registered_at": a.registered_at.isoformat() if a.registered_at else None,
        "last_checked_at": a.last_checked_at.isoformat() if a.last_checked_at else None,
        "last_known_country": a.last_known_country,
    }
