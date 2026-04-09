import base64
from cryptography.fernet import Fernet
from config import get_settings

settings = get_settings()


def _get_fernet() -> Fernet:
    key = settings.encryption_key.encode()
    # Ensure the key is valid Fernet key (32 url-safe base64 bytes)
    if len(key) != 44:  # Fernet keys are 44 chars in base64 representation
        # Pad/truncate to 32 bytes and encode properly
        raw = key[:32].ljust(32, b"0")
        key = base64.urlsafe_b64encode(raw)
    return Fernet(key)


def encrypt_token(plain_token: str) -> str:
    """Encrypt a plaintext OAuth token for storage."""
    f = _get_fernet()
    return f.encrypt(plain_token.encode()).decode()


def decrypt_token(encrypted_token: str) -> str:
    """Decrypt a stored encrypted OAuth token."""
    f = _get_fernet()
    return f.decrypt(encrypted_token.encode()).decode()
