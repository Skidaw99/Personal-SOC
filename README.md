# 🛡 Social Fraud Detector

Real-time fraud and unauthorized access detection for your social media accounts.
Built with Python 3.12, FastAPI, PostgreSQL, Redis, Celery, and React.

---

## Architecture

```
nginx (port 80)
  ├── /api/*         → FastAPI backend (uvicorn)
  ├── /api/webhooks/ → Platform webhook receivers
  └── /             → React dashboard (Vite)

Backend workers:
  ├── Celery Worker  → processes polling tasks
  └── Celery Beat    → fires polling jobs on schedule

Storage:
  ├── PostgreSQL     → accounts, events, alerts, baselines
  └── Redis          → Celery broker + result backend
```

---

## Quick Start

### 1. Clone and configure

```bash
git clone <your-repo>
cd social-fraud-detector
cp .env.example .env
```

Edit `.env` and fill in every value. At minimum, before first boot:

```env
POSTGRES_PASSWORD=your_strong_password
REDIS_PASSWORD=your_redis_password
SECRET_KEY=64_char_random_hex        # openssl rand -hex 32
ENCRYPTION_KEY=44_char_fernet_key    # python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=your_dashboard_password
SMTP_USERNAME=your_gmail@gmail.com
SMTP_PASSWORD=your_gmail_app_password  # see Gmail setup below
ALERT_TO_EMAIL=you@yourdomain.com
META_VERIFY_TOKEN=random_string_you_choose
WEBHOOK_SECRET=another_random_string
```

### 2. Start the system

```bash
docker compose up -d --build
```

Visit `http://your-server-ip` to open the dashboard.

---

## Gmail App Password Setup

1. Go to https://myaccount.google.com/security
2. Enable **2-Step Verification** (required)
3. Go to **App Passwords** → Select app: Mail → Select device: Other → name it "SFD"
4. Copy the 16-character app password → paste into `SMTP_PASSWORD` in `.env`

---

## Platform Developer App Setup

### Facebook + Instagram (Meta)

1. Go to https://developers.facebook.com/
2. Click **My Apps → Create App** → Choose **Business** type
3. Add products: **Webhooks** and **Instagram Graph API**
4. Under **Settings → Basic**: copy `App ID` → `META_APP_ID`, `App Secret` → `META_APP_SECRET`
5. Generate a **User Access Token** with these permissions:
   - `user_security_info`, `user_managed_groups`, `pages_show_list`
   - Copy it → `META_ACCESS_TOKEN`
6. Under **Webhooks**: set callback URL to `https://your-domain.com/api/webhooks/meta`
   - Verify token: the value you set in `META_VERIFY_TOKEN`
   - Subscribe to: `email`, `security`, `permissions`, `name`

---

### Twitter / X

1. Go to https://developer.twitter.com/en/portal/dashboard
2. Create a **Project** and an **App** inside it
3. Under **Keys and Tokens**:
   - Copy **API Key** → `TWITTER_API_KEY`
   - Copy **API Secret** → `TWITTER_API_SECRET`
   - Generate **Access Token + Secret** → `TWITTER_ACCESS_TOKEN`, `TWITTER_ACCESS_TOKEN_SECRET`
   - Copy **Bearer Token** → `TWITTER_BEARER_TOKEN`
4. Go to **Products → Premium → Account Activity API**
   - Create a Dev Environment, name it (e.g. `production`)
   - Copy the environment name → `TWITTER_WEBHOOK_ENV_NAME`
5. Register your webhook URL via Twitter API:
   ```bash
   POST https://api.twitter.com/1.1/account_activity/all/{env}/webhooks.json
   url=https://your-domain.com/api/webhooks/twitter
   ```

---

### LinkedIn

1. Go to https://www.linkedin.com/developers/apps
2. Click **Create App** → fill in details
3. Under **Auth**: copy `Client ID` → `LINKEDIN_CLIENT_ID`, `Client Secret` → `LINKEDIN_CLIENT_SECRET`
4. Add OAuth 2.0 scopes: `r_liteprofile`, `r_emailaddress`, `w_member_social`
5. Generate an access token via OAuth 2.0 flow → `LINKEDIN_ACCESS_TOKEN`

> LinkedIn does not support security webhooks. The system uses polling.

---

### TikTok

1. Go to https://developers.tiktok.com/
2. Click **Manage Apps → Create App**
3. Add products: **Login Kit**, **Content Posting API**
4. Under **App details**: copy `Client Key` → `TIKTOK_CLIENT_KEY`, `Client Secret` → `TIKTOK_CLIENT_SECRET`
5. Complete the OAuth 2.0 flow to get an access token → `TIKTOK_ACCESS_TOKEN`

> TikTok does not support security webhooks. The system uses polling.

---

### YouTube (Google)

1. Go to https://console.cloud.google.com/
2. Create a new project (or use existing)
3. Enable: **YouTube Data API v3**
4. Go to **Credentials → Create credentials → OAuth 2.0 Client ID**
   - Application type: **Web application**
   - Copy `Client ID` → `GOOGLE_CLIENT_ID`, `Client Secret` → `GOOGLE_CLIENT_SECRET`
5. Complete OAuth 2.0 flow:
   ```bash
   # Use Google OAuth Playground: https://developers.google.com/oauthplayground
   # Scope: https://www.googleapis.com/auth/youtube.readonly
   # Copy access_token → GOOGLE_ACCESS_TOKEN
   # Copy refresh_token → GOOGLE_REFRESH_TOKEN
   ```
6. Find your YouTube Channel ID → `YOUTUBE_CHANNEL_ID`
   - Go to YouTube Studio → Settings → Channel → Basic info

---

## Registering Your Accounts

Once the system is running, open the dashboard → **Accounts** tab → **Add Account**.

Or via API:
```bash
curl -u admin:your_password -X POST http://localhost/api/accounts/ \
  -H "Content-Type: application/json" \
  -d '{
    "platform": "twitter",
    "platform_user_id": "12345678",
    "username": "yourhandle",
    "display_name": "Your Name",
    "access_token": "your_oauth_token_here"
  }'
```

---

## Webhook Receiver (inbound from platforms)

| Platform  | URL                                    | Method |
|-----------|----------------------------------------|--------|
| Meta      | `https://your-domain/api/webhooks/meta`    | GET (verify) + POST |
| Twitter   | `https://your-domain/api/webhooks/twitter` | GET (CRC) + POST    |

Outbound alerts are POSTed to `WEBHOOK_TARGET_URL` with HMAC-SHA256 signature.

---

## Polling Schedule (default)

| Platform  | Interval |
|-----------|----------|
| Facebook  | 5 min    |
| Instagram | 5 min    |
| Twitter   | 3 min    |
| LinkedIn  | 10 min   |
| TikTok    | 10 min   |
| YouTube   | 5 min    |

Change intervals in `.env` → restart containers.

---

## Managing the System

```bash
# View logs
docker compose logs -f backend
docker compose logs -f celery_worker

# Restart a service
docker compose restart backend

# Stop everything
docker compose down

# Full reset (removes all data)
docker compose down -v
```

---

## Security Notes

- All OAuth tokens are **AES-encrypted (Fernet)** at rest in PostgreSQL
- The dashboard is protected with **HTTP Basic Auth** over TLS
- Platform webhooks are verified via **HMAC signatures**
- Outbound webhooks are signed with `X-SFD-Signature: sha256=<hmac>`
- Redis is password-protected and not exposed publicly
- Nginx enforces rate limiting: 30 req/min on API, 120 req/min on webhooks
