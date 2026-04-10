# Hetzner Server Setup — PersonalSOC

Complete deployment guide for PersonalSOC on a Hetzner CX32 (4 vCPU, 8 GB RAM, Ubuntu 24.04 LTS).

---

## 1. Server aanmaken in Hetzner Cloud Console

1. Log in op [console.hetzner.cloud](https://console.hetzner.cloud)
2. Klik **+ Create Server**
3. Configuratie:

| Setting         | Waarde                        |
|-----------------|-------------------------------|
| Location        | Falkenstein (fsn1) of Nuremberg (nbg1) |
| Image           | Ubuntu 24.04 LTS              |
| Type            | CX32 — 4 vCPU, 8 GB RAM, 80 GB NVMe |
| Networking      | Public IPv4 + IPv6             |
| SSH Key         | Voeg je publieke SSH key toe (zie stap 2) |
| Volume          | Geen (80 GB is voldoende)      |
| Firewall        | Skip — we doen UFW zelf        |
| Backups         | ✅ Enable (€1.57/mo extra)     |
| Name            | `personalsoc`                  |

4. Klik **Create & Buy Now**
5. Noteer het **IP-adres** (bijv. `65.108.xx.xx`)

---

## 2. SSH Key Setup

### Op je lokale machine (Windows/Mac/Linux)

```bash
# Genereer een Ed25519 key als je er nog geen hebt
ssh-keygen -t ed25519 -C "personalsoc-hetzner" -f ~/.ssh/personalsoc

# Bekijk je publieke key
cat ~/.ssh/personalsoc.pub
```

Kopieer de output en plak deze in Hetzner Console → **Security** → **SSH Keys** → **Add SSH Key**.

### Eerste verbinding

```bash
ssh -i ~/.ssh/personalsoc root@65.108.xx.xx
```

### SSH config (optioneel, maakt verbinden makkelijker)

Voeg toe aan `~/.ssh/config`:

```
Host personalsoc
    HostName 65.108.xx.xx
    User deploy
    IdentityFile ~/.ssh/personalsoc
    Port 2222
```

Daarna volstaat: `ssh personalsoc`

---

## 3. Ubuntu Hardening

### 3.1 Systeem updaten

```bash
apt update && apt upgrade -y
apt install -y curl wget git unzip htop ufw fail2ban
```

### 3.2 Deploy user aanmaken

```bash
# Maak een non-root user aan
adduser --disabled-password --gecos "PersonalSOC Deploy" deploy

# Geef sudo rechten
usermod -aG sudo deploy

# Stel sudo in zonder wachtwoord (optioneel, voor deploys)
echo "deploy ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/deploy
chmod 440 /etc/sudoers.d/deploy

# Kopieer SSH keys naar deploy user
mkdir -p /home/deploy/.ssh
cp /root/.ssh/authorized_keys /home/deploy/.ssh/
chown -R deploy:deploy /home/deploy/.ssh
chmod 700 /home/deploy/.ssh
chmod 600 /home/deploy/.ssh/authorized_keys
```

### 3.3 SSH hardening

```bash
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

cat > /etc/ssh/sshd_config.d/hardening.conf << 'EOF'
Port 2222
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
X11Forwarding no
AllowTcpForwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers deploy
EOF

# Test de config VOORDAT je restart
sshd -t
```

> ⚠️ **BELANGRIJK**: Open een TWEEDE terminal en test de SSH verbinding op de nieuwe poort VOORDAT je de huidige sessie sluit.

```bash
systemctl restart sshd
```

Test in een nieuw terminal venster:

```bash
ssh -i ~/.ssh/personalsoc -p 2222 deploy@65.108.xx.xx
```

Pas als dit werkt mag je de root sessie sluiten.

### 3.4 UFW Firewall

```bash
# Reset en configureer
ufw default deny incoming
ufw default allow outgoing

# SSH op nieuwe poort
ufw allow 2222/tcp comment 'SSH'

# HTTP + HTTPS
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'

# Activeer firewall
ufw enable

# Controleer status
ufw status verbose
```

Verwachte output:

```
Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
2222/tcp                   ALLOW IN    Anywhere       # SSH
80/tcp                     ALLOW IN    Anywhere       # HTTP
443/tcp                    ALLOW IN    Anywhere       # HTTPS
```

### 3.5 Fail2ban

```bash
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
banaction = ufw

[sshd]
enabled = true
port    = 2222
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400
EOF

systemctl enable fail2ban
systemctl start fail2ban

# Controleer status
fail2ban-client status sshd
```

### 3.6 Automatische security updates

```bash
apt install -y unattended-upgrades

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

# Controleer
unattended-upgrades --dry-run --debug 2>&1 | head -5
```

---

## 4. Docker + Docker Compose

### 4.1 Docker installeren

```bash
# Verwijder oude versies
apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null

# Voeg Docker repo toe
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list

apt update
apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### 4.2 Docker voor deploy user

```bash
# Voeg deploy user toe aan docker groep
usermod -aG docker deploy

# Activeer Docker op boot
systemctl enable docker
systemctl start docker

# Controleer
docker --version
docker compose version
```

Verwachte output:

```
Docker version 27.x.x
Docker Compose version v2.x.x
```

### 4.3 Docker daemon optimalisatie

```bash
cat > /etc/docker/daemon.json << 'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 65536,
      "Soft": 65536
    }
  }
}
EOF

systemctl restart docker
```

---

## 5. Domein + SSL via Caddy

We vervangen nginx door Caddy als reverse proxy op de host. Caddy regelt automatisch Let's Encrypt SSL.

### 5.1 DNS instellen

Ga naar je DNS provider (Cloudflare, TransIP, etc.) en maak de volgende records aan:

| Type | Name              | Value          | TTL  |
|------|-------------------|----------------|------|
| A    | personalsoc.com   | 65.108.xx.xx   | 300  |
| A    | www               | 65.108.xx.xx   | 300  |

Wacht tot DNS propageert (check met `dig personalsoc.com`).

### 5.2 Caddy installeren

```bash
apt install -y debian-keyring debian-archive-keyring apt-transport-https

curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg

curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list

apt update
apt install -y caddy
```

### 5.3 Docker Compose aanpassen voor Caddy

De nginx container in docker-compose.yml luistert op poorten 80/443, maar Caddy op de host neemt dat over. Pas de nginx service aan zodat die alleen intern luistert:

```bash
# Vanaf nu als deploy user werken
su - deploy
```

We passen later de docker-compose aan. Eerst de Caddy config:

### 5.4 Caddyfile schrijven

```bash
sudo cat > /etc/caddy/Caddyfile << 'EOF'
personalsoc.com {
    # Static pages — Meta App Review
    handle /security-app {
        root * /var/www/personalsoc/public
        rewrite * /security-app.html
        file_server
    }

    handle /privacy-policy {
        root * /var/www/personalsoc/public
        rewrite * /privacy-policy.html
        file_server
    }

    handle /terms {
        root * /var/www/personalsoc/public
        rewrite * /terms.html
        file_server
    }

    handle /data-deletion {
        root * /var/www/personalsoc/public
        rewrite * /data-deletion.html
        file_server
    }

    # WebSocket
    handle /ws/* {
        reverse_proxy localhost:8000
    }

    # API routes
    handle /api/* {
        reverse_proxy localhost:8000
    }

    # Health check
    handle /health {
        reverse_proxy localhost:8000
    }

    # Frontend (SPA)
    handle {
        reverse_proxy localhost:3000
    }

    # Security headers
    header {
        X-Frame-Options DENY
        X-Content-Type-Options nosniff
        X-XSS-Protection "1; mode=block"
        Referrer-Policy strict-origin-when-cross-origin
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    }

    # Logging
    log {
        output file /var/log/caddy/personalsoc.log {
            roll_size 10mb
            roll_keep 5
        }
    }
}

# Redirect www naar apex
www.personalsoc.com {
    redir https://personalsoc.com{uri} permanent
}
EOF
```

### 5.5 Docker Compose productie override

Maak een productie override die nginx vervangt en poorten naar localhost bind:

```bash
mkdir -p /home/deploy/personalsoc
```

We doen dit in stap 6 na het clonen.

### 5.6 Caddy starten

```bash
# Maak log directory
sudo mkdir -p /var/log/caddy
sudo chown caddy:caddy /var/log/caddy

# Valideer config
sudo caddy validate --config /etc/caddy/Caddyfile

# Start Caddy
sudo systemctl enable caddy
sudo systemctl start caddy

# Controleer status
sudo systemctl status caddy
```

Caddy regelt automatisch:
- Let's Encrypt certificaat aanvragen
- HTTPS redirect
- Certificaat auto-renewal

---

## 6. Git Repo Clonen + .env Configureren

### 6.1 Repo clonen

```bash
# Als deploy user
su - deploy
cd ~

git clone https://github.com/Skidaw99/Personal-SOC.git personalsoc
cd personalsoc
```

### 6.2 Static pages linken voor Caddy

```bash
sudo mkdir -p /var/www/personalsoc
sudo ln -s /home/deploy/personalsoc/public /var/www/personalsoc/public
sudo chown -R deploy:deploy /var/www/personalsoc
```

### 6.3 .env configureren

```bash
cp .env.example .env
```

Genereer veilige wachtwoorden en vul ze in:

```bash
# Genereer random wachtwoorden
echo "POSTGRES_PASSWORD: $(openssl rand -base64 24)"
echo "REDIS_PASSWORD:    $(openssl rand -base64 24)"
echo "SECRET_KEY:        $(openssl rand -hex 32)"
echo "WEBHOOK_SECRET:    $(openssl rand -hex 16)"
echo "META_VERIFY_TOKEN: $(openssl rand -hex 16)"
```

Bewerk het .env bestand:

```bash
nano .env
```

Minimaal deze waarden invullen met de gegenereerde wachtwoorden:

```env
# ── DATABASE ──
POSTGRES_DB=social_fraud_detector
POSTGRES_USER=sfd_user
POSTGRES_PASSWORD=<gegenereerd>
DATABASE_URL=postgresql+asyncpg://sfd_user:<gegenereerd>@postgres:5432/social_fraud_detector

# ── REDIS ──
REDIS_PASSWORD=<gegenereerd>
REDIS_URL=redis://:<gegenereerd>@redis:6379/0

# ── APP SECURITY ──
SECRET_KEY=<gegenereerd>
ENCRYPTION_KEY=<genereer een Fernet key, zie onder>
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=<sterk wachtwoord>

# ── EMAIL ──
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=<jouw gmail>
SMTP_PASSWORD=<gmail app password>
ALERT_FROM_EMAIL=<jouw gmail>
ALERT_TO_EMAIL=<alert ontvanger>

# ── AI ──
ANTHROPIC_API_KEY=sk-ant-...
OLLAMA_BASE_URL=http://ollama:11434
AI_ROUTING_THRESHOLD=70

# ── RESPONSE ──
RESPONSE_DRY_RUN=true
```

Fernet key genereren:

```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Als python3-cryptography niet beschikbaar is:

```bash
pip3 install cryptography
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 6.4 .env permissies

```bash
chmod 600 .env
```

---

## 7. Docker Compose Up + Verificatie

### 7.1 Productie docker-compose override

Maak een productie override aan die poorten naar localhost bindt (Caddy handelt extern verkeer af):

```bash
cat > docker-compose.prod.yml << 'EOF'
services:
  backend:
    command: uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
    volumes: []
    restart: always

  celery_worker:
    volumes: []
    restart: always

  celery_beat:
    volumes: []
    restart: always

  frontend:
    ports:
      - "127.0.0.1:3000:80"
    restart: always

  nginx:
    ports:
      - "127.0.0.1:8080:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./public:/usr/share/nginx/html/public:ro
    restart: always

  postgres:
    restart: always

  redis:
    restart: always

  ollama:
    image: ollama/ollama:latest
    container_name: sfd_ollama
    restart: always
    volumes:
      - ollama_data:/root/.ollama
    networks:
      - sfd_network
    deploy:
      resources:
        limits:
          memory: 4G

volumes:
  ollama_data:
EOF
```

### 7.2 Bouwen en starten

```bash
# Bouw alle images
docker compose -f docker-compose.yml -f docker-compose.prod.yml build

# Start alles (detached)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Bekijk logs
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs -f
```

### 7.3 Ollama model downloaden

```bash
# Download Mistral 7B (eerste keer duurt ~5 min)
docker exec sfd_ollama ollama pull mistral:7b

# Controleer
docker exec sfd_ollama ollama list
```

### 7.4 Verificatie checklist

```bash
# 1. Alle containers draaien
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps

# Verwacht: alle services "Up" of "Up (healthy)"
```

```bash
# 2. Database connectie
docker exec sfd_postgres pg_isready -U sfd_user -d social_fraud_detector

# Verwacht: accepting connections
```

```bash
# 3. Redis connectie
docker exec sfd_redis redis-cli -a $(grep REDIS_PASSWORD .env | cut -d= -f2) ping

# Verwacht: PONG
```

```bash
# 4. Backend health
curl -s http://localhost:8000/health | python3 -m json.tool

# Verwacht: {"status": "ok", ...}
```

```bash
# 5. Frontend
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000

# Verwacht: 200
```

```bash
# 6. SSL + domein
curl -s -o /dev/null -w "%{http_code}" https://personalsoc.com/health

# Verwacht: 200
```

```bash
# 7. Static pages (Meta review)
curl -s -o /dev/null -w "%{http_code}" https://personalsoc.com/security-app
curl -s -o /dev/null -w "%{http_code}" https://personalsoc.com/privacy-policy
curl -s -o /dev/null -w "%{http_code}" https://personalsoc.com/terms
curl -s -o /dev/null -w "%{http_code}" https://personalsoc.com/data-deletion

# Verwacht: 200 voor alle vier
```

```bash
# 8. SSL certificaat check
curl -vI https://personalsoc.com 2>&1 | grep -E "subject|expire|issuer"

# Verwacht: issuer: Let's Encrypt, expiry > 60 dagen
```

### 7.5 Handige aliases

Voeg toe aan `/home/deploy/.bashrc`:

```bash
cat >> ~/.bashrc << 'EOF'

# PersonalSOC shortcuts
alias soc-up="cd ~/personalsoc && docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d"
alias soc-down="cd ~/personalsoc && docker compose -f docker-compose.yml -f docker-compose.prod.yml down"
alias soc-logs="cd ~/personalsoc && docker compose -f docker-compose.yml -f docker-compose.prod.yml logs -f"
alias soc-ps="cd ~/personalsoc && docker compose -f docker-compose.yml -f docker-compose.prod.yml ps"
alias soc-restart="cd ~/personalsoc && docker compose -f docker-compose.yml -f docker-compose.prod.yml restart"
alias soc-pull="cd ~/personalsoc && git pull && docker compose -f docker-compose.yml -f docker-compose.prod.yml build && docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d"
EOF

source ~/.bashrc
```

---

## 8. Automatische Backups

### 8.1 Database backup script

```bash
sudo mkdir -p /opt/backups/personalsoc
sudo chown deploy:deploy /opt/backups/personalsoc

cat > /home/deploy/backup-soc.sh << 'SCRIPT'
#!/bin/bash
# PersonalSOC — Automated Backup Script
set -euo pipefail

BACKUP_DIR="/opt/backups/personalsoc"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

echo "[$(date)] Starting PersonalSOC backup..."

# ── 1. PostgreSQL dump ──
echo "  Dumping PostgreSQL..."
docker exec sfd_postgres pg_dump \
  -U sfd_user \
  -d social_fraud_detector \
  --format=custom \
  --compress=9 \
  > "${BACKUP_DIR}/db_${TIMESTAMP}.dump"

echo "  DB dump: $(du -h "${BACKUP_DIR}/db_${TIMESTAMP}.dump" | cut -f1)"

# ── 2. .env backup (encrypted) ──
echo "  Backing up .env..."
cp /home/deploy/personalsoc/.env "${BACKUP_DIR}/env_${TIMESTAMP}.bak"
chmod 600 "${BACKUP_DIR}/env_${TIMESTAMP}.bak"

# ── 3. Docker volumes (Redis) ──
echo "  Backing up Redis data..."
docker exec sfd_redis redis-cli \
  -a "$(grep REDIS_PASSWORD /home/deploy/personalsoc/.env | cut -d= -f2)" \
  BGSAVE 2>/dev/null || true
sleep 2

# ── 4. Caddy config ──
echo "  Backing up Caddy config..."
cp /etc/caddy/Caddyfile "${BACKUP_DIR}/caddyfile_${TIMESTAMP}.bak"

# ── 5. Cleanup old backups ──
echo "  Cleaning up backups older than ${RETENTION_DAYS} days..."
find "${BACKUP_DIR}" -type f -mtime +${RETENTION_DAYS} -delete

# ── 6. Summary ──
TOTAL_SIZE=$(du -sh "${BACKUP_DIR}" | cut -f1)
FILE_COUNT=$(find "${BACKUP_DIR}" -type f | wc -l)
echo "[$(date)] Backup complete. ${FILE_COUNT} files, ${TOTAL_SIZE} total."
SCRIPT

chmod +x /home/deploy/backup-soc.sh
```

### 8.2 Cron job instellen

```bash
# Open crontab voor deploy user
crontab -e
```

Voeg toe:

```cron
# PersonalSOC backup — dagelijks om 03:00 UTC
0 3 * * * /home/deploy/backup-soc.sh >> /opt/backups/personalsoc/backup.log 2>&1

# Docker system prune — wekelijks zondag 04:00 UTC
0 4 * * 0 docker system prune -f >> /opt/backups/personalsoc/prune.log 2>&1
```

### 8.3 Backup testen

```bash
/home/deploy/backup-soc.sh
ls -lah /opt/backups/personalsoc/
```

Verwachte output:

```
db_20260410_030000.dump      ~5-50 MB
env_20260410_030000.bak      ~2 KB
caddyfile_20260410_030000.bak  ~1 KB
```

### 8.4 Restore procedure

Mocht je ooit moeten restoren:

```bash
# Database restore
docker exec -i sfd_postgres pg_restore \
  -U sfd_user \
  -d social_fraud_detector \
  --clean \
  --if-exists \
  < /opt/backups/personalsoc/db_YYYYMMDD_HHMMSS.dump

# .env restore
cp /opt/backups/personalsoc/env_YYYYMMDD_HHMMSS.bak /home/deploy/personalsoc/.env
chmod 600 /home/deploy/personalsoc/.env

# Restart na restore
cd ~/personalsoc
docker compose -f docker-compose.yml -f docker-compose.prod.yml restart
```

### 8.5 Hetzner Snapshots (extra vangnet)

Naast de database backups, maak wekelijks een Hetzner server snapshot:

```bash
# Via Hetzner CLI (optioneel)
apt install -y hcloud-cli

# Login
hcloud context create personalsoc
# Voer je API token in (Hetzner Console → Security → API Tokens)

# Maak een snapshot
hcloud server create-image --type snapshot --description "PersonalSOC weekly $(date +%Y%m%d)" personalsoc

# Bekijk snapshots
hcloud image list --type snapshot
```

Of doe dit via de Hetzner Console: **Servers** → `personalsoc` → **Snapshots** → **Create Snapshot**.

---

## Quick Reference

### Server toegang

```bash
ssh personalsoc                     # via SSH config
ssh -i ~/.ssh/personalsoc -p 2222 deploy@65.108.xx.xx  # direct
```

### Dagelijkse operatie

```bash
soc-ps          # status alle containers
soc-logs        # live logs
soc-restart     # herstart alles
soc-pull        # git pull + rebuild + restart
```

### Monitoring

```bash
htop                                          # systeem resources
docker stats                                  # container resources
sudo tail -f /var/log/caddy/personalsoc.log   # web traffic
sudo fail2ban-client status sshd              # geblokkeerde IPs
df -h                                         # disk usage
```

### Ports in gebruik

| Port | Service          | Toegang     |
|------|------------------|-------------|
| 2222 | SSH              | Extern      |
| 80   | Caddy (HTTP→HTTPS) | Extern    |
| 443  | Caddy (HTTPS)    | Extern      |
| 8000 | Backend API      | Alleen localhost |
| 3000 | Frontend         | Alleen localhost |
| 5432 | PostgreSQL       | Alleen Docker netwerk |
| 6379 | Redis            | Alleen Docker netwerk |
| 11434| Ollama           | Alleen Docker netwerk |
