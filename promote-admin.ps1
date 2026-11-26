# promote-admin.ps1 — Promote a user to admin with one command.
# Usage:
#   .\promote-admin.ps1                 # prompts for email
#   .\promote-admin.ps1 someone@x.com   # promote directly
param([string]$Email)

if (-not $Email) {
    $Email = Read-Host "Enter the email address to promote to admin"
}

if (-not $Email) {
    Write-Host "No email provided. Aborting." -ForegroundColor Red
    exit 1
}

$py = @"
from app.models.user import User
from app.models.target import Target
from app.models.scan import Scan, Vulnerability
from app.db.session import SessionLocal
from sqlalchemy import select
db = SessionLocal()
u = db.scalar(select(User).where(User.email == '$Email'))
if not u:
    print('USER NOT FOUND: $Email')
else:
    u.role = 'admin'
    db.commit()
    print('PROMOTED', u.email, '-> admin')
"@

docker exec vulnscope-api-1 python -c $py

if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed. Is the stack running? Try: docker compose up -d" -ForegroundColor Red
}