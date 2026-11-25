# Deploying the Onboarding Portal on AWS

Same app as Replit, no code changes. One container on **App Runner**, data in **RDS PostgreSQL**, secrets in **Secrets Manager**, reminders triggered by **EventBridge**.

```
clinic / billing / Plexus browsers
        │ HTTPS (onboarding.plexusclinical.com)
        ▼
App Runner service  ──(VPC connector)──►  RDS PostgreSQL (private subnets, encrypted)
  container from ECR                       automated backups
  env + Secrets Manager refs
        ▲                     │ outbound (via NAT): SMTP email, Google sign-in check, RingCentral
        │
EventBridge rule (every 15 min) → POST /api/cron/reminders  (x-cron-secret header)
```

Before you store anything real: accept the **AWS BAA** in AWS Artifact, and confirm each service you use (App Runner, RDS, Secrets Manager, ECR, EventBridge, SES) is on AWS's current HIPAA Eligible Services list.

## 1. Database (RDS)

1. RDS → Create database → **PostgreSQL 16**.
   - Template: Production (or Dev/Test for a pilot). Instance: `db.t4g.small` is plenty to start.
   - Storage encryption **on**. Automated backups **7+ days**. Deletion protection **on**.
   - Connectivity: the same VPC as your other Plexus services, **private subnets**, **Public access: No**.
   - Security group: allow **5432** only from the App Runner VPC connector's security group (step 3).
2. Initial database name: `onboarding`. Save the master username/password; you'll put them in Secrets Manager.
3. Connection string (the app turns on verified TLS automatically for RDS):
   `postgres://USER:PASSWORD@<endpoint>.rds.amazonaws.com:5432/onboarding`

Tables are created automatically the first time the app starts.

## 2. Secrets (Secrets Manager)

Create one secret per value (App Runner references them individually), e.g. under the prefix `plexus-onboarding/`:

| Secret | Value |
|---|---|
| `plexus-onboarding/DATABASE_URL` | the connection string above |
| `plexus-onboarding/SMTP_PASS` | Google app password for onboarding@ (or SES SMTP password) |
| `plexus-onboarding/CRON_SECRET` | a long random string, e.g. `openssl rand -base64 32` |
| `plexus-onboarding/RINGCENTRAL_CLIENT_SECRET` | optional |
| `plexus-onboarding/RINGCENTRAL_JWT` | optional |

## 3. Image (ECR)

From the repo, with the AWS CLI signed in and Docker running:

```
AWS_REGION=us-west-2 ./deploy/aws/push-image.sh
```

This creates the `plexus-onboarding` ECR repository (scan on push) if needed and pushes `:latest` plus a tag for the commit.

## 4. App Runner service

1. App Runner → Create service → **Container registry → Amazon ECR** → `plexus-onboarding:latest`. Deployment trigger: **Automatic** (every push of `:latest` redeploys).
2. Service settings: port **3000**, **1 vCPU / 2 GB**, min 1 instance.
3. Health check: **HTTP**, path **`/healthz`** (it also checks the database).
4. Environment variables:

   | Name | Value |
   |---|---|
   | `NODE_ENV` | `production` |
   | `APP_URL` | `https://onboarding.plexusclinical.com` |
   | `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` | `smtp.gmail.com` / `465` / `onboarding@plexusclinical.com` (or your SES SMTP endpoint, port 465, SES SMTP username) |
   | `MAIL_FROM` | `Plexus Ancillary Services <onboarding@plexusclinical.com>` |
   | `SECURE_SHARE_URL` | your 1Password / Bitwarden request link |
   | `GOOGLE_CLIENT_ID` | optional — OAuth client with `APP_URL` as an authorized JavaScript origin |
   | `RINGCENTRAL_CLIENT_ID` / `RINGCENTRAL_FROM` | optional |
   | `DISABLE_INTERNAL_SCHEDULER` | `true` (EventBridge runs reminders instead — App Runner pauses CPU between requests) |

   And as **secrets** (reference the Secrets Manager ARNs): `DATABASE_URL`, `SMTP_PASS`, `CRON_SECRET`, and the RingCentral ones if used.
5. Security → **Instance role** with `secretsmanager:GetSecretValue` on `arn:aws:secretsmanager:<region>:<account>:secret:plexus-onboarding/*`.
6. Networking → Outgoing traffic: **Custom VPC** → create a VPC connector in the RDS VPC's **private subnets** with its own security group (the one RDS allows on 5432).
   The private subnets need a **NAT gateway** route so the app can still reach Gmail/SES, Google and RingCentral.
7. Custom domain: add `onboarding.plexusclinical.com` and create the DNS records App Runner shows you.

## 5. Reminders (EventBridge)

```
AWS_REGION=us-west-2 APP_URL=https://onboarding.plexusclinical.com CRON_SECRET='<same value as the secret>' ./deploy/aws/reminder-schedule.sh
```

Every 15 minutes EventBridge calls `/api/cron/reminders`. The app only sends between 9am and 5pm clinic time (and skips weekends if that's on in Settings → Reminders). A database lock makes sure only one copy of the app sends at a time.

## 6. Moving data from Replit (if you piloted there)

```
pg_dump --no-owner --no-acl "$REPLIT_DATABASE_URL" -Fc -f onboarding.dump
pg_restore --no-owner --no-acl -d "$RDS_DATABASE_URL" onboarding.dump
```

Run the restore before the first clinic signs in on AWS, then point the domain at App Runner. Everyone will need to sign in again (sessions are per server).

## 7. Check it

- `https://onboarding.plexusclinical.com/healthz` → `ok`
- Sign in as drimran@ with an emailed code → Settings → add a test clinic → invite yourself → accept on another browser.
- App Runner → Logs: the start line reads `email on, Google sign-in on/off, RingCentral on/off`.

## What changes later on AWS

When you're ready to store system passwords inside the portal instead of the secure-share link, add encrypted credential storage (KMS / Secrets Manager per clinic) — see `BACKEND.md`. Everything above stays the same.
