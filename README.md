# Plexus Ancillary Services — Onboarding Portal

Clinic and billing onboarding for Plexus partner clinics. One Node server (`server.js`) serves the app (`public/`) and a JSON API backed by Postgres.

## What's real

| | |
|---|---|
| **Data** | Every clinic is stored on the server. Clinic team, billing team and Plexus all work on the same copy; edits made at the same time are merged (see `public/merge.js`) and show up for the others within a few seconds. |
| **Access** | Clinic and billing users only see their own clinic and can't change invitations, reminders, requirements or verification. Plexus staff see every clinic; what they can change follows their role in Settings → Users & roles. |
| **Sign-in** | Clinic users: invitation link → create account (12+ character password) → 6-digit code by email every sign-in. Plexus staff: Google, or a 6-digit code emailed to their @plexusclinical.com address. Sessions last 12 hours of inactivity. |
| **Invitations** | Emailed from the server. Links are single-use and expire after 7 days. An email can belong to only one clinic. |
| **Reminders** | Sent by the server 9am–5pm clinic time on the schedule in Settings → Reminders. Email always; texts when RingCentral is set up. |
| **Passwords** | Never typed into the portal. Login cards collect URL, username and access level; the clinic sends each password through Plexus's secure share link, and Plexus ticks **Received**. The server also strips any `password` field it is sent. |

## Put it on Replit

1. **Import** this repo into Replit (Create → Import from GitHub → `noorhanmedical/Onboarding-Portals`).
2. **Database:** open Tools → Database and create a PostgreSQL database. Replit adds `DATABASE_URL` for you. Tables are created on first start.
3. **Secrets** (Tools → Secrets):

   | Secret | Required | Value |
   |---|---|---|
   | `APP_URL` | yes | The public address, e.g. `https://onboarding.plexusclinical.com` (used in invitation and reminder links) |
   | `MAIL_KEY` | yes | A long random string. Encrypts the email-account passwords admins save in **Settings → Email** (the normal way to set up email). Never change it once accounts are saved |
   | `SMTP_HOST` | no | Optional server-level fallback sender, e.g. `smtp.gmail.com` |
   | `SMTP_PORT` | no | `465` (only with `SMTP_HOST`) |
   | `SMTP_USER` | no | `onboarding@plexusclinical.com` |
   | `SMTP_PASS` | no | A Google **app password** for that account (Google Account → Security → 2-Step Verification on → App passwords) |
   | `MAIL_FROM` | no | `Plexus Ancillary Services <onboarding@plexusclinical.com>` |
   | `SECURE_SHARE_URL` | yes | Your 1Password or Bitwarden "request a secret" link that clinics use to send passwords |
   | `GOOGLE_CLIENT_ID` | no | Turns on "Continue with Google". Google Cloud Console → APIs & Services → Credentials → OAuth client ID (Web), with `APP_URL` as an authorized JavaScript origin |
   | `ADMIN_EMAILS` | no | Always-admin accounts. Default: onboarding@, drimran@, dralhadheri@ (plexusclinical.com) |
   | `RINGCENTRAL_CLIENT_ID`, `RINGCENTRAL_CLIENT_SECRET`, `RINGCENTRAL_JWT`, `RINGCENTRAL_FROM` | no | Turns on text reminders (RingCentral developer app with JWT auth and the SMS scope; `FROM` is the sending number) |
   | `REMINDER_TZ` | no | Default `America/Phoenix` |

4. **Run** to test, then **Deploy → Reserved VM** (already set in `.replit`) and connect your domain.
5. **First sign-in:** go to the site, enter `drimran@plexusclinical.com`, click *Email me a sign-in code*. If email isn't set up yet, the code is printed in the Replit console.

Without SMTP the server still runs: emails (codes, invitations, reminders) are printed to the console instead of sent, and the invitation panel tells you to use **Copy link**.

## Put it on AWS

Everything for AWS is in [`deploy/aws/AWS.md`](deploy/aws/AWS.md): App Runner (container from ECR) + RDS PostgreSQL + Secrets Manager + an EventBridge rule for reminders. The `Dockerfile` builds the production image; `deploy/aws/push-image.sh` and `deploy/aws/reminder-schedule.sh` do the CLI steps. No code changes between Replit and AWS — only settings.

| Extra setting | Where | Value |
|---|---|---|
| `CRON_SECRET` | AWS | Secret the reminder schedule sends to `/api/cron/reminders` |
| `DISABLE_INTERNAL_SCHEDULER` | AWS | `true` — EventBridge triggers reminders instead of the built-in timer |
| `DATABASE_SSL` | optional | `require` to force TLS on a non-RDS host (RDS gets verified TLS automatically) |

## Compliance note

Replit does not sign a HIPAA BAA. This portal holds no patient records, and it never stores system passwords, so keep it that way: don't add patient data or password fields here. To store credentials in the app later, move it to AWS under the BAA (see `BACKEND.md`).

## Develop locally

```
npm install
DATABASE_URL=postgres://user:pass@localhost:5432/onboarding npm start
npm test
```
