# Backend spec — Plexus Ancillary Services Onboarding

The UI in `public/index.html` is the source of truth for look and behavior. The backend must make the
preview behaviors real without changing the UI. Everything below is already working in the preview
(browser storage) and must be persisted and enforced on the server.

## Accounts and sign-in

| Who | How they sign in |
|---|---|
| Plexus staff | **Google only** (OAuth / OpenID Connect). Only Google accounts listed in *Users & roles* may sign in. `onboarding@plexusclinical.com` is the owner and cannot be removed or demoted. |
| Clinic team / billing team | **Invitation link → create account**: full name + password (12+ chars) + required two-step verification (6-digit email code or authenticator app). They may instead link a Google account with the same email. |

- Invitation links: one per person, single-use, expire after 7 days, tied to facility + team (`clinic` or `billing`). Resend issues a new token and invalidates the old one. Removing an invitee revokes access.
- Passwords: argon2id (or bcrypt cost ≥ 12). Never logged or returned. Lockout/rate limit after repeated failures. Password reset by email.
- Sessions: httpOnly, Secure, SameSite=Lax cookies. Server enforces role:
  - Plexus roles (Admin, Coordinator, Reviewer, Billing) per the permission matrix in *Users & roles*.
  - Clinic members see only Clinic Onboarding for their facility; billing members only Billing Onboarding for their facility.
- The console shows each invitee's status: *Invited · no account yet* / *Account created · last sign-in* / *Google account*.

## Facilities and shared data

- One onboarding record per facility. Clinic and billing teams edit the **same** record; shared items
  (practice details, locations, clinicians, logins, insurance/multi-payer/prior-auth portals) appear in both views.
- Autosave every change (debounced) so partial progress survives closing the browser; return users see
  "Welcome back — your progress was saved …".
- Optimistic concurrency with a `version` field. On conflict return 409 and merge per item.

## Attribution ("Updated by")

Every shared item stores `_by = { name, team: 'Clinic team'|'Billing team'|'Plexus team', tk, at }` from the
**signed-in user** (server-set, never trusted from the client). When a different team overwrites an item,
keep the previous value summary in `_prev`. The UI shows "Name – Team · time" on every shared card.

## Cross-team review on submit

When a team submits, list shared items last changed by the other team that this team hasn't acknowledged
(`ack[team][itemKey] >= _by.at`). For each: **Agree** (acknowledge) or **Disagree** (sets `_dispute`
with who/when, their value and the team's earlier value). Submission continues; disputes appear in
Plexus review under *Disputed between teams* with **Mark resolved**. Everything is written to the audit log.

## Requirements

Plexus requirement defaults (per team) plus per-facility overrides decide which checks block completion,
progress and submit (rule keys in `REQ_RULES`).

## Reminders (automated)

Settings: enabled, every N business/calendar days, recipients (clinic, billing or both), stop on submit,
max per team, no weekends, send-from address (default `onboarding@plexusclinical.com`); per-facility override.
- Scheduler (EventBridge, hourly) computes due reminders with the same logic as `reminderPlan()` and emails
  every invitee of the unfinished team (Gmail API from the Workspace account, or SES with that sender).
- Log each send (`reminders[]`: at, team, recipients, automatic or sent by) — shown in review.
- "Send now" in the console triggers one immediately.

## Google Workspace

- Google OAuth client restricted to approved accounts; add/remove accounts in *Users & roles*.
- Outgoing invitation and reminder emails are sent from `onboarding@plexusclinical.com` (Gmail API with
  domain-wide delegation or SMTP relay). Shared mailboxes such as `billing@plexusclinical.com` sign in like any other Google account.

## Credentials

Portal/EMR/phone passwords are never stored in the database, JSON or logs: write-only to AWS Secrets Manager;
only Admins may reveal, and every reveal is audited.
