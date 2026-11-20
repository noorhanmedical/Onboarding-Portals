# Plexus Onboarding Portal

Clinic onboarding and billing onboarding for Plexus partner clinics.

Three views:
- **Clinic view** — the clinic team completes Clinic Onboarding.
- **Billing view** — the billing team completes Billing Onboarding.
- **Plexus console** — every facility with clinic and billing completion; **Open review** opens Plexus review for that facility.

- **Clinic Onboarding:** Facility Details, Add Clinician, Clinic Flows, Logins, Telephone Systems, Team, Vendors, Scheduling, Testing Day
- **Billing Onboarding:** Facility Details, Add Clinician, Billing, Logins (insurance, multi-payer and prior authorization portals)
- Shared sections (facility, clinicians, portal logins) stay in sync between both teams.

## Run

```bash
npm start          # http://localhost:3000
```

No dependencies or build step. On Replit, press **Run**.

## Files

| Path | What it is |
|---|---|
| `public/index.html` | The whole app (Preact + htm, inline CSS/JS) |
| `public/htm.js` | Vendored Preact + htm runtime |
| `server.js` | Zero-dependency static server with security headers and `/healthz` |

## Data and security

This version is a working prototype: progress is saved in the viewer's browser (localStorage).
Passwords are held in page memory only — never written to storage, logs or exports.
Do not enter real patient data. Shared multi-user data and invitations require a backend (next phase).
