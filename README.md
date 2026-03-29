# SecureScan — Cloud Vulnerability Intelligence Platform

Scan any domain for SSL/TLS issues, security header misconfigurations, DNS records, CVE vulnerabilities, and get an overall risk score.

## Stack

- **Next.js 15** (App Router, TypeScript)
- **Supabase** (PostgreSQL + real-time subscriptions)
- **Recharts** (charts)
- **Tailwind CSS** (styling)
- **Vercel** (deployment)

## What It Scans

| Check | Source API |
|---|---|
| SSL/TLS grade | Qualys SSL Labs |
| Security headers | Direct HTTP fetch |
| DNS records | Google DNS-over-HTTPS |
| HTTP Observatory | Mozilla Observatory |
| CVE lookup | NIST NVD 2.0 API |

## Setup

### 1. Clone and install

```bash
git clone <repo>
cd securescan
npm install
```

### 2. Supabase

1. Create a project at [supabase.com](https://supabase.com)
2. Run `supabase/schema.sql` in the SQL Editor
3. Copy your project URL and keys

### 3. Environment variables

```bash
cp .env.local.example .env.local
# Fill in your Supabase credentials
```

### 4. Run locally

```bash
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000)

## Deploy to Vercel

```bash
npx vercel
```

Add all environment variables in Vercel dashboard. Set `NEXT_PUBLIC_APP_URL` to your Vercel deployment URL.

## Risk Scoring

| Score | Risk Level |
|---|---|
| 90–100 | Low 🟢 |
| 70–89 | Medium 🟡 |
| 50–69 | High 🟠 |
| 0–49 | Critical 🔴 |

**Deductions:**
- SSL grade F/T/M: severe penalty
- Missing HSTS/CSP: -15 pts each
- Missing X-Frame-Options/X-Content-Type-Options: -8 pts each
- CVE CVSS ≥ 9.0: -20 pts each
- CVE CVSS 7.0–8.9: -12 pts each
- Missing SPF/DMARC: -5 pts each

## Notes

- SSL Labs polling takes up to 4 minutes for uncached domains
- Mozilla Observatory takes 30–60 seconds
- NVD API rate limit: 5 req/30s without key, 50/30s with key (free)
- `vercel.json` sets extended timeouts for slow APIs
# cis-project
