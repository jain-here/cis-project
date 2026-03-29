# Refactored Headers Analyzer - Technical Reference

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────┐
│                      GET /api/headers                          │
├────────────────────────────────────────────────────────────────┤
│ 1. Extract domain from URL                                      │
│ 2. Check CDN list → isCdnManagedDomain()                       │
│ 3. Fetch with retry → fetchWithRetry()                         │
│ 4. Parse headers from response                                 │
│ 5. Analyze headers → analyzeHeaders()                          │
│    a. Count missing critical headers                           │
│    b. For each missing header:                                 │
│       - Compute severity → computeSeverity()                   │
│       - Add to Map (deduplicates by key)                       │
│    c. Check fingerprinting issues (X-Powered-By, Server)       │
│ 6. Calculate risk → calculateRiskSummary()                     │
│ 7. Build notes (CDN warning, redirect info)                    │
│ 8. Return structured JSON                                      │
└────────────────────────────────────────────────────────────────┘
```

---

## Data Structures

### HeaderConfig
Controls behavior of each security header.

```typescript
interface HeaderConfig {
  name: string;              // lowercase header name (e.g., 'strict-transport-security')
  display: string;           // human-readable name (e.g., 'Strict-Transport-Security')
  description: string;       // what it does
  recommendation: string;    // how to fix
  baselineSeverity: 'high' | 'medium' | 'low' | 'info';
  importance: 'critical' | 'important' | 'standard' | 'advisory';
}
```

### Finding
The issue/vulnerability identified in headers.

```typescript
interface Finding {
  category: 'headers';
  title: string;             // Issue title
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;       // Detailed explanation
  mitigation: string;        // How to fix
  confidence: 'high' | 'low'; // How certain are we
}
```

### Risk Summary
Overall assessment of header security.

```typescript
interface RiskSummary {
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  score: number; // 0-100, where 100 = most secure
}
```

---

## Function Reference

### `isCdnManagedDomain(domain: string): boolean`

**Purpose:** Detect if domain is managed by a large CDN/provider.

**Logic:**
1. Normalize domain (lowercase, remove `www.`)
2. Check against CDN_DOMAINS set (24 major providers)
3. Return true if found

**Example:**
```typescript
isCdnManagedDomain('google.com')      // → true
isCdnManagedDomain('example.com')     // → false
isCdnManagedDomain('www.facebook.com') // → true
```

**Impact:** Downgrade severity of missing headers for known CDN domains.

---

### `fetchWithRetry(url: string, maxRetries?: number, timeout?: number): Promise<Response>`

**Purpose:** Robust HTTP fetch with retry logic and redirect following.

**Parameters:**
- `url`: Full URL to fetch
- `maxRetries` (default: 2): Number of retry attempts
- `timeout` (default: 10000ms): Per-request timeout

**Logic:**
1. Set realistic User-Agent header
2. Try HEAD request (fast, headers only)
3. If HEAD fails, fallback to GET with `Range: bytes=0-1` (small response)
4. Automatic redirect following (up to 5 hops)
5. On failure: exponential backoff (500ms, 1000ms) then retry
6. Return final response or throw after all retries exhausted

**Backoff Schedule:**
- Attempt 0: immediate
- Attempt 1: fail → wait 500ms → retry
- Attempt 2: fail → wait 1000ms → retry
- Attempt 3: fail → throw error

**Example:**
```typescript
const response = await fetchWithRetry('https://example.com');
// → Follows redirects, retries on network error
// → Returns final response headers
```

---

### `computeSeverity(header: HeaderConfig, isCdn: boolean, missingCount: number): Severity`

**Purpose:** Context-aware severity calculation for missing headers.

**Logic:**
```
If CDN-managed domain:
  → return 'low'  (headers managed at edge infrastructure)

Else if not CDN:
  If header is 'high' importance:
    If 2+ critical headers missing:
      → return 'high'  (concerning pattern)
    Else:
      → return 'medium'  (could be mitigated)
  Else:
    → return baseline severity  (low/medium/low)
```

**Examples:**
```typescript
// google.com (CDN) missing HSTS
computeSeverity(hstsHeader, true, 4)  // → 'low'

// custom-site.com missing HSTS (1st critical missing)
computeSeverity(hstsHeader, false, 1) // → 'medium'

// custom-site.com missing HSTS + CSP (2+ critical)
computeSeverity(hstsHeader, false, 2) // → 'high'

// custom-site.com missing Referrer-Policy
computeSeverity(refPolicyHeader, false, 4) // → 'low' (baseline)
```

---

### `analyzeHeaders(headers: Record<string, string>, isCdn: boolean): Finding[]`

**Purpose:** Identify missing/misconfigured headers and return deduplicated findings.

**Logic:**
1. Create Map for deduplication
2. Count critical headers that are missing (used for severity context)
3. For each configured security header:
   a. Check if present in response headers
   b. If missing:
      - Compute severity (context-aware)
      - If severity not 'info': add to Map with unique key
      - Key format: `missing-${headerName}`
4. Check for fingerprinting issues:
   a. If `X-Powered-By` header exists:
      - Add finding with key `fingerprint-x-powered-by`
   b. If `Server` header has version pattern (e.g., "nginx/1.14.2"):
      - Add finding with key `fingerprint-server`
5. Return all map values (automatically deduplicated)

**Deduplication Key Strategy:**
- Missing header: `missing-strict-transport-security`
- X-Powered-By leak: `fingerprint-x-powered-by`
- Server version: `fingerprint-server`

Each key can appear only once in the result, preventing duplicates.

**Example:**
```typescript
const findings = analyzeHeaders(
  {
    'content-type': 'text/html',
    'server': 'nginx/1.14.2'
  },
  false // not CDN
);

// Result: 
// [
//   { title: 'Strict-Transport-Security header missing', severity: 'high', ... },
//   { title: 'Content-Security-Policy header missing', severity: 'high', ... },
//   { title: 'Server Version Information Exposed', severity: 'info', ... }
// ]
```

---

### `calculateRiskSummary(findings: Finding[], isCdn: boolean): { riskLevel, score }`

**Purpose:** Compute overall risk level and score from findings.

**Logic:**
```
If CDN-managed domain:
  count HIGH-severity findings
  if highCount > 1:
    → { riskLevel: 'medium', score: 65 }
  else:
    → { riskLevel: 'low', score: 85 }

Else (non-CDN):
  count HIGH and MEDIUM findings
  if highCount >= 2:
    → { riskLevel: 'high', score: 50 }
  else if highCount === 1 OR mediumCount >= 2:
    → { riskLevel: 'medium', score: 65 }
  else:
    → { riskLevel: 'low', score: 85 }
```

**Score Interpretation:**
- **85-100:** Low risk (secure)
- **65-84:** Medium risk (needs attention)
- **50-64:** High risk (security gaps)
- **0-49:** Critical risk (severe issues)

**Examples:**
```typescript
// google.com: CDN with 4 missing headers (all downgraded to LOW)
calculateRiskSummary([{ severity: 'low' }, ...], true)
// → { riskLevel: 'low', score: 85 }

// example.com: custom site missing HSTS + CSP (2 HIGH)
calculateRiskSummary([
  { severity: 'high' }, // HSTS
  { severity: 'high' }, // CSP
], false)
// → { riskLevel: 'high', score: 50 }

// startup.io: custom site with 1 missing Referrer-Policy (LOW)
calculateRiskSummary([{ severity: 'low' }], false)
// → { riskLevel: 'low', score: 85 }
```

---

## Response Structure

### Success Response
```json
{
  "headers": {
    "content-type": "text/html",
    "cache-control": "public, max-age=3600",
    ...
  },
  "findings": [
    {
      "category": "headers",
      "title": "Strict-Transport-Security header missing",
      "severity": "high",
      "description": "...",
      "mitigation": "...",
      "confidence": "high"
    }
  ],
  "summary": {
    "riskLevel": "medium",
    "score": 65
  },
  "notes": [
    "Final response after https://example.com (followed redirects)."
  ]
}
```

### Error Response
```json
{
  "error": "fetch failed",
  "headers": {},
  "findings": [],
  "summary": {
    "riskLevel": "unknown",
    "score": null
  },
  "notes": []
}
```

---

## Testing Guide

### Test Case 1: CDN Domain
**Input:** `url=https://google.com`
**Expected:**
- `isCdnManagedDomain()` returns `true`
- All missing header severities downgraded to `low`
- `riskLevel: 'low'`, `score: 85`
- Notes include CDN warning

### Test Case 2: Custom Site with Critical Issues
**Input:** `url=https://custom-site.example.com` (no HSTS, no CSP)
**Expected:**
- `isCdnManagedDomain()` returns `false`
- HSTS finding: `severity: 'high'`
- CSP finding: `severity: 'high'`
- `riskLevel: 'high'`, `score: 50`

### Test Case 3: Fingerprinting Issues
**Input:** `url=https://example.com` (Server header: "Apache/2.4.41", X-Powered-By: "PHP/7.4")
**Expected:**
- Finding: "Server Version Information Exposed" (`severity: 'info'`)
- Finding: "Technology Stack Exposed (X-Powered-By)" (`severity: 'info'`)
- No duplicates of same fingerprinting type

### Test Case 4: Redirect Following
**Input:** `url=https://example.com` (301 → https://www.example.com)
**Expected:**
- `fetchWithRetry()` follows redirect automatically
- Headers analyzed from final response
- Notes indicate redirect was followed

---

## Performance Considerations

| Aspect | Value | Notes |
|--------|-------|-------|
| Timeout per request | 10s | Generous for slow servers |
| Max retries | 2 | Total 3 attempts (0, 1, 2) |
| Backoff delays | 500ms, 1000ms | Exponential |
| Total max time | ~13s | 10s + 0.5s + 10s + 1s + 10s |
| CDN list size | 24 entries | O(1) lookup in Set |
| Headers to check | 6 | O(6) = O(1) |
| Overall complexity | O(1) | No loops over findings |

---

## Extending the Code

### Add a New Security Header
```typescript
const SECURITY_HEADERS: HeaderConfig[] = [
  // ... existing headers ...
  {
    name: 'x-permitted-cross-domain-policies',
    display: 'X-Permitted-Cross-Domain-Policies',
    description: 'Restricts cross-domain requests from Flash/PDF.',
    recommendation: 'Add `X-Permitted-Cross-Domain-Policies: none`.',
    baselineSeverity: 'low',
    importance: 'standard',
  },
];
```

### Add a New CDN Provider
```typescript
const CDN_DOMAINS = new Set([
  // ... existing domains ...
  'cloudflare.com',
  'my-cdn-provider.com',
]);
```

### Add Custom Fingerprinting Check
```typescript
// In analyzeHeaders()
if (headers['x-aspnet-version']) {
  findingsMap.set('fingerprint-aspnet', {
    category: 'headers',
    title: '.NET Version Exposed',
    severity: 'info',
    // ...
  });
}
```

---

## Migration from Old Code

If migrating from the old `mapHeaderSeverity()` function:

```typescript
// Old (remove)
const severity = mapHeaderSeverity(secHeader.name);

// New (replace with)
const severity = computeSeverity(
  secHeader,
  isCdnManagedDomain(domain),
  missingCriticalCount
);
```

The old function mapped globally without context. The new approach is aware of:
1. Which domain is being scanned
2. How many critical headers are missing (pattern detection)
3. Whether it's a CDN-managed domain (infrastructure consideration)

---

## Summary

The refactored analyzer provides:
- ✓ Context-aware severity assessment
- ✓ CDN infrastructure recognition
- ✓ Retry + redirect handling
- ✓ Deduplication via Map
- ✓ Modular, testable functions
- ✓ Clear error handling
- ✓ Extensible design

This results in **accurate, actionable** scan reports instead of false-positive-riddled ones.
