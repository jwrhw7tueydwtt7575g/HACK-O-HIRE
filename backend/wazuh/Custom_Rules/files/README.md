# Wazuh Custom Rules — Enterprise Banking SOC
## Deployment Guide

---

## Files in This Package

| File | What It Covers | Rule IDs |
|------|---------------|----------|
| `0001-banking_rules.xml` | Core banking fraud, transfers, MFA, privileged ops | 100001–100010 |
| `0002-threat_intel_rules.xml` | Threat intel IP matching (Vector-enriched fields) | 100100–100109 |
| `0003-database_rules.xml` | DB bulk exports, schema changes, privilege grants | 100200–100213 |
| `0004-geo_anomaly_rules.xml` | High-risk country access, geo + fraud combos | 100300–100307 |
| `0005-waf_cef_rules.xml` | BankPortal WAF / CEF format events | 100400–100410 |
| `0006-correlation_rules.xml` | Cross-dataset attack chains (load this last) | 100500–100515 |

---

## Where to Deploy on Wazuh Manager

```bash
# Copy all files to Wazuh custom rules directory
cp *.xml /var/ossec/etc/rules/

# Verify XML syntax before restart
/var/ossec/bin/ossec-logtest -t

# Restart Wazuh manager
systemctl restart wazuh-manager
```

---

## Why These Rules Are NOT in Wazuh By Default

| Category | Reason Missing from Default Wazuh |
|---|---|
| Core Banking | Wazuh has no financial transaction awareness |
| Threat Intel | Wazuh cannot match Vector-enriched `threat.*` ECS fields |
| Database Audit | Wazuh has no DB query/export/DDL rules |
| Geo Anomaly | Wazuh has zero geo-awareness out of the box |
| WAF CEF | BankPortal WAF is custom — Wazuh doesn't know it |
| Correlations | Wazuh correlations don't span banking + DB + geo together |

---

## Rule Level Guide

| Level | Meaning | Recommended Action |
|---|---|---|
| 15 | CRITICAL — active attack confirmed | Immediate page + block IP |
| 14 | HIGH — strong attack indicator | Alert SOC, investigate within 15 min |
| 13 | MEDIUM-HIGH — suspicious activity | Investigate within 1 hour |
| 12 | MEDIUM — anomaly detected | Review within 4 hours |
| 11 | LOW-MEDIUM | Daily review queue |
| 10 | LOW — informational | Weekly audit review |
| 3 | Base/parent rules | Never alert on these |

---

## Load Order (IMPORTANT)

Wazuh loads rules alphabetically. The numbering ensures correct order:
```
0001 → 0002 → 0003 → 0004 → 0005 → 0006
```
`0006-correlation_rules.xml` MUST load last because it references
parent rule IDs from all other files.

---

## Tuning Geo Rules (0004)

Edit `0004-geo_anomaly_rules.xml` rule 100301 country list
based on your organisation's acceptable countries:

```xml
<!-- Current high-risk list -->
<field name="geo.country_name" type="pcre2">^(CN|RU|KP|IR|NG|BY|SY)$</field>

<!-- Add/remove country codes (ISO 3166-1 alpha-2) as needed -->
```

---

## Prerequisites

1. Vector must be enriching logs with:
   - `threat.indicator.*` fields (from threat_intel.csv)
   - `geo.country_name` field (from GeoLite2-City.mmdb)
   - `event.dataset`, `event.action`, `event.outcome` (ECS normalization)

2. Wazuh must be receiving the Vector `clean.json` output

3. Wazuh filebeat/agent must be configured to read Vector output path:
   `/vector-output/clean.json`
