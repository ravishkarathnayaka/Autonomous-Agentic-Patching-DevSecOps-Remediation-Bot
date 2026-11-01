# DevSecOps Remediation Metrics & Vulnerability Dwell Time SLA Specification

## 1. Executive Summary

Quantifying the effectiveness of an autonomous DevSecOps remediation program requires standardized metrics. This specification defines operational formulas for tracking **Mean Time to Remediate (MTTR)**, **Mean Time to Detect (MTTD)**, **Vulnerability Dwell Time**, and **Remediation Yield Rate**.

---

## 2. Core DevSecOps Performance Metrics

### Mean Time to Detect (MTTD)
$$MTTD = \frac{1}{N} \sum_{i=1}^N (T_{detect, i} - T_{commit, i})$$
Measures the duration from when a vulnerable commit is merged into a repository to when a scanner (SAST, SCA, DAST) detects and logs the alert. Target: $< 15$ minutes in CI/CD.

### Mean Time to Remediate (MTTR)
$$MTTR = \frac{1}{N} \sum_{i=1}^N (T_{merge, i} - T_{detect, i})$$
Measures elapsed time from initial vulnerability alert generation to verified patch merge. Target for autonomous agentic remediation: $< 2$ hours for Critical / High CVEs.

### Vulnerability Dwell Time
$$\text{Dwell Time} = T_{deploy, i} - T_{commit, i} = MTTD + MTTR$$
The total lifetime of an unmitigated vulnerability within production systems.

### Autonomous Remediation Yield Rate ($Y_{auto}$)
$$Y_{auto} = \frac{\text{Passed and Merged Autonomous Patches}}{\text{Total Triaged Security Findings}} \times 100\%$$
Target benchmark: $> 85\%$ clean autonomous pass without human code intervention.

---

## 3. SLA Enforcement Tiers

| Priority | CVSS Range | EPSS Probability | Autonomous SLA | Escalation Trigger |
|---|---|---|---|---|
| **P0 - Emergency** | 9.0 - 10.0 | $\ge 0.50$ (Actively Exploited) | $< 6$ Hours | CISO & PagerDuty Urgent |
| **P1 - Critical** | 9.0 - 10.0 | $< 0.50$ | $< 24$ Hours | Security Lead Alert |
| **P2 - High** | 7.0 - 8.9 | Any | $< 48$ Hours | Component Tech Lead |
| **P3 - Medium** | 4.0 - 6.9 | Any | $< 120$ Hours | Sprint Backlog PR |
| **P4 - Low** | 0.1 - 3.9 | Any | $< 240$ Hours | Weekly Digest |
