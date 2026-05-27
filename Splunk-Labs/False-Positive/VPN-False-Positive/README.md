# VPN failed logins followed by Success –  false positive Analysis

## Lab Overview

This lab demonstrates the investigation of suspicious VPN authentication activity detected in Splunk Enterprise Security.  

The alert was triggered after multiple failed VPN login attempts were followed by a successful authentication for the same user account within a short time window.

Although the activity initially appeared suspicious and was treated as a high-severity event, further investigation determined that the behavior was consistent with a legitimate user entering incorrect credentials before successfully authenticating.

The activity was ultimately classified as a false positive after validating:
- historical user behavior
- authentication patterns
- source IP context
- absence of malicious follow-up activity

---

## Environment

| Component | Details |
|---|---|
| SIEM Platform | Splunk Enterprise Security |
| Data Source | FortiGate VPN Logs |
| Index | main |
| Sourcetype | fortigate_event |

---

## Detection Scenario

The detection logic identified:
- multiple failed VPN login attempts
- followed by a successful login
- for the same user account
- within a short time window

This behavior can potentially indicate:
- brute-force activity
- credential stuffing
- compromised credentials

As a result, the event was initially treated as a high-severity authentication alert requiring investigation.
---


