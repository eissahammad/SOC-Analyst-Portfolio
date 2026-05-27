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

## Detection Logic

The following Splunk query was used to identify multiple failed VPN login attempts followed by a successful authentication for the same user account:

```spl
index=main sourcetype=fortigate_event
("SSL user failed to logged in" OR "added to auth logon")
| eval activity=if(searchmatch("failed"),"Failed Login","Successful Login")
| stats count(eval(activity="Failed Login")) as fail_count count(eval(activity="Successful Login")) as success_count by user
| where fail_count >= 2 AND success_count >= 1
```

### Detection Query Result

![VPN Detection Query](screenshots/vpn-detection-query.png)

---

## Investigation Process

After the alert was generated, additional investigation was performed to validate whether the activity represented a real compromise or legitimate user behavior.

The investigation focused on:
- authentication timeline analysis
- historical user activity
- source IP consistency
- validation of successful authentication behavior

### Authentication Timeline Investigation

The following investigation timeline showed multiple failed login attempts followed by a successful authentication for the same user account within a short period of time.

![VPN Investigation Timeline](screenshots/vpn-investigation-timeline.png)

---

### Correlation Rule Configuration

A correlation rule was configured in Splunk Enterprise Security to generate a notable event when multiple failed VPN logins were followed by a successful authentication.

![VPN Correlation Rule](screenshots/vpn-correlation-rule.png)

---

### Alert Generation

The correlation rule successfully generated a high-severity notable event for investigation.

> Note:
> Splunk Enterprise Security automatically associated multiple MITRE ATT&CK tactics with technique T1078 (Valid Accounts). Although several tactics were displayed by the platform, the actual investigation context primarily aligned with Initial Access because no persistence, privilege escalation, or defense evasion activity was observed.

![VPN Alert Details](screenshots/vpn-alert-details.png)

---

### Source IP and Authentication Validation

Additional investigation confirmed consistent source IP usage and historical successful authentication activity for the same user account.

This behavior supported the conclusion that the activity was consistent with legitimate user behavior rather than malicious compromise.

![VPN Source IP Analysis](screenshots/vpn-source-ip-analysis.png)
