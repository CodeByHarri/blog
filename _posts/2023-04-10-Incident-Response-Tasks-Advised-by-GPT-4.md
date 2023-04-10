# Incident Response Playbooks by GPT4
> Can GPT-4 come up with valuable IR playbooks?

- toc: true
- badges: false
- comments: true
- categories: [CyberSecurity]

## Atypical Travel Alert Response Playbook

**Objective:** To respond to an "Atypical Travel" alert by determining if it's a false positive or a genuine security incident.

**Scope:** This playbook applies to SOC analysts and other team members responsible for responding to security incidents in an environment using Microsoft Defender, Azure Sentinel, and KQL.

**1. Alert Description and Background**

The "Atypical Travel" alert is triggered when a user logs in from a location significantly different from their typical logon location in a short time frame. This may indicate unauthorized access, credential compromise, or a false positive due to remote work, VPNs, or other legitimate reasons.

**2. Initial Triage and Assessment**

Upon receiving the alert, perform the following steps:

a. Review the alert details, such as the user's account, source IP address, login timestamp, and recent login locations.

b. Check for any contextual information, like user-reported travel plans or known VPN usage.

**3. KQL Queries for Investigation**

Use the following KQL queries to gather relevant data from Azure Sentinel to determine if this is a false positive or an actual security incident.

a. Retrieve the user's recent sign-in history:

```
SigninLogs
| where TimeGenerated >= ago(7d) // last 7 days
| where UserPrincipalName == "<username>"
| project TimeGenerated, UserPrincipalName, IPAddress, Location
| sort by TimeGenerated desc

```


b. Calculate the distance between the current login location and previous login locations:

```
SigninLogs
| where TimeGenerated >= ago(7d) // last 7 days
| where UserPrincipalName == "<username>"
| extend distance_in_miles = geo_distance_2points(Latitude, Longitude, <current_latitude>, <current_longitude>, 'mi')
| project TimeGenerated, UserPrincipalName, IPAddress, Location, distance_in_miles
| sort by TimeGenerated desc
```
c. Check for other logins from the same IP address:

```
SigninLogs
| where TimeGenerated >= ago(7d) // last 7 days
| where IPAddress == "<source_ip>"
| project TimeGenerated, UserPrincipalName, IPAddress, Location
| sort by TimeGenerated desc
```
d. Check for failed logins within the last 24 hours:

```
SigninLogs
| where TimeGenerated >= ago(24h) // last 24 hours
| where UserPrincipalName == "<username>" and ResultType !in ('0') // exclude successful logins
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, ResultDescription
| sort by TimeGenerated desc
```
**4. Analysis and Decision Making**
Analyze the results of the KQL queries to determine if the alert is a false positive or not:
a. If the distance between the current login location and previous locations is reasonable and other logins from the same IP address show no suspicious activity, it may be a false positive.

b. If the user has a history of failed login attempts or there are logins from other users originating from the same IP address, it may be an actual security incident.

**5. Response Actions**

Based on the analysis, perform the appropriate actions:
a. If it's a false positive, document the findings, update the alert status, and inform relevant stakeholders.

b. If it's an actual security incident, initiate your organization's incident response plan, which may include actions such as resetting the user's password, enabling multi-factor authentication, blocking the suspicious IP address, and conducting a further investigation.

**6. Post-Incident Activities**

Review the incident and update your organization's cybersecurity policies, procedures, and training materials to prevent similar incidents in the future. Consider tuning your alert rules

## Authentication Methods Changed for Privileged Account 

**Objective:** To respond to an "Authentication Methods Changed for Privileged Account" alert by determining if it's a false positive or a genuine security incident.

**Scope:** This playbook applies to SOC analysts and other team members responsible for responding to security incidents in an environment using Microsoft Defender, Azure Sentinel, and KQL.

**1. Alert Description and Background**

The "Authentication Methods Changed for Privileged Account" alert is triggered when changes in authentication methods, such as enabling or disabling multi-factor authentication (MFA), are detected for privileged accounts. This may indicate unauthorized account modification or a false positive due to legitimate administrative activities.

**2. Initial Triage and Assessment**

Upon receiving the alert, perform the following steps:

a. Review the alert details, such as the affected privileged account, timestamp of the change, and the specific authentication method changes.

b. Check for any contextual information, like planned maintenance or recent security policy updates.

**3. KQL Queries for Investigation**

Use the following KQL queries to gather relevant data from Azure Sentinel to determine if this is a false positive or an actual security incident.

a. Retrieve the recent audit logs for the affected privileged account:

```
AuditLogs
| where TimeGenerated >= ago(7d) // last 7 days
| where TargetPrincipalName == "<privileged_account>"
| project TimeGenerated, OperationName, TargetPrincipalName, InitiatingUserPrincipalName, IPAddress, Result
| sort by TimeGenerated desc
```
b. Check for other changes related to privileged accounts:

```
AuditLogs
| where TimeGenerated >= ago(7d) // last 7 days
| where TargetPrincipalName has_any ("<privileged_account1>", "<privileged_account2>", ...)
| project TimeGenerated, OperationName, TargetPrincipalName, InitiatingUserPrincipalName, IPAddress, Result
| sort by TimeGenerated desc
```
c. Review logins from the initiating user:

```
SigninLogs
| where TimeGenerated >= ago(7d) // last 7 days
| where UserPrincipalName == "<initiating_user>"
| project TimeGenerated, UserPrincipalName, IPAddress, Location
| sort by TimeGenerated desc
```
**4. Analysis and Decision Making**
Analyze the results of the KQL queries to determine if the alert is a false positive or not:
a. If the authentication method changes were performed by a legitimate administrator during a planned maintenance window or as part of recent security policy updates, it may be a false positive.

b. If the initiating user has suspicious login activity or there are other unexpected changes to privileged accounts, it may be an actual security incident.

**5. Response Actions**

Based on the analysis, perform the appropriate actions:
a. If it's a false positive, document the findings, update the alert status, and inform relevant stakeholders.

b. If it's an actual security incident, initiate your organization's incident response plan, which may include actions such as reverting the authentication method changes, resetting the affected account's password, reviewing access rights, and conducting a further investigation.

**6. Post-Incident Activities**
Review the incident and update your organization's cybersecurity policies, procedures, and training materials to prevent similar incidents in the future. Consider tuning your alert rules to reduce false positives and ensure timely detection of unauthorized changes to privileged accounts.

## Unfamiliar Sign-In Properties Alert Response Playbook

**Objective:** To respond to an "Unfamiliar Sign-In Properties" alert by determining if it's a false positive or a genuine security incident.

**Scope:** This playbook applies to SOC analysts and other team members responsible for responding to security incidents in an environment using Microsoft Defender, Azure Sentinel, and KQL.

**1. Alert Description and Background**

The "Unfamiliar Sign-In Properties" alert is triggered when a user logs in with a combination of properties that are unusual for their account. This may include unfamiliar devices, operating systems, browsers, or sign-in locations. This may indicate unauthorized access, credential compromise, or a false positive due to changes in the user's environment or other legitimate reasons.

**2. Initial Triage and Assessment**

Upon receiving the alert, perform the following steps:

a. Review the alert details, such as the user's account, source IP address, login timestamp, device, operating system, browser, and recent login properties.

b. Check for any contextual information, like user-reported device changes or recent travels.

**KQL Queries for Investigation**

Use the following KQL queries to gather relevant data from Azure Sentinel to determine if this is a false positive or an actual security incident.

a. Retrieve the user's recent sign-in history:

```
SigninLogs
| where TimeGenerated >= ago(7d) // last 7 days
| where UserPrincipalName == "<username>"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, DeviceDetail, OperatingSystem, Browser
| sort by TimeGenerated desc
```
b. Identify unique devices, operating systems, and browsers used by the user:

```
SigninLogs
| where TimeGenerated >= ago(30d) // last 30 days
| where UserPrincipalName == "<username>"
| summarize count() by DeviceDetail, OperatingSystem, Browser
| sort by count_ desc
```
c. Check for other logins from the same IP address:

```
SigninLogs
| where TimeGenerated >= ago(7d) // last 7 days
| where IPAddress == "<source_ip>"
| project TimeGenerated, UserPrincipalName, IPAddress, Location
| sort by TimeGenerated desc
```
d. Check for failed logins within the last 24 hours:

```
SigninLogs
| where TimeGenerated >= ago(24h) // last 24 hours
| where UserPrincipalName == "<username>" and ResultType !in ('0') // exclude successful logins
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, ResultDescription
| sort by TimeGenerated desc
```

**3. Analysis and Decision Making**

Analyze the results of the KQL queries to determine if the alert is a false positive or not:
a. If the unfamiliar sign-in properties can be explained by legitimate changes in the user's environment or recent travels, it may be a false positive.

b. If the user has a history of failed login attempts or there are logins from other users originating from the same IP address, it may be an actual security incident.

**4. Response Actions**

Based on the analysis, perform the appropriate actions:
a. If it's a false positive, document the findings, update the alert status, and inform relevant stakeholders.

b. If it's an actual security incident, initiate your organization's incident response plan, which may include actions such as resetting the user's password, enabling multi-factor authentication, blocking the suspicious IP address, and conducting a further investigation.

**5. Post-Incident Activities**

Review the incident and update your organization's cybersecurity policies, procedures, and training materials to prevent similar incidents in the future. Consider tuning your alert rules to reduce false positives