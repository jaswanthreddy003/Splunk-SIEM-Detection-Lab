SSH Login Analysis & Security Monitoring

Project Overview

This section of the lab focuses on monitoring and analyzing SSH (Secure Shell) traffic to identify patterns of legitimate access and potential malicious activity. Using Splunk, we ingested and parsed SSH logs to build a comprehensive security dashboard that tracks authentication health and detects brute-force threats.


Key Metrics Tracked

Total SSH Events: 1,200

Successful Logins: 306

Failed Logins: 305

Invalid User Attempts: 286

Brute Force Leads: 303

Technical Implementation (SPL Queries)

Below are the Search Processing Language (SPL) commands used to generate the dashboard panels:

1. Event Discovery & Initial Count

To begin the investigation, I used a broad search to verify the total volume of SSH data available in the index.
```splunk
index=ssh host=SSH 
| stats count AS "Total SSH Events"
```
Result: Confirmed 1,200 total log entries.

2. Authentication Success Tracking

This query filters for successful login events to establish a baseline for authorized user behavior.
```splunk
index=ssh host=ssh Event_Type="Successful SSH Login"
```
Result: Identified 306 successful logins.

3. Authentication Failure Tracking

This query filters for failed login events to establish a baseline for authorized user behavior.
```splunk
index=ssh host=ssh Event_Type="Failed SSH Login"
```
Result: Identified 305 failed logins.

4. Multiple Failed Attempts Detection

This query specifically tracks high-frequency authentication failures that trigger security alerts.
```splunk
index=ssh host=ssh sourcetype="_json" Event_Type="Multiple Failed Authentication Attempts"
```
Result: Identified 303 instances of high-frequency failures.

5. Connection without Authentication

This identifies attempts where a connection was made but no authentication was provided, often indicative of port scanning.
```splunk
index=ssh host=ssh sourcetype="_json" Event_Type="Connection Without Authentication"
```
Result: Identified 286 events.

6. Targeted Username Analysis (Failed Logins)

To identify which accounts were under the most pressure from attackers, I visualized failed login attempts by username.
```splunk
index=ssh host=ssh Event_Type="Failed SSH Login" 
| top username limit=20
```
Observation: The "root" user was the primary target with 27 failed attempts, followed by common service accounts like "backup" and "alice".

7. Brute Force Detection by Source IP

This query identifies high-frequency failed attempts from unique IP addresses, a key indicator of automated brute-force attacks.
```splunk
index=ssh host=ssh sourcetype=_json Event_Type="Multiple Failed Authentication Attempts" 
| top limit=20 "id.orig_h"
```
Top Attacker: IP 83.195.24.226 was responsible for 4.29% of all multiple-failure events.

8. Geographical Threat Mapping

To visualize where these attacks originated globally, I used the iplocation and geom commands.
```splunk
index=ssh host=ssh sourcetype="_json" event_type="Multiple Failed Authentication Attempts" 
| table id.orig_h 
| iplocation id.orig_h 
| stats count by Country 
| geom geo_countries featureIdField="Country"
```
Observation:Significant brute-force activity was visualized originating from North America and South America and china.
