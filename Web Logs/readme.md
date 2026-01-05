Web Traffic Analysis & Security Monitoring (Splunk)
Project Overview

This project focuses on analyzing Apache web server traffic using Splunk to understand normal user behavior, detect anomalies, and identify potential security issues. Web access logs were ingested in JSON format and visualized through multiple dashboard panels to monitor request volume, response status, user activity, and geographic distribution of traffic.

The goal of this lab is to simulate a SOC-style web traffic analysis workflow using real-world log patterns.

Data Source & Environment

Platform: Splunk Enterprise

Log Type: Apache Web Access Logs (JSON)

Index: web_traffic

Host: Web_Logs

Source: apache_logs.json

Sourcetype: _json

Total Events Ingested: 2,000

Key Metrics Observed

Total Web Requests: 2,000
Successful Responses (HTTP 200): 1,168
Client Errors (HTTP 4xx): 376
Server Errors (HTTP 5xx): 167

Technical Implementation (SPL Queries)

Below are the Search Processing Language (SPL) commands used to generate each dashboard panel.

1.Total Web Traffic (Initial Event Discovery)

This query verifies that web logs are properly ingested and confirms the total volume of web traffic.
```splunk
index=web_traffic host=Web_Logs source="apache_logs.json"
```

Result: Confirmed 2,000 total web request events.

2.Successful Web Responses (HTTP 200)

This query filters successful HTTP responses to establish a baseline of normal user activity.
```splunk
index=web_traffic host=Web_Logs source="apache_logs.json" status=200
```

Result: Identified 1,168 successful responses.

3.Client Error Analysis (HTTP 4xx)

This query identifies client-side errors such as forbidden access, missing resources, or unauthorized requests.
```splunk
index=web_traffic host=Web_Logs source="apache_logs.json"
| where status>=399 AND status<=499
```

Result: Identified 376 client error events.

Observation: Frequent access to restricted or invalid URIs indicates possible probing or misconfigured requests.

4.Server Error Analysis (HTTP 5xx)

This query tracks server-side errors that may indicate backend failures or service instability.
```splunk
index=web_traffic host=Web_Logs source="apache_logs.json"
| where status>=499 AND status<=599
```

Result: Identified 167 server error events.

Observation: Intermittent server errors may indicate application stress or abnormal request patterns.

5.Top Visited URIs

This query identifies the most frequently accessed web resources.
```splunk
index=web_traffic host=Web_Logs source="apache_logs.json"
| stats count AS "Hits" BY uri
```

Result: Top visited URIs were visualized using a column chart.

Observation: Some URIs contained unusual query parameters and external referrers, which may indicate malicious or automated access attempts.

6.Top Users by IP Address

This query identifies the most active client IP addresses based on request volume.
```splunk
index=web_traffic host=Web_Logs source="apache_logs.json"
| stats count AS "ip count" BY ip
```

Result: Multiple IP addresses showed higher request volumes, useful for identifying potential bots or scanners.

7.Web Traffic by Client IP Addresses (Geographical Analysis)

This query maps client IP addresses to geographic locations to visualize where traffic originates.
```splunk
index=web_traffic host=Web_Logs source="apache_logs.json" method=GET
| table ip
| iplocation ip
| stats count by Country
| geom geo_countries featureIdField="Country"
```

Result: Web traffic was distributed globally, with a significant concentration originating from North America.

Observation: Geographic clustering helps identify abnormal regional traffic spikes and potential threat sources.
