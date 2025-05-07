# Security Hunt Documentation

## 1. Preparation
**Goal:** Set up the hunt by defining what you're looking for.  
During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.  
**Activity:** Develop a hypothesis based on threat intelligence and security gaps (e.g., “Could there be lateral movement in the network?”).  
During the time the devices were unknowingly exposed to the internet, it’s possible that someone could have actually brute-force logged into some of them since some of the older devices do not have account lockout configured for excessive failed login attempts.

## 2. Data Collection
**Goal:** Gather relevant data from logs, network traffic, and endpoints.  
Consider inspecting the logs to see which devices have been exposed to the internet and have received excessive failed login attempts. Take note of the source IP addresses and number of failures, etc.  
**Activity:** Ensure data is available from all key sources for analysis.  
Ensure the relevant tables contain recent logs:
- DeviceInfo
- DeviceLogonEvents

## 3. Data Analysis
**Goal:** Analyze data to test your hypothesis.  
**Activity:** Look for anomalies, patterns, or indicators of compromise (IOCs) using various tools and techniques.  
Is there any evidence of brute force success (many failed logins followed by a success?) on your VM or ANY VMs in the environment?  
If so, what else happened on that machine around the same time? Were any bad actors able to log in?

## 4. Investigation
**Goal:** Investigate any suspicious findings.  
**Activity:** Dig deeper into detected threats, determine their scope, and escalate if necessary. See if anything you find matches TTPs within the MITRE ATT&CK Framework.  
You can use ChatGPT to figure this out by pasting/uploading the logs: Scenario 1: TTPs

## 5. Response
**Goal:** Mitigate any confirmed threats.  
**Activity:** Work with security teams to contain, remove, and recover from the threat.  
Can anything be done?

## 6. Documentation
**Goal:** Record your findings and learn from them.  
**Activity:** Document what you found and use it to improve future hunts and defenses.  
Document what you did.

## 7. Improvement
**Goal:** Improve your security posture or refine your methods for the next hunt.  
**Activity:** Adjust strategies and tools based on what worked or didn’t.  
Anything we could have done to prevent the thing we hunted for? Any way we could have improved our hunting process?

## Timeline Summary and Findings
### Executive Summary:
- Number of devices that were internet facing: **234**
- Evidence of brute force attempts from remote IP addresses: **Yes**
- Number of successful logons from remote IP addresses: **4**
- Number of endpoints breached: **4**

### Remediation Recommendations:
- Configure firewalls and NSG to block public traffic.
- Implement account lockout policy.
- Disable root accounts from network logon where possible.
- Disable guest account where possible. Use a strong password if a guest account is necessary.

### Relevant TTPs:
1. **# of Internet Facing Devices**
   - Tactic: Discovery
   - Technique: Network Service Scanning (T1046)

2. **Checking for Failed Logons**
   - Tactic: Credential Access
   - Technique: Brute Force (T1110)

3. **Discovery of Brute Force Success**
   - Tactic: Credential Access
   - Technique: Brute Force (T1110)

4. **Investigating Machines for Malware and Privilege Escalation**
   - Tactic: Execution and Privilege Escalation
   - Technique: Malicious File Execution (T1203) / Exploitation of Vulnerability (T1203)

5. **Investigating All Remote IP Addresses for Brute Force Attacks**
   - Tactic: Reconnaissance
   - Technique: Active Scanning (T1595)

## Queries and Results
### # of Internet Facing Devices
![Devicecount](https://github.com/user-attachments/assets/93cf47dc-0104-4670-9ebc-75c445f87f38)

```kql
DeviceInfo
| where IsInternetFacing == 1
| project DeviceName
| sort by DeviceName asc
| summarize UniqueDeviceCount = dcount(DeviceName)
```

This query filters down the hosts that are internet facing and then counts the unique device name field to present the total number of hosts that have been internet facing for the last 30 days. This may give us a list of endpoints on which we want to focus. Are any of these endpoints business critical?

### Checking for Failed Logons

![Failedlogoncount](https://github.com/user-attachments/assets/60f06bf7-1354-4a96-81de-8ba987696014)

```kql
DeviceLogonEvents
| where LogonType has_any ("Network", "Interactive", "RemoteInteractive","NetworkClearText")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```
This query looks for failed logons specifically from remote or suspicious logon types. It filters only for failed logons and then counts the attempts for evidence of possible brute forcing attempts.

Distinct Device Count for Failed Logons

![Numberofdevices](https://github.com/user-attachments/assets/a28c7720-1c56-4965-b112-6aa739fa5bd8)

```kql
DeviceLogonEvents
| where LogonType has_any ("Network", "Interactive", "RemoteInteractive","NetworkClearText")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| distinct DeviceName
| count
```
This query builds off the previous to show the possible number of devices that may have been brute forced. Again, this will help give us some scope to know the impact of the issue.

Discovery of Brute Force Success
![Successful Logons](https://github.com/user-attachments/assets/caaadc56-54c5-481e-9f48-ebca347f9ba1)

```kql
let RemoteIPsinQuestion = dynamic(["218.92.0.187","218.92.0.186","218.92.0.153","43.251.215.9","196.251.84.225","80.94.95.90","115.245.191.82","185.243.96.107","45.88.186.251"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "NetworkClearText")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsinQuestion)
```
Based on the results of the Failed Logons query, we can look at the remote IP addresses with the most failed logons. We want to see if these remote IPs were able to successfully log on at some point.

The results show 12 events where remote IP addresses with a high number of failed logons were able to successfully log in. Unsurprisingly, they were able to log on “root” and “guest” accounts. Most likely they had weak passwords. Judging by the timing of the events, there were probably only 4 total successful logons in the last 30 days.

Next, we investigate these machines and check for any malware, privilege escalation, and other IOCs.

Outside of a lab environment, and assuming adequate resources, we would want to investigate all of the remote IP addresses that attempted brute force attacks.

