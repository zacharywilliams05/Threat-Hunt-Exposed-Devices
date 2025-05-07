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
```kql
DeviceInfo
| where IsInternetFacing == 1
| project DeviceName
| sort by DeviceName asc
| summarize UniqueDeviceCount = dcount(DeviceName)

