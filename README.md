# 📲 Threat Hunting Scenario: Unauthorized Remote Access via AnyDesk

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- AnyDesk
  
## 🎯 Scenario

SOC received a tip from the helpdesk team: a workstation displayed an AnyDesk pop-up. Since remote administration tools (RATs) are not approved, a threat hunt was initiated to detect AnyDesk installation and usage.

## 🔎 High-Level IoC Discovery Plan
1.	Check  `DeviceFileEvents` for `AnyDesk.exe` or `anydesk.msi`.
2.	Check  `DeviceProcessEvents` for `anydesk.exe` process creation.
3.	Check  `DeviceNetworkEvents` for outbound traffic to `AnyDesk` servers.

---   

## 📑 Steps Taken

## 1. Search for AnyDesk process activity

Looked for any file that had the string "AnyDesk" in its name within the `DeviceFileEvents` table. Found evidence that user labusertest downloaded and launched an installer `AnyDesk.exe` in their Downloads folder. Suspicious traffic was also initiated. These events began at:

Query to locate events: `2025-08-24T08:00:12.1056409Z`


```kusto
DeviceProcessEvents
| where DeviceName == "windows-target-"
| where FileName contains "AnyDesk"
| where Timestamp >= datetime(2025-08-24T08:00:12.1056409Z)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```

## 2. Detect AnyDesk Silent installation

Queried process execution logs to see if AnyDesk was installed or launched. Account, labusertest executed `AnyDesk.exe` in silent installation mode. Later logs show `anydesk.exe` running under their profile.
Query used to locate event: 

```kusto
DeviceProcessEvents  
| where DeviceName == "windows-target-"
| where ProcessCommandLine contains "AnyDesk.exe  /S"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc

```

## 3. Identify AnyDesk utilization

```kusto
DeviceProcessEvents
| where DeviceName == "windows-target-"
| where InitiatingProcessAccountName == "labusertest"
| where FileName has_any ("anydesk")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine, Account = InitiatingProcessAccountName
``` 


## 4. Detect AnyDesk network connections

Checked for suspicious network traffic tied to AnyDesk usage. Found outbound connections initiated by anydesk.exe to `185.229.191.44` over port `443`.

```kusto
DeviceNetworkEvents
| where DeviceName == "windows-target-"
| where InitiatingProcessFileName == "anydesk.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc

```  
## Chronological Events

**1. File Download – AnyDesk Installer**
- Timestamp: 2025-08-24T08:00:12.1056409Z
- Event: User labusertest downloaded AnyDesk.exe to the Downloads folder.


**2. Process Execution – AnyDesk Setup**
- Timestamp: 2025-08-24T08:13:58.6399872Z
- Event: User labusertest executed AnyDesk.exe initiating an AnyDesk installation.


**3. Process Execution – AnyDesk Launched**
- Timestamp: 2025-08-24T08:00:14.7556654Z 
- Event: anydesk.exe process was created, confirming the browser launch.


**4. Network Connection – Detect AnyDesk established connections** 
- Timestamp: 2025-08-24T08:00:20.498343Z
- Event: Outbound connection from anydesk.exe to 185.229.191.44.

## 📌 Summary

Logs confirmed that user jdoe installed `AnyDesk.exe` in their Downloads folder and launched it, establishing a session with remote IP `185.229.191.44`.

## 🚨 Response Taken

-	AnyDesk removed from the system
-	User account investigated for potential insider threat
-	Firewall updated to block AnyDesk-related connections.

## 📌 Revision History

| Version | Change                  | Date         | Author      |
|---------|-------------------------|--------------|-------------|
| 1.0     | Initial draft | August 24, 2025 | Tinan Makadjibeye |



