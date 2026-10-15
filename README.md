# WinEvent Triage — Windows Security Event Log Triage Tool

A browser-based, beginner-friendly tool that turns a **Windows Event Viewer CSV export** into an
easy-to-read **SOC-style triage report**.

You export events from Windows, drop the CSV into the page, and the tool explains what it found:
which Event IDs matter, which accounts and hosts are involved, what patterns are worth a closer
look, why they might matter, what innocent explanations exist, and what an analyst would check next.

It is an **educational triage tool**. It highlights activity that deserves investigation. It never
claims to prove that a system has been compromised.

---

## Privacy first

> **Your Windows security logs are analysed locally in your browser. Files are not uploaded or transmitted anywhere.**

* All parsing and analysis happens in JavaScript inside your own browser tab.
* There is **no backend, no database, no analytics, no tracking, no cookies, no advertising and no telemetry**.
* The tool makes **no network requests at all** — not to an AI provider, not to any API, not to itself.
* Nothing you load is stored, and nothing survives a page refresh or a tab close.

You can verify this yourself: open `script.js` and search for `fetch`, `XMLHttpRequest`, `WebSocket`
or `sendBeacon`. You will not find them.

---

## Educational disclaimer

> **Educational SOC triage tool. Findings indicate activity that may deserve investigation and do not prove malicious behaviour.**
>
> **Only analyse logs from systems you own or are authorised to investigate.**

The central lesson of this project is that:

> **A detection is a reason to investigate, not proof that an attacker is present.**
>
> **One security event rarely tells the entire story. Analysts build context by correlating multiple events.**
>
> **Detection tells an analyst where to look. Investigation determines what actually happened.**

Windows Event IDs record *that something happened*. They cannot record *why*. The same Event ID 4625
appears when a tired user mistypes a password and when an attacker guesses it. Context is everything,
and context is exactly what a triage tool helps you gather.

---

## What the tool does

1. You export events from **Windows Event Viewer** as a CSV file.
2. You drop that CSV onto the page (or load one of the safe demo datasets).
3. The browser parses the CSV and recognises the Event IDs it understands.
4. It correlates related events — for example repeated failures followed by a success.
5. It produces a triage report: summary cards, an itemised investigation score, detailed findings,
   charts, a timeline, a filterable event table, and guidance on what to do next.

Every finding contains:

| Field | Meaning |
|---|---|
| Alert name | What pattern was detected |
| Severity | Investigative priority: Informational, Low, Medium or High |
| Event ID(s) | Which Windows events triggered it |
| Account | The account involved (target account where the message makes it clear) |
| Time | Timestamp or time range, when timestamps could be read |
| Source IP / Computer | Where available in the data |
| Observed activity | Exactly what was seen, with counts and the configured threshold |
| Event sequence | For correlations, the order of events (e.g. `4720 → 4732`) |
| Why this could matter | Why an analyst would care |
| Possible benign explanations | Perfectly normal reasons the same pattern appears |
| Suggested investigation | Concrete next steps |

---

## Project purpose

This project exists to teach, not to impress. Specifically it aims to help you understand:

* what common Windows security Event IDs mean in plain English;
* how SOC analysts work through authentication, account and privilege activity;
* how **correlating** several events produces far more insight than reading them one at a time;
* why **false positives** are normal and how thresholds create them;
* how to decide what genuinely deserves escalation;
* how to be honest about the limits of the evidence you have.

It is deliberately **not** an "AI detects hackers" product. There is no machine learning, no
probability score, and no claim of certainty anywhere in the interface.

---

## Running it locally on Windows (no installation required)

You need **nothing installed**. No Node.js, no Python, no npm, no build step, no libraries.
Only a modern browser (Microsoft Edge, Google Chrome or Mozilla Firefox) and the three files in this
folder.

### Option A — the simplest way

1. Download or copy this whole folder to your computer (for example to `Documents\WinEvent-Triage`).
2. Double-click **`index.html`**.
3. It opens in your default browser and is ready to use.

> The **"Load ... Sample"** buttons work even when you open the page this way, because safe copies of
> the demo datasets are embedded inside `script.js`. This is deliberate: browsers block a local page
> from reading other files on disk, so an embedded copy is what makes the one-click demos work.

### Option B — upload your own exports

Exactly the same as Option A, then use the drop zone:

1. Click the drop zone (or press <kbd>Enter</kbd> while it is focused) and pick your CSV file, **or**
2. drag the `.csv` file from File Explorer straight onto the drop zone.

You can also open the `samples` folder and drag one of those `.csv` files onto the page to see the
tool work with a real file rather than the embedded copy.

### Optional: host it as a static website

Because there is no backend, you can publish these files anywhere that serves static content — for
example GitHub Pages, Cloudflare Pages or Netlify. Upload `index.html`, `styles.css`, `script.js` and
the `samples` folder, and the site works. Nothing needs configuring.

---

## What Windows Event Logs are

Windows keeps detailed records of what happens on a system. The **Security** log is the one most
relevant to defenders. Each entry has:

* an **Event ID** — a number identifying what kind of thing happened (for example 4625 = a logon failed);
* a **timestamp**;
* a **provider** (which Windows component wrote it);
* a **computer name**;
* a **user / account**, when relevant;
* a **Message** — the human-readable detail, often containing the account, source IP address, logon
  type, group name or process path.

Two things make these logs genuinely useful:

1. **They are authoritative for what Windows recorded.** If auditing is switched on, the events exist.
2. **They can be correlated.** Individual events are weak evidence; sequences of events are strong
   evidence. That is the whole idea behind this tool.

Two things make them frustrating:

1. **They only contain what auditing is configured to record.** If process creation auditing is off,
   there are no Event 4688 entries — and their absence proves nothing.
2. **The Message column is not always exported.** Event Viewer's CSV export includes only the columns
   you can see in the list view, so the Message (and therefore the source IP address) is often missing.

---

## What SOC triage means

A SOC (Security Operations Centre) is a team that monitors for and responds to security activity.
**Triage** is the first pass: sorting a pile of signals into "nothing to do here", "worth a look" and
"escalate now".

Triage is not investigation. It is a fast, repeatable way of deciding where to spend limited attention.
A triage tool is useful when it:

* surfaces the things most likely to matter;
* explains *why* each item was surfaced;
* is honest about the innocent explanations; and
* tells you the next concrete step.

That is exactly what this tool tries to do — and the score it produces is an **attention-ordering
device**, not a verdict.

---

## How to export suitable Windows event data

### Method 1 — Windows Event Viewer (graphical, quick)

1. Press <kbd>Win</kbd> + <kbd>R</kbd>, type `eventvwr.msc`, press <kbd>Enter</kbd>.
2. In the left pane, expand **Windows Logs** and click **Security**.
3. Use **Filter Current Log…** on the right to narrow things down. Filtering by **Event IDs** and a
   **time range** keeps the export small and focused.
4. Select the events you want (or select all with <kbd>Ctrl</kbd> + <kbd>A</kbd>).
5. **Right-click → Save Selected Events…**
6. Choose **CSV (Comma delimited)**, give it a name and save it.
7. Drop that file onto the tool.

**Honest caveat:** this export writes the *list-view columns* only. Depending on your Windows version
and how the view is configured, that may or may not include the **Message**. The tool tells you clearly
which columns it found and which are missing, and it degrades gracefully when the Message is absent.

### Method 2 — PowerShell (recommended when you want the Message)

This produces a richer CSV that includes the full message text, which is where source IP addresses,
logon types and group names live. Run PowerShell **as Administrator** on a machine you own or are
authorised to investigate.

```powershell
# Example: the most recent 2000 Security events, exported with the message text
Get-WinEvent -FilterHashtable @{LogName='Security'} -MaxEvents 2000 |
  Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName,
                @{Name='User';Expression={$_.UserId}},
                @{Name='Message';Expression={$_.Message}} |
  Export-Csv -Path "$env:USERPROFILE\Desktop\security-events.csv" -NoTypeInformation -Encoding UTF8
```

Narrow it to the events you care about with an Event ID filter:

```powershell
Get-WinEvent -FilterHashtable @{
  LogName   = 'Security'
  Id        = 4624,4625,4720,4726,4728,4732,1102
  StartTime = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName,
                @{Name='User';Expression={$_.UserId}},
                @{Name='Message';Expression={$_.Message}} |
  Export-Csv -Path "$env:USERPROFILE\Desktop\security-events.csv" -NoTypeInformation -Encoding UTF8
```

To include PowerShell script block logging (Event 4104), add the operational log:

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 1000 -ErrorAction SilentlyContinue |
  Where-Object { $_.Id -eq 4104 } |
  Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName,
                @{Name='User';Expression={$_.UserId}},
                @{Name='Message';Expression={$_.Message}} |
  Export-Csv -Path "$env:USERPROFILE\Desktop\powershell-blocks.csv" -NoTypeInformation -Encoding UTF8
```

> **Note:** Event 4104 only exists if *Script Block Logging* was enabled **before** the activity
> happened. You cannot enable it afterwards and expect history to appear.

Both export styles work in this tool. Column names are matched flexibly, so you do not need to rename
anything.

---

## Supported CSV fields

The parser is deliberately tolerant. Headers are normalised (lowercased, with spaces, quotes and
underscores removed) and matched against a list of accepted aliases:

| Field | Accepted header names (after normalisation) | Required? |
|---|---|---|
| Event ID | `Event ID`, `EventID`, `event_id`, `EventCode`, `Event Number`, `Id` | **Yes** — the file is rejected without it |
| Date / Time | `Date and Time`, `TimeCreated`, `Date`, `Timestamp`, `Time`, `Logged` | Optional — without it the timeline is unavailable |
| User / Account | `User`, `Account Name`, `User Name`, `Account`, `TargetUserName`, `SubjectUserName` | Optional — account-based rules degrade |
| Level | `Level`, `LevelDisplayName`, `Severity`, `Type` | Optional |
| Source / Provider | `Source`, `Provider Name`, `Source Name`, `Provider` | Optional |
| Computer | `Computer`, `Computer Name`, `Hostname`, `Host`, `Machine` | Optional |
| Message | `Message`, `Description`, `Details` | Optional, but strongly recommended |

### What is read out of the Message

Because the interesting detail often lives inside the Message text, the tool parses it into named
blocks (`Subject:`, `New Logon:`, `Account For Which Logon Failed:`, `New Account:`, `Member:`,
`Group:`, `Process Information:`, `Network Information:`, …) and extracts:

`Account Name`, `Group Name`, `Source Network Address`, `Workstation Name`, `Logon Type`,
`New Process Name`, `Creator Process Name`, `Process Command Line`, `Service Name`, `Service File Name`.

This is why the tool can say *"the failed logon was for **jsmith** from **198.51.100.77**"* even though
those values only ever appear as text inside a message.

**Account precedence:** for authentication and account events the tool prefers the account from the
meaningful block in the Message (for example the *New Logon* account, or the *Account For Which Logon
Failed* account) and falls back to the `User` column. This matters, because the `User` column on a
failed-logon event often shows the *system* account rather than the account that was actually targeted.

### Missing fields never cause a crash

If a critical field is missing the tool explains the problem and stops. If an optional field is
missing it says so, continues with everything it *can* read, and tells you which features were skipped.
For example:

> *This file does not appear to contain an "Event ID" column, so it cannot be analysed.*

> *No "Message" column was found. Source IP addresses, group names and logon types usually live inside the message, so those details may be unavailable.*

---

## Supported Event IDs

Only these Event IDs are understood in Version 1. Anything else is still counted and displayed, but
shown as **"Unrecognised Event ID"** with a severity of **Unrecognised** — and it is **never flagged**.
This is deliberate: not every event is interesting, and inventing findings for unknown IDs would
create false positives and teach the wrong lesson.

| Event ID | Name | Default priority | Plain English |
|---|---|---|---|
| **4624** | Successful Logon | Informational | An account successfully logged on. Extremely common. Its value is as **context** — when it follows a burst of failures for the same account, it becomes interesting. |
| **4625** | Failed Logon | Low | A logon attempt failed. One failure is usually a typo. Many failures for one account in a short time deserve a look. |
| **4634** | Logoff | Informational | An account logged off. Useful mainly for pairing sessions with their logon events. |
| **4688** | Process Created | Informational | A new process started. Requires process creation auditing to be enabled. Used as **context**, not as a detection, in Version 1. |
| **4720** | User Account Created | Medium | A new account was created. Often routine (new starters, service accounts), but should be verifiable against a change record. |
| **4726** | User Account Deleted | Low | An account was deleted. Usually administration, occasionally part of covering tracks or account manipulation. |
| **4728** | Member Added to Global Security Group | Medium | An account joined a global (typically Active Directory) group. Priority rises sharply for privileged groups such as Domain Admins. |
| **4732** | Member Added to Local Security Group | Medium | An account joined a local group. Priority rises sharply for Administrators and similar. |
| **1102** | Security Audit Log Cleared | **High** | The Security audit log was cleared. It can happen during maintenance, but because attackers clear logs to remove evidence, it should normally be investigated. |
| **4104** | PowerShell Script Block Logging | Informational | The text of a PowerShell script or command was recorded. PowerShell itself is not suspicious — the *content* is what matters. Requires script block logging to have been enabled in advance. |
| **7045** | Service Installed | Low | A new Windows service was installed. Often legitimate software installation; also a well-known persistence technique. |

Event IDs are matched by number, so a leading zero, a differently named `Event ID` header, or a value
like `4625 (0x1211)` all resolve correctly.

---

## Detection and correlation rules

Everything is rule-based and explainable. There is no machine learning and no hidden weighting.

### Rule 1 — Repeated Failed Logons

* **Trigger:** one account has at least `Failed logon threshold` (default **5**) Event 4625 entries
  **within** the `Failed logon time window` (default **10 minutes**).
* **Severity:** Medium, raised to High when the count reaches three times the threshold.
* **Why it matters:** repeated authentication failures for one account may indicate password guessing
  or a brute-force attempt.
* **Benign explanations:** a forgotten password, a stale service credential, a mobile device or mail
  client retrying an old password, a password change an automated process has not picked up.
* **Investigate:** the source system and IP, whether the account is expected, whether the failures were
  followed by a success, and whether other accounts were targeted from the same source.

> If timestamps cannot be read, the rule falls back to counting failures across the whole dataset and
> says so in the finding.

### Rule 2 — Failed Logons Followed By Success

* **Trigger:** an account meets Rule 1 **and** an Event 4624 (successful logon) for the same account
  appears **after** the first recorded failure.
* **Severity:** High.
* **Why it matters:** failures followed by a success can indicate that a password was eventually
  guessed or sprayed successfully.
* **Benign explanations:** the legitimate user mistyped several times and then got it right; a stale
  credential was refreshed; a shared or kiosk account.
* **Investigate:** verify the source IP and device, check MFA, review what the account did after the
  logon, and check whether other accounts were targeted from the same address.

When Rule 2 fires it **replaces** Rule 1 for that account, so the same failures are never counted
twice. The finding shows the sequence — for example `4625 ×8 (within 10 min) → 4624` — and how many
seconds passed between the last failure and the success.

### Rule 3 — Account Created Then Privileges Added

* **Trigger:** the same account has an Event 4720 (created) **and** at least
  `Privilege change threshold` (default **1**) Event 4728/4732 (privileged group addition).
* **Severity:** High when a privileged group is involved, otherwise Medium.
* **Why it matters:** creating an account and quickly granting it elevated privileges is a common way
  to establish persistence or escalate privileges — and is also completely normal onboarding.
* **Benign explanations:** a new administrator or contractor was onboarded; a service account was
  created; a documented change added a user to a project group.
* **Investigate:** confirm authorisation against change records, identify the administrator who made
  the change, review what the new account did afterwards, and confirm the account is still required.

The finding displays the exact sequence, for example
`4720 — User Account Created  →  4732 — Member Added to Local Security Group (Administrators)`.

### Rule 4 — Security Audit Log Cleared

* **Trigger:** any Event 1102.
* **Severity:** High.
* **Why it matters:** clearing the log can happen during legitimate maintenance, but because attackers
  clear logs to remove evidence, it should normally be investigated. Clearing the log does not by
  itself prove malicious intent — it removes the evidence that would confirm or rule it out.
* **Investigate:** confirm whether a maintenance task or administrator was expected to clear it, check
  the recorded account, look for other activity at the same time, and compare with centralised log
  collection (SIEM) to see what happened just before.

### Rule 5 — Administrative / Privilege Activity summary

A dedicated section gathers, **without scoring them**:

* account creation (4720);
* privileged group changes (4728 / 4732);
* service installation (7045);
* audit-log clearing (1102);
* PowerShell script blocks (4104).

**Unrelated users are never automatically linked.** Each entry is listed on its own merits with its
timestamp, account, and (where present) the account that performed it. The section exists so you can
see the whole administrative picture in one place, then judge each item separately.

### Additional standalone findings

| Finding | Trigger | Severity | Points |
|---|---|---|---|
| User Account Created | 4720 not already covered by Rule 3 | Medium | +10 |
| User Account Deleted | 4726 | Low | +5 |
| Privileged Group Membership Change | 4728 / 4732 not already covered by Rule 3 | High if a privileged group, else Medium | +25 / +15 |
| New Windows Service Installed | 7045 | Low | +10 |
| Obfuscated or Encoded PowerShell Command | 4104 whose text contains several obfuscation indicators | Medium | +10 |

### Why some things are deliberately *not* flagged

* **4688 (process creation)** is shown as context only. Judging whether a process is malicious needs
  file hashes, signatures, command lines and parent-child relationships — far beyond what a CSV can
  support honestly.
* **4624 (successful logon)** on its own is never a finding. It is context.
* **Unknown Event IDs** are counted and displayed, but never flagged.

---

## Default thresholds — and why they are not universal

| Setting | Default | What it controls |
|---|---|---|
| Failed logon threshold | **5** | How many Event 4625 failures for one account before a finding is raised |
| Failed logon time window (minutes) | **10** | How close together the failures must be. Set to **0** to count across the whole dataset |
| Privilege change threshold | **1** | How many privileged group additions before a finding is raised |

Change them in the **Detection thresholds** panel and click **Re-run analysis**, or click
**Reset Defaults** to go back. Re-analysis happens instantly against the data already loaded — you do
not need to upload the file again.

> **Security thresholds vary by environment. These values are educational defaults rather than universal SOC detection rules.**
>
> A busy file server may legitimately generate hundreds of logons an hour, while the same pattern from
> a single user's laptop at 03:00 deserves a look. A domain controller will see failed logons
> constantly. A finance workstation will not. Good thresholds are tuned to a specific environment —
> which is exactly why they are configurable here.

---

## Investigation score

The score is simply **the sum of the points of the findings that fired, capped at 100**. There is no
hidden weighting and no probability maths anywhere.

| Finding | Points |
|---|---|
| Repeated failed logons | +10 |
| Repeated failed logons followed by a successful logon | +20 |
| User account created | +10 |
| User account deleted | +5 |
| Security group membership change | +15 |
| Privileged group membership change | +25 |
| Account created and then granted privileges | +25 |
| Security audit log cleared | +30 |
| New service installed | +10 |
| Obfuscated PowerShell command | +10 |

**Labels**

| Score | Label |
|---|---|
| 0 | Baseline — no notable indicators detected |
| 1 – 19 | Low investigative priority |
| 20 – 44 | Elevated activity |
| 45 – 69 | Notable activity |
| 70 – 100 | High investigative priority |

The interface lists every contributing item next to its points, so you can always reconstruct the
number by hand. The score is an **educational prioritisation mechanism**, not a mathematical
probability that a system is compromised. A score of 0 does **not** mean "safe" — it means nothing in
the data you provided matched the rules the tool knows about.

---

## Sample datasets

All four are completely fictional. Usernames, computer names and IP addresses are invented, and the
IP addresses use private ranges (`10.x.x.x`, `127.0.0.1`) or reserved documentation ranges
(`198.51.100.x`, `203.0.113.x`) that are never routable on the internet.

| File | Scenario | Expected result |
|---|---|---|
| `samples/normal-windows-events.csv` | 18 events of ordinary activity: console logons, service logons, process creation, one mistyped password | **No findings, score 0.** One failed logon is counted but stays below the threshold — exactly the point |
| `samples/password-guessing.csv` | 8 failed logons for `jsmith` from `198.51.100.77` within ~45 seconds, then a successful logon | **Possible Password Guessing Followed By Success**, High, score 20 |
| `samples/account-persistence.csv` | `svc_backup2` created (4720) then added to local **Administrators** (4732) | **New Account Granted Privileges**, High, score 25 |
| `samples/suspicious-admin-activity.csv` | Mixed lab: failures + success, account creation + two privileged group additions, service installation, obfuscated PowerShell, audit log cleared | **5 findings**, including log-cleared at High; score 95 |

Load them with the one-click buttons in the **Demo data** panel. The status panel clearly labels the
result as **Demo Data — fictional**, so there is no confusion when demonstrating the tool.

### Suggested demonstration sequence (for a video or interview)

1. **Load Normal Sample.** Point out: 18 events, 9 successful logons, process creation, and *one*
   failed logon — which is deliberately **not** flagged. "A single failed logon is noise."
2. **Load Password Guessing Sample.** Point out that the tool raised the **Possible Password Guessing
   Followed By Success** alert because it saw the failures and the success *together*. Show the
   sequence `4625 ×8 (within 10 min) → 4624` and the 14-second gap.
3. **Load Privilege Escalation Sample.** Point out `4720 → 4732` and the **New Account Granted
   Privileges** alert. Note the word "Administrators" and why it raises the priority.
4. **Load Mixed SOC Sample.** Point out that this single dataset produces **five** correlated findings
   and a score of 95 — then use the filters to isolate Event 1102 and show the **Security Audit Log
   Cleared** finding at High priority.
5. **Change a threshold.** Raise the failed-logon threshold to 50 and click **Re-run analysis**. The
   findings disappear and the score falls. This is the moment to make the point:

   > **"Detection tells an analyst where to look. Investigation determines what actually happened."**
   >
   > **"An anomaly is a starting point for investigation, not proof of compromise."**

---

## False positives — and why they are expected

Every rule in this tool can be triggered by completely legitimate activity. That is by design, not a
defect:

| Finding | Very common innocent cause |
|---|---|
| Repeated Failed Logons | A user forgot a password after annual leave; a scheduled task has a stale credential |
| Password Guessing Followed By Success | A user genuinely mistyped their password four times, then got it right |
| New Account Granted Privileges | New starter onboarding, or a help-desk engineer following a ticket |
| Privileged Group Membership Change | A promotion, a project, or temporary elevation for software installation |
| New Windows Service Installed | Any software installation, Windows Update, or endpoint agent deployment |
| Security Audit Log Cleared | A log-rotation script, a maintenance window, or a lab machine being reset |
| Obfuscated PowerShell Command | A legitimate deployment tool or vendor installer that encodes its scripts |

A detection tells you **where to look**. It never tells you **what happened**. The most important
skill this tool can help you build is the habit of asking *"what would this look like if it were
completely normal?"* before deciding.

---

## Limitations — stated honestly

* **CSV exports differ between Windows versions and configurations.** Column names, date formats and
  whether the Message is included all vary. The tool is tolerant, but it can only work with what the
  export contains.
* **A CSV is not a full record.** It contains the summary line per event. Deep analysis (full event
  XML, process trees, file hashes) requires going back to the original logs or an EDR.
* **Not every event contains a source IP address.** Console logons may show `127.0.0.1`, `::1` or
  nothing. IP-based reasoning then simply is not available.
* **Event logging configuration determines what telemetry exists at all.** No 4688 auditing means no
  process events; no script block logging means no 4104 events.
* **Absence of an event does not prove the activity did not occur.** A quiet dataset can mean a quiet
  system *or* auditing that was never switched on — or that was switched off.
* **Date order can be ambiguous.** `03/04/2026` is 3 April in the UK and 4 March in the US. The tool
  detects the order across the whole file (a day above 12 settles it) and defaults to day-first when
  genuinely ambiguous. If your export is month-first and contains no disambiguating date, timeline
  ordering may be affected. Counts and per-account correlation are unaffected.
* **NAT, shared accounts and proxies blur attribution.** Several devices can look like one source
  address, and a service account can be used by many people.
* **Static browser analysis provides limited correlation.** The tool only sees the file you gave it.
  It cannot cross-reference other hosts, MFA logs, network data or a change-management system.
* **Windows Event IDs alone cannot determine intent.** This is the core limitation and the core lesson.
* **The tool does not replace an EDR, SIEM or a professional SOC platform.** It is a teaching aid.
* **The tool performs no malware analysis** and never inspects files or binaries.

---

## Privacy architecture

This is the design, not just a promise:

| Concern | How it is handled |
|---|---|
| Data upload | **Impossible.** There is no server, no endpoint and no upload code. Files are read with the browser's `FileReader` and live only in the tab's memory |
| Network requests | **None.** No `fetch`, no `XMLHttpRequest`, no `WebSocket`, no `sendBeacon`, no external scripts, styles, fonts or images |
| AI providers | **Not used.** All logic is local, deterministic, rule-based JavaScript |
| Analytics / telemetry | **None.** No analytics library, no pixel, no error reporting |
| Cookies | **None.** Nothing is written to `document.cookie` |
| Local storage | **None.** Nothing is written to `localStorage` or `sessionStorage` |
| Persistence | Nothing survives a page refresh or a tab close |
| Third parties | No third-party content of any kind is loaded |

You can verify this in seconds: open `script.js` and search for `fetch`, `XMLHttpRequest`, `WebSocket`,
`sendBeacon`, `localStorage` or `cookie`. The only `http` occurrences are inside the fictional sample
data.

For extra confidence, open your browser's developer tools **Network** tab before loading a file. You
will see no new requests.

---

## Security design

Uploaded CSV content is treated as **untrusted input**, because it is. Anyone can craft a log file.

* **No untrusted value is ever inserted as HTML.** All text from the file is written with
  `textContent` or `document.createTextNode`. There is no `innerHTML` with file data anywhere.
* **No `eval`, no `new Function`, no dynamic script creation.** File content is never executed.
* **Malformed CSV fails safely.** Unclosed quotes, ragged rows, binary junk, wrong file types, empty
  files and files with no Event ID column all produce a clear message instead of an error or a hang.
* **File type and size are validated.** Non-CSV files are rejected with an explanation, and files over
  25 MB are refused with advice to narrow the export (a very large file would otherwise tie up the tab).
* **No data leaves the browser**, so there is no server-side attack surface at all.

### A note on formula injection

If you open a CSV export in Excel, a cell beginning with `=`, `+`, `-` or `@` can be interpreted as a
formula. This tool displays all values as inert text and never passes them to a spreadsheet, but it is
worth knowing about when handling untrusted CSVs elsewhere.

---

## Accessibility

* Semantic HTML: `header`, `main`, `section`, `article`, `footer`, real `<table>` elements with
  `<caption>` and `<th scope="col">`, and a real `<label>` for every input.
* The drop zone is keyboard-accessible: focus it and press <kbd>Enter</kbd> or <kbd>Space</kbd>.
* Visible focus outlines on every interactive element (`:focus-visible`).
* A "Skip to main content" link at the top of the page.
* Live regions (`aria-live="polite"`, `role="status"`) announce load results and filter counts to
  screen readers.
* Severity is never conveyed by colour alone — the words **Informational / Low / Medium / High** always
  appear next to the colour, and score labels are written out in full.
* Good contrast against the dark background, and text that reflows rather than shrinking on mobile.
* `prefers-reduced-motion` is respected.

---

## Project structure

```
.
├── index.html                          The whole interface (semantic HTML)
├── styles.css                          Dark SOC theme, severity colours, CSS bar charts
├── script.js                           CSV parser, Event ID catalogue, rules, scoring, rendering
├── README.md                           This file
└── samples/
    ├── normal-windows-events.csv       Demo 1 — ordinary activity
    ├── password-guessing.csv           Demo 2 — failures followed by success
    ├── account-persistence.csv         Demo 3 — account created then privileged
    └── suspicious-admin-activity.csv   Demo 4 — mixed SOC lab
```

Inside `script.js` the code is organised into clearly labelled sections:

1. Embedded demo datasets
2. Windows Event ID catalogue
3. Defaults and DOM helpers
4. CSV parser
5. Column detection
6. Message parsing
7. Timestamp parsing
8. Event normalisation
9. Detection and correlation rules
10. Analysis, statistics and scoring
11. Rendering
12. UI wiring

**No dependencies.** No `package.json`, no `node_modules`, no bundler, no build step, no framework.

> The demo datasets appear twice: as real files in `samples/`, and as an embedded copy near the top of
> `script.js`. The embedded copy is what makes the one-click demo buttons work when `index.html` is
> opened directly from disk (`file://`), where browsers block a page from reading neighbouring files.
> If you edit a sample CSV, update the embedded copy too — or simply drag the file onto the page.

---

## Educational use

This project is intended for learning and for demonstrating SOC triage reasoning.

* Use it in a classroom or study group to practise reading Windows events.
* Use it to show how the same event is benign in one context and worth investigating in another.
* Use it to practise writing an investigation note: what you saw, why it mattered, what you checked,
  and what you concluded.
* Use the sample datasets to demonstrate the difference between an anomaly and a compromise.

**Do not** use it as a detection control, as an alerting system, or as evidence that a system is or is
not compromised. Only ever analyse logs from systems and networks you own or are explicitly authorised
to investigate.

---

## Future improvements (not in Version 1)

These are deliberately excluded so the current version stays simple, honest and dependency-free:

* direct `.evtx` parsing in the browser;
* Sysmon event support (process creation, network connections, image loads);
* deeper PowerShell 4104 analysis (decoding Base64, listing invoked URLs and domains);
* process-tree visualisation from 4688 parent/child relationships;
* MITRE ATT&CK technique mapping for each finding;
* richer timeline analysis with time-window bucketing and baselining;
* per-user login-time baselining to spot "unusual hour" logons;
* dedicated service-creation and scheduled-task monitoring;
* Windows Defender operational log analysis;
* an exportable incident report (print-friendly summary);
* SIEM-style rule syntax so students can write their own detections;
* multi-file correlation across several hosts.

No external APIs will be added to any future version without a clear, explicit decision to change the
privacy model — and that decision would be documented in this file.

---

## Verification performed

Two automated test suites were run against the **real `script.js` code** (not a copy):

### 1. Logic suite — 100 checks

* **CSV parsing:** quoted commas, embedded newlines, doubled quotes, BOM, CRLF, ragged rows, unclosed
  quotes, empty input and null input;
* **Column detection** across several header naming styles (`Event ID`, `event_id`, `EventID`,
  `TimeCreated`, `Provider Name`, `host_name`, …);
* **Timestamp parsing** for day-first, month-first, ISO-with-timezone, 12-hour and invalid values;
* **Message parsing:** account, source IP, logon type, group name, actor and process fields;
* **Helper logic:** privileged-group detection, account-key normalisation, PowerShell obfuscation
  heuristics;
* **Each sample dataset** producing exactly the expected findings, severities and score;
* **Threshold changes** altering the results correctly, including the fallback from a correlated
  finding to a standalone one;
* **Malformed and incomplete input** failing safely with a helpful message, and analysis continuing
  when only optional columns are missing;
* **Hostile content** (`<script>`, `onerror=`, formula-style values, 60,000-character fields) being
  handled as inert text and never executed.

### 2. Rendering suite — 63 checks

Every demo dataset is run through the complete pipeline into a small in-memory DOM, verifying that
the summary cards, score dial, itemised breakdown, findings, admin-activity section, bar charts,
timeline and event table all render without throwing, and that no `undefined`, `NaN` or
`[object Object]` ever leaks into the output. It also checks that a malformed file hides the results
panel and shows an error instead.

### 3. Structure checks

The HTML tag tree balances, every element ID referenced by the script exists in the markup, and the
CSS braces balance.

### Bugs found and fixed during testing

* **Top-level `Logon Type` was being missed.** In a real Windows 4625 message, `Logon Type:` appears on
  its own line rather than inside a named block, so the section parser attached it to the preceding
  block and the extraction step never found it. Fixed by adding a `pickAnyField` helper that searches
  the top-level map first and then every block, and by using it for the logon-type, process and service
  fields. This is a genuine robustness fix, not just a test fix.

### Known quirks (documented rather than hidden)

* **Account precedence.** The tool prefers the account found in the meaningful message block over the
  `User` column, because on a failed-logon event the `User` column often shows the system account
  rather than the targeted account. This is intentional, and it is why the finding for a failed logon
  correctly names `jsmith` rather than `SYSTEM`.
* **Time-window fallback.** If timestamps cannot be read for a group of failures, the rule counts them
  across the whole dataset and says so, rather than silently producing no finding.
* **Ambiguous dates.** Where a file contains no date that disambiguates day-first from month-first, the
  tool assumes day-first; this is stated in the limitations above.
* **Demo data is duplicated** between `samples/` and the embedded copy in `script.js` (explained above).
* **Correlation is single-file.** Two accounts in different files cannot be linked, because the tool
  never sees more than one file at a time.
