# Lab : MITRE ATT&CK Investigation with Wazuh

Hands-on lab where I generate small, harmless attacker-style behaviours on a Linux host and a Windows host, find them in Wazuh, and map each one to a MITRE ATT&CK technique.

The goal is to finish every investigation with one sentence: *I observed this behaviour, and it maps to this ATT&CK technique.*

## Environment

| Component | Detail |
| --- | --- |
| SIEM | Wazuh 4.9.0, single-node Docker stack (manager, indexer, dashboard) |
| Linux host | Ubuntu VM `jayy` (192.168.56.20) with a Wazuh agent |
| Windows host | `DESKTOP-3OKNFSD` with a Wazuh agent |
| Dashboard | Discover view, index `wazuh-alerts-*`, DQL queries |

Note: Discover shows browser time (UTC-8); the VM clock is UTC.

## Investigation template

Process -> User -> Parent process -> Command -> Network connection -> Evidence -> ATT&CK mapping

Each finding is labelled **Observed** (the log shows it directly) or **Inferred** (I am reading intent into it).

## Commands used

### 0. Setup and housekeeping

```bash
# Find the VM's address
hostname -I

# Check the Wazuh containers
sudo docker ps -a

# Wazuh rule/decoder testing inside the manager container
sudo docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest

# Evidence folder
mkdir -p ~/lab-evidence/lab2
```

### 1. Find ATT&CK tags in Wazuh alerts (Discover, DQL)

```
rule.mitre.id:*
agent.name:DESKTOP*
agent.name:DESKTOP* and data.win.system.eventID:4688
agent.name:DESKTOP* and data.win.system.providerName:"Microsoft-Windows-Sysmon"
agent.name:DESKTOP* and data.win.system.channel:*PowerShell*
full_log:*crontab*
```

Result: 3,788 ATT&CK-tagged hits before any simulation (T1078 on logons).

### 2. Execution and Discovery through sudo

Techniques: T1033, T1082, T1016, T1049, T1057, T1087.001, T1548.003.

Harmless read-only commands run through sudo. Wazuh logs them from `auth.log` with `data.command`, `data.srcuser`, `data.dstuser`, `data.pwd` and `data.tty`.

```bash
sudo whoami                 # T1033
sudo uname -a               # T1082
sudo ip a                   # T1016
sudo ss -tulpn              # T1049
sudo ps aux                 # T1057
sudo cat /etc/passwd        # T1087.001
```

### 3. Persistence

**Local account (T1136.001)**

```bash
sudo useradd labtest
sudo userdel labtest
```

**Cron job (T1053.003)**

```bash
# Add a harmless job
(crontab -l 2>/dev/null; echo '*/5 * * * * /bin/true # lab2-test') | crontab -

# Confirm it
crontab -l

# Look at the syslog timeline (REPLACE -> RELOAD -> CMD)
sudo grep -a -E 'crontab|lab2-test' /var/log/syslog | tail -10

# Save the excerpt as evidence
sudo grep -a -E 'crontab|lab2-test' /var/log/syslog | tail -10 > ~/lab-evidence/lab2/step4-cron-syslog.txt

# Clean up
crontab -l | grep -v lab2-test | crontab -
```

**Detection gap fix.** The agent was not reading `/var/log/syslog`, so cron changes never reached Wazuh. Back up first:

```bash
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
```

Then add this block to `/var/ossec/etc/ossec.conf` on the agent:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/syslog</location>
</localfile>
```

```bash
sudo systemctl restart wazuh-agent
```

After the restart, "Crontab entry changed." (rule 2832) appeared.

### 4. Credential Access (T1110.001)

No new commands. The earlier lockout test on 31 October was still in the index.

Result: about six failed password attempts between 02:52:26 and 02:53:02 (rule 5503, `firedtimes` 6).

### 5. Windows PowerShell scenario

Techniques: T1059.001, T1027, T1564.003, T1033.

Run in an elevated PowerShell on the Windows host to log process creation with command lines:

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
```

Test command, run from a command prompt. The base64 decodes to `Write-Output 'lab2-ps-test'; whoami`:

```cmd
powershell.exe -NoP -W Hidden -Enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGwAYQBiADIALQBwAHMALQB0AGUAcwB0ACcAOwAgAHcAaABvAGEAbQBpAA==
```

Find it in Wazuh (Event 4688, rule 67027):

```
agent.name:DESKTOP* and data.win.system.eventID:4688
```

**Revert Windows auditing when finished:**

```powershell
auditpol /set /subcategory:"Process Creation" /success:disable

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  -Name ProcessCreationIncludeCmdLine_Enabled -Value 0 -Type DWord
```

## Consolidated ATT&CK mapping

| Behaviour | Tactic | Technique | Evidence | Confidence |
| --- | --- | --- | --- | --- |
| Routine Windows and Linux logons | Initial Access, Persistence, Privilege Escalation, Defense Evasion | T1078 Valid Accounts | Event 4624, PAM rules | Observed |
| Event 4672 special privileges | Defense Evasion | T1484 (Wazuh tag) | Wazuh tag | Weak fit |
| Discovery commands via sudo | Discovery | T1033, T1082, T1016, T1049, T1057, T1087.001 | auth.log sudo entries | Observed |
| Commands run as root | Privilege Escalation | T1548.003 Sudo and Sudo Caching | auth.log | Observed |
| Shell command execution | Execution | T1059.004 Unix Shell | auth.log | Inferred |
| `labtest` account created and deleted | Persistence | T1136.001 Local Account | Account-creation alert | Observed |
| Cron job added | Execution, Persistence, Privilege Escalation | T1053.003 Cron | syslog 13:24:15 / 13:25:01 / 13:25:02; rule 2832 | Observed |
| About six failed logons, 31 Oct | Credential Access | T1110.001 Password Guessing | Rule 5503, firedtimes 6 | Observed |
| Encoded PowerShell | Execution | T1059.001 PowerShell | Event 4688, rule 67027 | Observed |
| `-Enc` base64 argument | Defense Evasion | T1027 | Event 4688 command line | Observed |
| `-W Hidden` | Defense Evasion | T1564.003 Hidden Window | Event 4688 command line | Observed |
| `whoami.exe` child | Discovery | T1033 | Event 4688 | Observed |

## Detection gaps found

| Gap | Status |
| --- | --- |
| Agent not collecting `/var/log/syslog` | Fixed with a `<localfile>` entry |
| Rule 2832 (Crontab entry changed) has no ATT&CK tag | Recorded; map by hand |
| Rule 67027 (A process was created) has no ATT&CK tag, level 3 | Recorded |
| Cron CMD line has no decoder or rule | Likely, not fully verified |
| No Sysmon or PowerShell-channel events | Process auditing with command line enabled instead |
| Event 4672 tagged T1484 | Weak fit |

## Lessons learned

- A Wazuh ATT&CK tag is a lead, not a verdict.
- When an alert is missing, find where the chain breaks (log, agent file list, ruleset) before blaming the rules.
- Searching a log for a word also matches your own commands that contain it.
- Context (who, from where, when) decides whether a technique is suspicious.

## Screenshots

### Environment
![Wazuh stack running in Docker](images/Screenshot%20%28100%29.png)

### 1. ATT&CK tags in Wazuh
![3,788 ATT&CK-tagged hits](images/Screenshot%20%28105%29.png)
![Logons with descriptions and tactics](images/Screenshot%20%28106%29.png)

### 2. Discovery through sudo
![sudo discovery commands](images/Screenshot%20%28107%29.png)

### 3. Persistence
![labtest account alert](images/Screenshot%20%28108%29.png)
![Cron timeline in syslog](images/Screenshot%20%28114%29.png)
![logtest, cron line with no decoder](images/Screenshot%20%28117%29.png)
![logtest, rule 2832 match](images/Screenshot%20%28118%29.png)
![Agent file list, syslog missing](images/Screenshot%20%28120%29.png)
![Crontab entry changed alert](images/Screenshot%20%28121%29.png)

### 4. Credential Access (T1110.001)
![35 authentication failure hits](images/Screenshot%20%28123%29.png)
![31 October failed-logon burst](images/Screenshot%20%28125%29.png)
![Rule 5503 mapped to T1110.001](images/Screenshot%20%28126%29.png)

### 5. Windows PowerShell (T1059.001)
![4,465 Windows agent alerts](images/Screenshot%20%28128%29.png)
![Enabling process-creation auditing](images/Screenshot%20%28130%29.png)
![Process-created events](images/Screenshot%20%28131%29.png)
![Expanded Event 4688](images/Screenshot%20%28133%29.png)
![whoami child process](images/Screenshot%20%28137%29.png)

## Disclaimer

Everything here ran in my own isolated lab. Do not run these techniques on systems you do not own or have permission to test.
