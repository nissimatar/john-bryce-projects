# john-bryce-projects
Automation scripts created during a 10-month, 680 hours cyber security course, each covering a different module.  
Each script is self-contained and intended for **lab** use.

## Quick start
```bash
# Make executable
chmod +x JMagen773630.s17.nx*.sh

# Run a project (examples)
./JMagen773630.s17.nx201.sh    # Network Research
./JMagen773630.s17.nx212.sh    # Windows Forensics
./JMagen773630.s17.nx301.sh    # Penetration Testing
./JMagen773630.s17.nx305.sh    # Network Security
```

Projects
1) Project 1 – Network Research — JMagen773630.s17.nx201.sh

Installs needed tools if not installed

Shows local IP, checks anonymity, suggests a tool if needed

Establishes SSH connection: uses provided creds or (optionally) attempts brute-force with user consent

2) Project 2 – Windows Forensics — JMagen773630.s17.nx212.sh

Installs needed tools if not installed

Asks for an input file (disk image or memory dump)

Disk (HDD): carves/extracts data; looks for network traces; searches human-readable strings

Memory: Volatility analysis (processes, network connections); attempts registry extraction

Displays a findings report; saves results; supports searching within findings

3) Project 3 – Penetration Testing — JMagen773630.s17.nx301.sh

Installs needed tools if not installed

Multiple scan levels and password-list options

Attempts to brute-force common login services in a given network (with consent)

Vulnerability mapping via Nmap NSE + Searchsploit

4) Project 4 – Network Security — JMagen773630.s17.nx305.sh

Installs needed tools if not installed

Choose between scanning, enumeration, exploitation, and password-list options

Scans a given network range with multiple tools; supports AD creds if provided

Saves results and supports searching in the results

Requirements

Linux (Kali recommended) with sudo

Internet access for tool installation (first run)

Lab/test environment and permission for any scans or brute-force

Skills & tools demonstrated

Bash • Linux (Kali) • SSH • Nmap/NSE • Hydra • Searchsploit • Volatility • Disk & memory triage • Enumeration • Exploitation • Reporting

Notes

No real credentials or private data are included.

Large artifacts (pcaps, images, zips) are not committed.

Ethical use only: learning and lab environments where you have explicit permission.
