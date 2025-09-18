#! /bin/bash

### Network Security Project ###
### Nissim Atar ###
### s17 ###
### JMagen773630 ###

#3.2 creating log file
log_file="/var/log/project4.log"


#function for log message
log_message()
{
        echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$log_file"
}

# Show a "press any key" pause that can't leak into the next read
_press_key() {
  local msg="${1:-Press any key to continue…}"
  _flush_tty                               # make sure buffer is empty first
  read -r -n1 -s -p "$msg" < /dev/tty     # wait for exactly one key
  _flush_tty                               # drain leftover bytes (e.g., arrow keys)
  echo
}
# Drain any pending bytes from the terminal (non-blocking)
_flush_tty() {
  # eat everything available right now (handles multi-byte escape sequences)
  while IFS= read -r -n1 -s -t 0.01 _junk < /dev/tty; do :; done
}

# Read one full line from the real TTY; never returns empty
_read_menu_choice() {
  local line
  while true; do
    _flush_tty                         # ensure buffer is clean
    IFS= read -r line < /dev/tty || continue
    # strip CR/LF just in case
    line="${line//$'\r'/}"; line="${line//$'\n'/}"
    [[ -n "$line" ]] && { printf '%s' "$line"; return 0; }
    # if empty, loop and read again (no redraw/clear)
  done
}

# Convert DNS domain → LDAP base DN (e.g., mydomain.local → dc=mydomain,dc=local)
_domain_to_basedn() {
  local d="$1"
  [[ -z "$d" ]] && return 1
  printf 'dc=%s\n' "${d//./,dc=}"
}

# Try DNS SRV lookups to get a DC IP (works if Kali’s DNS points at the DC)
resolve_dc_ip_dns() {
  local d="$1" srv host ip
  [[ -z "$d" ]] && return 1

  if command -v dig >/dev/null 2>&1; then
    srv="$(dig +short _ldap._tcp.dc._msdcs."$d" SRV 2>/dev/null | awk '{print $4}' | sed 's/\.$//' | head -n1)"
    [[ -n "$srv" ]] && ip="$(dig +short "$srv" A 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)"
  elif command -v host >/dev/null 2>&1; then
    host="$(host -t SRV _ldap._tcp.dc._msdcs."$d" 2>/dev/null | awk '{print $NF}' | sed 's/\.$//' | head -n1)"
    [[ -n "$host" ]] && ip="$(host "$host" 2>/dev/null | awk '/has address/{print $4; exit}')"
  else
    host="$(nslookup -type=SRV _ldap._tcp.dc._msdcs."$d" 2>/dev/null | awk '/service =/ {print $NF}' | sed 's/\.$//' | head -n1)"
    [[ -n "$host" ]] && ip="$(nslookup "$host" 2>/dev/null | awk '/Address: / {print $2; exit}')"
  fi

  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && echo "$ip"
}

# If DNS fails, scan the provided range for LDAP RootDSE, pick the one matching your Domain
find_dc_ip_in_range() {
  local domain="$1" range="$2" ip basedn got
  basedn="$(_domain_to_basedn "$domain")" || return 1

  while read -r ip; do
    got="$(
      ldapsearch -LLL -x -H "ldap://$ip" -s base defaultNamingContext 2>/dev/null \
        | sed -n 's/^defaultNamingContext:[[:space:]]*//Ip' | head -n1
    )"
    # make both lowercase before comparing
    if [[ -n "$got" ]]; then
      local got_lc="${got,,}" base_lc="${basedn,,}"
      if [[ "$got_lc" == "$base_lc" ]]; then
        echo "$ip"; return 0
      fi
    fi
  done < <(nmap -Pn --open -p389 "$range" -oG - 2>/dev/null | awk '/open/{print $2}')

  return 1
}


# Final resolver: try DNS first, then active scan of the range
resolve_or_find_dc_ip() {
  local domain="$1" range="$2" ip=""
  ip="$(resolve_dc_ip_dns "$domain")"
  [[ -z "$ip" ]] && ip="$(find_dc_ip_in_range "$domain" "$range")"
  [[ -n "$ip" ]] && echo "$ip"
}

install_apps() {
    local YELLOW="\e[93m" RED="\e[91m" GREY="\e[90m" NC="\e[0m"
    local -a required_pkgs optional_pkgs pkgs
    local total step idx p

    log_message "checking apps installation"

    echo -e "${YELLOW}... Updating package lists ...${NC}"
    sudo apt-get update

    # ---------------------------
    # Package lists (APT names)
    # ---------------------------
    # REQUIRED packages (hard requirements for your modes & core features)
    required_pkgs=(
        nmap                 # scans + NSE
        hydra                # toolkit baseline
        crackmapexec         # SMB/WinRM/LDAP enumeration & spraying
        enum4linux           # SMB/AD enum
        samba-common-bin     # provides rpcclient
        ldap-utils           # provides ldapsearch
        sipcalc              # subnet math
        dnsutils             # dig / nslookup (client DNS tools)
        bind9-host           # host (alt DNS client)
        impacket             # Impacket CLIs on Kali (sometimes provides wrappers)
    )

    # OPTIONAL packages (nice-to-have; missing won't warn)
    optional_pkgs=(
        python3-impacket     # alt provider of Impacket CLIs (Debian/Ubuntu)
        enscript             # TXT->PDF path #1
        ghostscript          # ps2pdf (TXT->PDF path #1)
        pandoc               # TXT->PDF path #2
        libreoffice          # TXT->PDF path #3
        hashcat              # Kerberoast cracking helper
    )

    # Union for progress count
    pkgs=("${required_pkgs[@]}" "${optional_pkgs[@]}")
    total=${#pkgs[@]}

    # ---------------------------
    # Install loop
    # ---------------------------
    for idx in "${!pkgs[@]}"; do
        p="${pkgs[$idx]}"
        if dpkg -s "$p" &>/dev/null; then
            echo -e "${YELLOW}... $p is already installed ...${NC}"
        else
            echo -e "${YELLOW}... $p is not installed, installing... ...${NC}"
            log_message "installing $p"
            sudo apt-get install -y "$p" || true
            if dpkg -s "$p" &>/dev/null; then
                log_message "$p is installed."
            else
                echo -e "${GREY}... Could not confirm install of '$p' (continuing) ...${NC}"
                log_message "could not confirm install of $p"
            fi
        fi
        step=$((idx + 1))
        echo -e "${YELLOW}... Progress: $step/$total packages processed ...${NC}"
    done

    # ---------------------------
    # Post-install command checks
    # ---------------------------
    local -a missing_required_cmds=()
    local -a missing_optional_cmds=()

    need_cmd_required() {
        local cmd="$1"
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_required_cmds+=("$cmd")
        fi
    }
    need_cmd_optional() {
        local cmd="$1"
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_optional_cmds+=("$cmd")
        fi
    }

    # REQUIRED commands (map to required features in ModesExecute)
    need_cmd_required nmap
    need_cmd_required hydra
    need_cmd_required crackmapexec
    need_cmd_required enum4linux
    need_cmd_required rpcclient
    need_cmd_required ldapsearch
    need_cmd_required sipcalc
    # At least one DNS client
    if ! command -v dig >/dev/null 2>&1 && \
       ! command -v host >/dev/null 2>&1 && \
       ! command -v nslookup >/dev/null 2>&1; then
        missing_required_cmds+=("dig/host/nslookup")
    fi
    # Impacket CLIs (used by Enumeration/Exploitation Advanced)
    need_cmd_required impacket-GetADUsers
    need_cmd_required impacket-GetUserSPNs

    # If Impacket CLIs missing, try alternate package and create shim symlinks if needed
    if ! command -v impacket-GetADUsers >/dev/null 2>&1 || \
       ! command -v impacket-GetUserSPNs >/dev/null 2>&1; then
        if ! dpkg -s python3-impacket &>/dev/null; then
            echo -e "${YELLOW}... trying alternate package 'python3-impacket' for Impacket CLIs ...${NC}"
            sudo apt-get install -y python3-impacket || true
        fi
        # Create compatibility symlinks if distro uses Get*.py names
        if ! command -v impacket-GetADUsers >/dev/null 2>&1 && command -v GetADUsers.py >/dev/null 2>&1; then
            echo -e "${YELLOW}... creating shim for impacket-GetADUsers -> $(command -v GetADUsers.py) ...${NC}"
            sudo ln -sf "$(command -v GetADUsers.py)" /usr/local/bin/impacket-GetADUsers || true
        fi
        if ! command -v impacket-GetUserSPNs >/dev/null 2>&1 && command -v GetUserSPNs.py >/dev/null 2>&1; then
            echo -e "${YELLOW}... creating shim for impacket-GetUserSPNs -> $(command -v GetUserSPNs.py) ...${NC}"
            sudo ln -sf "$(command -v GetUserSPNs.py)" /usr/local/bin/impacket-GetUserSPNs || true
        fi
        # Re-check after fallback
        if ! command -v impacket-GetADUsers >/dev/null 2>&1; then
            missing_required_cmds+=("impacket-GetADUsers")
        fi
        if ! command -v impacket-GetUserSPNs >/dev/null 2>&1; then
            missing_required_cmds+=("impacket-GetUserSPNs")
        fi
    fi

    # OPTIONAL commands (PDF conversions & cracking helpers)
    # TXT->PDF path #1
    need_cmd_optional enscript
    need_cmd_optional ps2pdf   # provided by ghostscript
    # TXT->PDF path #2
    need_cmd_optional pandoc
    # TXT->PDF path #3
    need_cmd_optional libreoffice
    # Cracking helper
    need_cmd_optional hashcat

    # If ps2pdf still missing but ghostscript package exists under a different name somehow
    if ! command -v ps2pdf >/dev/null 2>&1; then
        echo -e "${GREY}... ps2pdf not found; attempting to (re)install ghostscript ...${NC}"
        sudo apt-get install -y ghostscript || true
        command -v ps2pdf >/dev/null 2>&1 || missing_optional_cmds+=("ps2pdf")
    fi

    # ---------------------------
    # Report status
    # ---------------------------
    if ((${#missing_required_cmds[@]})); then
        echo -e "${RED}... Missing required tools/commands: ${missing_required_cmds[*]} ...${NC}"
        log_message "missing required after install: ${missing_required_cmds[*]}"
    else
        echo -e "${YELLOW}... All required tools are installed and ready ...${NC}"
        log_message "all required tools present"
    fi

    if ((${#missing_optional_cmds[@]})); then
        echo -e "${GREY}... Optional tools not found (features will gracefully degrade): ${missing_optional_cmds[*]} ...${NC}"
        log_message "optional tools missing: ${missing_optional_cmds[*]}"
    fi
}



# Check if the network connection is anonymous; if not, alert the user and exit
# option to install anonsurf
function isAnon () {
    IP=$(curl -s ifconfig.co)

    # GeoIP for IP address
    CNTRY=$(geoiplookup $IP | awk '{print $4}' | sed 's/,//g')
    echo "$CNTRY"
    echo "$IP"
    # Check if IP is IL
    if [ "$CNTRY" == "IL, Israel" ] || [ "$CNTRY" == "IL" ]; then
        echo -e "\e[95m... you are not anonymous ...\e[0m"
        log_message "anonymous check false"
        echo -e "\e[95m... do you wish to download, install and run anonsurf? yes/no ...\e[0m"        
        echo
        read ans
        echo
        if [ "$ans" == "yes" ]; then
		if ! dpkg -l | grep -q anonsurf; then
	                echo -e "\e[95m... updating and upgrading system. might take a moment... ...\e[0m"
        	        sleep 1.5
			sudo apt update && sudo apt upgrade
          	   	sudo echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" | sudo tee -a /etc/apt/sources.list
			sudo git clone https://github.com/Und3rf10w/kali-anonsurf
			sudo ./kali-anonsurf/installer.sh
			echo -e "\e[95m... DONE ...\e[0m"
			log_message "anonsurf downloaded"
		fi
                echo -e "\e[95m... anonsurf installed ...\e[0m"
                log_message "anonsurf installed"
                sudo anonsurf start
                echo -e "\e[95m... anonsurf started running ...\e[0m"
        fi
    else
        echo -e "\e[95m... you are anonymous ...\e[0m"
        log_message "anonymous check true"
    # display the spoofed country name
	    echo "Spoofed Country: $(curl -s https://api.myip.com | grep -oP '(?<="country":")[^"]*')"
    fi
}

# 1.1  Function - Get address and validate
#  Enter output directory name option 
EnterAdr() {
    local input ip prefix valid
    local octets

    # POSIX ERE:  a.b.c.d/NN  (NN limited to 0..32)
    local re_cidr='^[0-9]{1,3}(\.[0-9]{1,3}){3}/([0-9]|[12][0-9]|3[0-2])$'

    while true; do
        echo -e "\e[95mPlease type a network range in CIDR notation (e.g. 192.168.0.0/24) (type \"back\" to go back)\e[0m"
        read -r input < /dev/tty

        # allow user to return without changes
        case "$input" in
            back|Back|BACK)
                echo -e "\e[93mReturning to menu. Network Range remains: $NTADR\e[0m"
                return
                ;;
        esac

        # remove any whitespace the user might have pasted
        input="${input//[[:space:]]/}"

        if [[ $input =~ $re_cidr ]]; then
            # split without relying on capture groups
            ip="${input%/*}"
            prefix="${input##*/}"
            valid=1

            IFS='.' read -r -a octets <<< "$ip"
            for oct in "${octets[@]}"; do
                if (( oct < 0 || oct > 255 )); then
                    valid=0
                    break
                fi
            done

            # prefix already pattern-limited to 0..32, extra guard:
            if (( prefix < 0 || prefix > 32 )); then
                valid=0
            fi

            if (( valid )); then
                NTADR="$input"
                log_message "Network range entered: $NTADR"
                break
            fi
        fi

        echo -e "\e[91mInvalid network range — please try again. For example: 192.168.0.0/24\e[0m"
    done

    # --- Default OUTPUT prompt remains unchanged ---
    local default_dir="${NTADR//\//_}_output"
    echo -e "\e[95mDefault output directory name is \"$default_dir\". Would you like to change it? (Y/N)\e[0m"

    while true; do
        read -r choice < /dev/tty
        case "$choice" in
            Y|y|Yes|yes)
                OutputDirName
                break
                ;;
            N|n|No|no)
                OUTPUT="$default_dir"
                break
                ;;
            *)
                echo -e "\e[91mWrong input — please try again (Y/N)\e[0m"
                ;;
        esac
    done
}


# 1.2 function: insert domain & creds
InsertAD() {
    local YELLOW="\e[93m" NC="\e[0m"

    echo -e "${YELLOW}Enter Active Directory domain name (e.g. corp.local):${NC}"
    read -r DOMAIN_NAME

    echo -e "${YELLOW}Enter AD username:${NC}"
    read -r AD_USER

    echo -e "${YELLOW}Enter AD password:${NC}"
    read -rs -r AD_PASS
    echo

    log_message "AD domain set to $DOMAIN_NAME; user $AD_USER"
    echo -e "${YELLOW}AD settings updated.${NC}"
    _press_key "Press any key to continue…"
}

# Choosing output directory name
OutputDirName() {
    local dir choice

    while true; do
        # 1. Ask for preferred directory name
        echo -e "\e[95mPlease insert your preferred name for the directory:\e[0m"
        read -r dir

        # 2. Check if it already exists
        if [[ -d "$dir" ]]; then
            echo -e "\e[95mA directory with that name already exists.\e[0m"
            echo -e "\e[91mKeeping the chosen name will save output in the existing directory.\e[0m"
            while true; do
                echo -e "\e[95mWould you like to choose another name? (Y/N)\e[0m"
                read -r choice < /dev/tty
                case "$choice" in
                    Y|y|Yes|yes)
                        # loop back to ask for a new name
                        break
                        ;;
                    N|n|No|no)
                        # 3. Accept existing name and set OUTPUT
                        OUTPUT="$dir"
                        return
                        ;;
                    *)
                        echo -e "\e[91mWrong input. please try again\e[0m"
                        ;;
                esac
            done
            # if user chose to pick another name, outer loop repeats
        else
            # directory doesn't exist, accept it
            OUTPUT="$dir"
            break
        fi
    done
}

# Creativity - Allow the user to search inside the resaults
SearchDir() {
    local search results

    # Check if OUTPUT was set
    if [[ "$OUTPUT" == "None" ]]; then
        echo -e "\e[91m... No output directory name was selected ...\e[0m"
        sleep 3
        return
    fi

    # Check that the directory exists
    if [[ ! -d "$OUTPUT" ]]; then
        echo -e "\e[91m... Selected output directory \"$OUTPUT\" does not exist ...\e[0m"
        sleep 3
        return
    fi

    # Check if it contains any files
    if [[ -z "$(ls -A "$OUTPUT")" ]]; then
        echo -e "\e[91m... Selected output directory is empty ...\e[0m"
        sleep 3
        return
    fi

    # Ask for the search term
    echo -e "\e[95m... Type your search: ...\e[0m"
    read -r search

    # Perform the search
    results=$(grep -R -n --color=always "$search" "$OUTPUT")

    if [[ -z "$results" ]]; then
        echo -e "\e[95m... No results found for \"$search\" ...\e[0m"
    else
        echo -e "\e[95m... Results for \"$search\": ...\e[0m"
        echo "$results"
    fi
}

# 1.3 - Choose passwrod list, Rockyou is default
PWMenu() {
    local choice dir file_loc words modified_file

    while true; do
        # Menu header
        local YELLOW="\e[93m" NC="\e[0m"

        echo -e "${YELLOW}... Passwords/Wordlist Menu ...${NC}"
        echo -e "${YELLOW}... Current Passwords/Wordlist: $PWLIST    ...${NC}"
        echo -e "${YELLOW}... Passwords/Wordlist directory: $PWLDir    ...${NC}"
        echo -e "${YELLOW}... type number to execute: ...${NC}"

        # Options
        echo -e "1 - Create and change to basic Password list (1111, 1234, Kali, aA12345678, etc)"
        echo -e "2 - Select Password/Word list location"
        echo -e "3 - Add to current Password/Word list"
        echo -e "4 - Back to default - rockyou"
        echo -e "5 - Back to main menu"
        read -r choice < /dev/tty

        case "$choice" in
            1)
                # Create a basic list
                dir="Basic_PWList.txt"
                cat > "$dir" <<EOF
1111
1234
aA12345678
Kali
win
win10
administrator
Administrator
Admin
admin
msfadmin
EOF
                PWLDir="$PWD/$dir"
                PWLIST="Basic"
                log_message "Created basic password list at $PWLDir"
                echo -e "\e[93m... Basic password list created and selected ...\e[0m"
                ;;
            2)
                # Prompt for existing file or back
                while true; do
                    echo -e "\e[93mInsert new file location (or type 'back' to return):\e[0m"
                    read -r file_loc
                    if [[ "$file_loc" == "back" ]]; then
                        break
                    elif [[ -f "$file_loc" ]]; then
                        PWLDir="$file_loc"
                        PWLIST="Selected file"
                        log_message "Password list changed to $PWLDir"
                        echo -e "\e[93m... Password list set to $PWLDir ...\e[0m"
                        break
                    else
                        echo -e "\e[91mfile wasn't found\e[0m"
                    fi
                done
                ;;
            3)
                # Add words to current list
                echo -e "\e[93mType the words or numbers you would like to add to the current list, with space between them, and then Enter:\e[0m"
                read -r words
                if [[ -n "$words" ]]; then
                    modified_file="modified_PWList.txt"
                    {
                        for w in $words; do
                            printf '%s\n' "$w"
                        done
                        cat "$PWLDir"
                    } > "$modified_file"
                    PWLDir="$PWD/$modified_file"
                    PWLIST="Modified"
                    log_message "Modified password list created at $PWLDir"
                    echo -e "\e[93m... Modified password list created and selected ...\e[0m"
                fi
                ;;
            4)
                # Reset to default rockyou
                PWLIST="Default - rockyou"
                PWLDir="/usr/share/wordlists/rockyou.txt"
                log_message "Password list reset to default rockyou"
                echo -e "\e[93m... Password list reset to default rockyou ...\e[0m"
                ;;
            5)
                # Back to main menu
                break
                ;;
            *)
                echo -e "\e[91m... wrong input. try again ...\e[0m"
                ;;
        esac
    done
}

# ==========================================================
# ModesExecute
# Runs the selected modes (Scanning / Enumeration / Exploitation)
# Saves results into $OUTPUT/<timestamp>/, writes a consolidated TXT,
# and converts it to PDF when possible.
# ==========================================================
ModesExecute() {
    local YELLOW="\e[93m" RED="\e[91m" GREY="\e[90m" NC="\e[0m"
    local ts outdir runlog pdfout base dc_ip=""
    ts="$(date +%Y%m%d_%H%M%S)"
    outdir="${OUTPUT%/}/run_${ts}"
    mkdir -p "$outdir"

    base="$outdir/report_${ts}"
    runlog="${base}.txt"
    pdfout="${base}.pdf"

    # --- Progress tracker ----------------------------------------------------
    local STEP=0
    local TOTAL_STEPS=7    # 1) Prep 2) Scan 3) Enum 4) Exploit 5) Results/PDF 6) Ownership 7) Done
    phase() { STEP=$((STEP+1)); echo -e "${YELLOW}[Step ${STEP}/${TOTAL_STEPS}] $*${NC}"; log_message "[Step ${STEP}/${TOTAL_STEPS}] $*"; }
    stage() { echo -e "${YELLOW}[*] $*${NC}"; log_message "$*"; }

    # --- Report helpers ------------------------------------------------------
    header() {
        {
            echo
            echo "================================================================"
            echo "$*"
            echo "================================================================"
            echo
        } | tee -a "$runlog" >/dev/null
    }
    run_capture() {
        local title="$1"; shift
        header "$title"
        echo -e "${GREY}\$ $*${NC}"
        { echo "\$ $*"; "$@" < /dev/null 2>&1; echo; } | tee -a "$runlog"
    }

    # --- TXT -> PDF ----------------------------------------------------------
    to_pdf() {
        if command -v enscript >/dev/null 2>&1 && command -v ps2pdf >/dev/null 2>&1; then
            stage "Converting report to PDF via enscript+ps2pdf (5.1)"
            enscript -B -q -p - "$runlog" | ps2pdf - "$pdfout" && return 0
        elif command -v pandoc >/dev/null 2>&1; then
            stage "Converting report to PDF via pandoc (5.1)"
            pandoc "$runlog" -o "$pdfout" && return 0
        elif command -v libreoffice >/dev/null 2>&1; then
            stage "Converting report to PDF via LibreOffice (5.1)"
            libreoffice --headless --convert-to pdf --outdir "$outdir" "$runlog" >/dev/null 2>&1 && \
                mv "$outdir/report_${ts}.pdf" "$pdfout" 2>/dev/null && return 0
        fi
        return 1
    }

        # --- Helpers: CME feature-detect for password spray ----------------------
    _cme_supports_spray() { crackmapexec smb -h 2>&1 | grep -q -- '--spray'; }

    _cme_spray_or_fallback() {
        # $1 targets, $2 domain, $3 user (or users file), $4 password list
        local targets="$1" domain="$2" user="$3" passlist="$4"
        if _cme_supports_spray; then
            crackmapexec smb "$targets" -d "$domain" -u "$user" -p "$passlist" --spray
        else
            # Fallback: 1 pass per line; continue on success to find multiple hits safely
            while IFS= read -r P; do
                crackmapexec smb "$targets" -d "$domain" -u "$user" -p "$P" --continue-on-success
            done < "$passlist"
        fi
    }

    # --- Tunables & wrappers (timeouts) -------------------------------------
    local T_NMAP="25m" T_LDAP="2m" T_RPC="1m" T_HASHCAT="30m"
    rc_nmap() { local title="$1"; shift; run_capture "$title" timeout --foreground "$T_NMAP" "$@"; }
    rc_ldap() { local title="$1"; shift; run_capture "$title" timeout --foreground "$T_LDAP" "$@"; }
    rc_rpc()  { local title="$1"; shift; run_capture "$title" timeout --foreground "$T_RPC"  "$@"; }

    # CME capability check (some builds lack --spray)
    cme_supports_spray() { crackmapexec smb -h 2>&1 | grep -q -- '--spray'; }

    # --- DC discovery helpers -----------------------------------------------
    _domain_to_basedn() {
        local d="$1"
        [[ -z "$d" || "$d" == "None" ]] && return 1
        printf 'dc=%s\n' "${d//./,dc=}"
    }
    resolve_dc_ip() {
        local d="$1" srv hostn ip
        [[ -z "$d" || "$d" == "None" ]] && return 1
        if command -v dig >/dev/null 2>&1; then
            srv="$(dig +short _ldap._tcp.dc._msdcs."$d" SRV 2>/dev/null | awk '{print $4}' | sed 's/\.$//' | head -n1)"
            [[ -n "$srv" ]] && ip="$(dig +short "$srv" A 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)"
        elif command -v host >/dev/null 2>&1; then
            hostn="$(host -t SRV _ldap._tcp.dc._msdcs."$d" 2>/dev/null | awk '{print $NF}' | sed 's/\.$//' | head -n1)"
            [[ -n "$hostn" ]] && ip="$(host "$hostn" 2>/dev/null | awk '/has address/{print $4; exit}')"
        else
            hostn="$(nslookup -type=SRV _ldap._tcp.dc._msdcs."$d" 2>/dev/null | awk '/service =/ {print $NF}' | sed 's/\.$//' | head -n1)"
            [[ -n "$hostn" ]] && ip="$(nslookup "$hostn" 2>/dev/null | awk '/Address: / {print $2; exit}')"
        fi
        [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && echo "$ip"
    }
    find_dc_ip_in_range() {
        local domain="$1" range="$2" ip basedn got
        basedn="$(_domain_to_basedn "$domain")" || return 1
        while read -r ip; do
            got="$(ldapsearch -LLL -x -H "ldap://$ip" -s base defaultNamingContext 2>/dev/null \
                  | sed -n 's/^defaultNamingContext:[[:space:]]*//Ip' | head -n1)"
            if [[ -n "$got" ]]; then
                local got_lc="${got,,}" base_lc="${basedn,,}"
                if [[ "$got_lc" == "$base_lc" ]]; then
                    echo "$ip"; return 0
                fi
            fi
        done < <(nmap -Pn --open -p389 "$range" -oG - 2>/dev/null | awk '/open/{print $2}')
        return 1
    }
    resolve_or_find_dc_ip() {
        local domain="$1" range="$2" ip=""
        ip="$(resolve_dc_ip "$domain")"
        [[ -z "$ip" ]] && ip="$(find_dc_ip_in_range "$domain" "$range")"
        [[ -n "$ip" ]] && echo "$ip"
    }

    # --- Step 1/7: Preparation ----------------------------------------------
    phase "Preparation"
    log_message "ModesExecute start (Sc=$ScMode En=$EnMode Ex=$ExMode Range=$NTADR Domain=$DOMAIN_NAME User=$AD_USER)"

    header "Session Metadata"
    {
        echo "Timestamp       : $ts"
        echo "Network Range   : $NTADR"
        echo "Output Dir      : $outdir"
        echo "Scan Mode       : $ScMode"
        echo "Enum Mode       : $EnMode"
        echo "Exploit Mode    : $ExMode"
        echo "Domain          : $DOMAIN_NAME"
        echo "AD User         : $AD_USER"
        echo
    } | tee -a "$runlog"

    header "Tool versions"
    {
        nmap --version 2>/dev/null | head -n1
        crackmapexec --version 2>&1 | head -n1 || true
        ldapsearch -VV 2>&1 | head -n1 || ldapsearch -V 2>&1 | head -n1 || true
        impacket-GetUserSPNs -h 2>&1 | head -n1 | sed "s/Usage.*//" || true
        rpcclient -V 2>&1 || true
        hashcat --version 2>/dev/null | head -n1 || true
        enscript --version 2>/dev/null | head -n1 || true
        ps2pdf -h 2>&1 | head -n1 | sed -n "1p" || true
    } | sed "/^$/d" | tee -a "$runlog"

    # --- Step 2/7: Scanning --------------------------------------------------
    phase "Scanning"
    if [[ "$ScMode" != "Off" ]]; then
        # helpers
        scan_basic() {
            run_capture "2.1 Nmap Basic Scan (-Pn)" \
                nmap -Pn -T4 -oN "$outdir/nmap_basic.txt" "$NTADR"
        }
        scan_intermediate() {
            run_capture "2.2 Nmap Intermediate Scan (-Pn -p-)" \
                nmap -Pn -p- -T4 -oN "$outdir/nmap_intermediate.txt" "$NTADR"
        }
        scan_advanced() {
            run_capture "2.3 TCP all ports" \
                nmap -Pn -p- -sS -T4 -oN "$outdir/nmap_tcp_all.txt" "$NTADR"
            run_capture "2.3 UDP top 200" \
                nmap -Pn -sU --top-ports 200 -T4 -oN "$outdir/nmap_udp_top200.txt" "$NTADR"
        }

        # cumulative execution
        case "$ScMode" in
            Basic)        scan_basic ;;
            Intermediate) scan_basic; scan_intermediate ;;
            Advanced)     scan_basic; scan_intermediate; scan_advanced ;;
        esac
    else
        header "2. Scanning Mode"
        echo "turned off" | tee -a "$runlog"
    fi

    # --- Step 3/7: Enumeration ----------------------------------------------
    phase "Enumeration"
    if [[ "$EnMode" != "Off" ]]; then
        local NO_DC=0
        dc_ip="$(resolve_or_find_dc_ip "$DOMAIN_NAME" "$NTADR")"
        header "Active Directory target"
        if [[ -z "$dc_ip" ]]; then
            NO_DC=1
            echo -e "\e[91mCould not locate a Domain Controller for \"$DOMAIN_NAME\" in \"$NTADR\".\e[0m" | tee -a "$runlog"
            echo -e "\e[93mTip:\e[0m ensure the DC is up and listening on TCP/389, or point Kali DNS to the DC." | tee -a "$runlog"
        else
            echo "Using DC IP: $dc_ip" | tee -a "$runlog"
            log_message "Using DC IP: $dc_ip"
        fi

        stage "Enumeration Phase (3)"

        enum_basic() {
            run_capture "3.1.1 Nmap service/version detection" \
                nmap -Pn -sV -T4 -oN "$outdir/enum_services_sV.txt" "$NTADR"
            header "3.1.2 Domain Controller IP"
            echo "${dc_ip:+Detected DC IP: $dc_ip}" | tee -a "$runlog"
            run_capture "3.1.3 Attempt DHCP server discovery (UDP/67, dhcp-discover)" \
                nmap -sU -p67 --script=dhcp-discover -oN "$outdir/enum_dhcp_discover.txt" "$NTADR"
        }

        enum_intermediate() {
            run_capture "3.2.1 Enumerate hosts by key services (FTP, SSH, SMB, WinRM, LDAP/LDAPS, RDP)" \
                nmap -Pn --open -p21,22,445,5985,5986,389,636,3389 -oG "$outdir/enum_key_services.gnmap" "$NTADR"

            if [[ "$AD_USER" != "None" && "$AD_PASS" != "None" ]]; then
                run_capture "3.2.2 Shares via CrackMapExec (with domain if set)" \
                    bash -c "crackmapexec smb \"$NTADR\" ${DOMAIN_NAME:+-d \"$DOMAIN_NAME\"} -u \"$AD_USER\" -p \"$AD_PASS\" --shares"
            else
                run_capture "3.2.2 Shares via CrackMapExec (unauthenticated)" \
                    crackmapexec smb "$NTADR" --shares
            fi

                            # --- Unauth NSE (keep these) ---
                rc_nmap "3.2.3 Nmap NSE: smb-enum-shares (unauth)" \
                    nmap -Pn -p445 --script smb-enum-shares \
                         -oN "$outdir/nse_smb_enum_shares.txt" "$NTADR"

                rc_nmap "3.2.3 Nmap NSE: smb-enum-users (unauth)" \
                    nmap -Pn -p445 --script smb-enum-users \
                         -oN "$outdir/nse_smb_enum_users.txt" "$NTADR"

                rc_nmap "3.2.3 Nmap NSE: ldap-search (unauth)" \
                    nmap -Pn -p389 --script ldap-search \
                         -oN "$outdir/nse_ldap_search.txt" "${dc_ip:-$NTADR}"

                # --- Auth NSE (run *in addition* when creds exist) ---
                if [[ "$AD_USER" != "None" && "$AD_PASS" != "None" ]]; then
                    # SMB scripts with SMB auth
                    rc_nmap "3.2.3 Nmap NSE: smb-enum-shares (auth)" \
                        nmap -Pn -p445 --script smb-enum-shares \
                             --script-args smbusername="$AD_USER",smbpassword="$AD_PASS",smbdomain="$DOMAIN_NAME" \
                             -oN "$outdir/nse_smb_enum_shares_auth.txt" "$NTADR"

                    rc_nmap "3.2.3 Nmap NSE: smb-enum-users (auth)" \
                        nmap -Pn -p445 --script smb-enum-users \
                             --script-args smbusername="$AD_USER",smbpassword="$AD_PASS",smbdomain="$DOMAIN_NAME" \
                             -oN "$outdir/nse_smb_enum_users_auth.txt" "$NTADR"

                    # LDAP script with LDAP auth pointed at the DC if we have it
                    base_dn="dc=${DOMAIN_NAME//./,dc=}"
                    rc_nmap "3.2.3 Nmap NSE: ldap-search (auth@DC)" \
                        nmap -Pn -p389 --script ldap-search \
                             --script-args "ldap.username=${AD_USER}@${DOMAIN_NAME},ldap.password=${AD_PASS},ldap.base=${base_dn}" \
                             -oN "$outdir/nse_ldap_search_auth.txt" "${dc_ip:-$NTADR}"
                fi
        }

        enum_advanced() {
            if [[ "$DOMAIN_NAME" == "None" || "$AD_USER" == "None" || "$AD_PASS" == "None" ]]; then
                header "3.3 Advanced Enumeration"
                echo "AD credentials not set. Skipping 3.3 block." | tee -a "$runlog"
                return
            fi
            if (( NO_DC )); then
                header "3.3 Advanced Enumeration"
                echo "Skipping (no DC found)." | tee -a "$runlog"
                return
            fi

            run_capture "3.3.1 Extract all users (Impacket GetADUsers)" \
                bash -c "impacket-GetADUsers \"${DOMAIN_NAME}/${AD_USER}:${AD_PASS}\" -all -dc-ip \"$dc_ip\""

            run_capture "3.3.2 Extract all groups (ldapsearch)" \
                bash -c "ldapsearch -x -H ldap://$dc_ip -D \"${AD_USER}@${DOMAIN_NAME}\" -w \"${AD_PASS}\" -b \"dc=${DOMAIN_NAME//./,dc=}\" '(objectClass=group)' cn"

            run_capture "3.3.3 Enumerate shares (CrackMapExec with creds)" \
                bash -c "crackmapexec smb \"$NTADR\" -d \"$DOMAIN_NAME\" -u \"$AD_USER\" -p \"$AD_PASS\" --shares"

            run_capture "3.3.4 Password policy (rpcclient getdompwinfo)" \
                bash -c "rpcclient -U \"${AD_USER}%${AD_PASS}\" \"$dc_ip\" -c getdompwinfo"

            run_capture "3.3.5 Disabled accounts (ldapsearch UAC bit 2)" \
                bash -c "ldapsearch -x -H ldap://$dc_ip -D \"${AD_USER}@${DOMAIN_NAME}\" -w \"${AD_PASS}\" -b \"dc=${DOMAIN_NAME//./,dc=}\" '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))' sAMAccountName"

            run_capture "3.3.6 Never-expired accounts (ldapsearch UAC bit 0x10000)" \
                bash -c "ldapsearch -x -H ldap://$dc_ip -D \"${AD_USER}@${DOMAIN_NAME}\" -w \"${AD_PASS}\" -b \"dc=${DOMAIN_NAME//./,dc=}\" '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))' sAMAccountName"

            run_capture "3.3.7 Domain Admins membership (ldapsearch)" \
                bash -c "ldapsearch -x -H ldap://$dc_ip -D \"${AD_USER}@${DOMAIN_NAME}\" -w \"${AD_PASS}\" -b \"cn=Domain Admins,cn=Users,dc=${DOMAIN_NAME//./,dc=}\" member"
        }

        # cumulative execution
        case "$EnMode" in
            Basic)        enum_basic ;;
            Intermediate) enum_basic; enum_intermediate ;;
            Advanced)     enum_basic; enum_intermediate; enum_advanced ;;
        esac
    else
        header "3. Enumeration Mode"
        echo "turned off" | tee -a "$runlog"
    fi

    # --- Step 4/7: Exploitation ---------------------------------------------
    phase "Exploitation"
    if [[ "$ExMode" != "Off" ]]; then
        stage "Exploitation Phase (4)"

        exploit_basic() {
            run_capture "4.1 Nmap NSE vuln scan (--script vuln)" \
                nmap -Pn --script vuln -T4 -oN "$outdir/nse_vuln.txt" "$NTADR"
        }
        exploit_intermediate() {
            if [[ "$DOMAIN_NAME" != "None" && "$AD_USER" != "None" && -n "$PWLIST" ]]; then
                run_capture "4.2 Password spraying (CrackMapExec SMB)" \
                bash -c '
                if [ -z "'"$PWLIST"'" ] || [ ! -s "'"$PWLIST"'" ]; then
                    echo "Password list is empty or missing; skipping spray."
                    exit 0
                fi
                if crackmapexec smb -h 2>&1 | grep -q -- "--spray"; then
                    crackmapexec smb "'"$NTADR"'" -d "'"$DOMAIN_NAME"'" -u "'"$AD_USER"'" -p "'"$PWLIST"'" --spray
                else
                    while IFS= read -r P; do
                        crackmapexec smb "'"$NTADR"'" -d "'"$DOMAIN_NAME"'" -u "'"$AD_USER"'" -p "$P" --continue-on-success
                    done < "'"$PWLIST"'"
                fi
                '
            else
                header "4.2 Password spraying"
                echo "Missing DOMAIN/AD_USER/PWLIST. Skipping spray." | tee -a "$runlog"
            fi
        }
        exploit_advanced() {
            if [[ "$DOMAIN_NAME" != "None" && "$AD_USER" != "None" && "$AD_PASS" != "None" ]]; then
                [[ -z "$dc_ip" ]] && dc_ip="$(resolve_or_find_dc_ip "$DOMAIN_NAME" "$NTADR")"
                if [[ -z "$dc_ip" ]]; then
                    header "4.3 Kerberos tickets"
                    echo "Skipping (no DC found)." | tee -a "$runlog"
                    return
                fi
                run_capture "4.3 GetUserSPNs request TGS (Impacket)" \
                    bash -c "impacket-GetUserSPNs \"${DOMAIN_NAME}/${AD_USER}:${AD_PASS}\" -request -dc-ip \"$dc_ip\" -outputfile \"$outdir/tgs_hashes_${ts}.txt\""

                if command -v hashcat >/dev/null 2>&1; then
                    run_capture "4.3 Crack TGS hashes with hashcat (mode 13100, if any)" \
                    bash -c '
                        f="'"$outdir"'/tgs_hashes_'"$ts"'.txt"
                        pot="'"$outdir"'/hashcat_'"$ts"'.potfile"
                        if [ -s "$f" ]; then
                            hashcat -m 13100 "$f" "'"$PWLDir"'" --potfile-path "$pot"
                            hc=$?
                            if   [ $hc -eq 0 ];  then echo "hashcat finished (hit(s) found or clean exit)."
                            elif [ $hc -eq 1 ];  then echo "hashcat finished exhausted (no hits)."
                            else                     echo "hashcat returned status $hc (possible error)."
                            fi
                            owner="${SUDO_USER:-$USER}"; chown "$owner":"$owner" "$pot" 2>/dev/null || true
                        else
                            echo "No TGS hashes were generated; skipping hashcat."
                        fi'
                else
                    header "4.3 Hash cracking"
                    echo "hashcat not installed; saved hashes to: $outdir/tgs_hashes_${ts}.txt" | tee -a "$runlog"
                fi
            else
                header "4.3 Kerberos tickets"
                echo "AD creds missing. Skipping TGS extraction/cracking." | tee -a "$runlog"
            fi
        }

        # cumulative execution
        case "$ExMode" in
            Basic)        exploit_basic ;;
            Intermediate) exploit_basic; exploit_intermediate ;;
            Advanced)     exploit_basic; exploit_intermediate; exploit_advanced ;;
        esac
    else
        header "4. Exploitation Mode"
        echo "turned off" | tee -a "$runlog"
    fi

    # --- Step 5/7: Results & PDF --------------------------------------------
    phase "Results & PDF"
    if to_pdf; then
        stage "Report saved to: $pdfout (5.1)"
        log_message "PDF report created: $pdfout"
    else
        echo -e "${RED}[!] PDF conversion not available. Kept TXT at: ${runlog}${NC}"
        log_message "PDF conversion failed/missing tools; TXT kept: $runlog"
    fi

    # --- Step 6/7: Ownership fix --------------------------------------------
    phase "Finalize outputs (permissions)"
    owner="${SUDO_USER:-$USER}"
    chown -R "$owner":"$owner" "$outdir" 2>/dev/null || true

    # --- Step 7/7: Done ------------------------------------------------------
    phase "Done"
    log_message "ModesExecute finished"
    echo -e "${YELLOW}Done. Outputs in: $outdir${NC}"
    _press_key "Press any key to return to menu…"
}


#Menu function
function Menu() {
    local YELLOW="\e[93m"
    local GREY="\e[90m"
    local NC="\e[0m"

    while true; do
        clear

        # build the colorized mode‐strings (including Off)
        case "$ScMode" in
            Basic)        SM="${YELLOW}Basic${NC}${GREY}/Intermediate${NC}${GREY}/Advanced${NC}${GREY}/Off${NC}" ;;
            Intermediate) SM="${GREY}Basic${NC}/${YELLOW}Intermediate${NC}${GREY}/Advanced${NC}/${GREY}Off${NC}" ;;
            Advanced)     SM="${GREY}Basic${NC}/${GREY}Intermediate${NC}/${YELLOW}Advanced${NC}${GREY}/Off${NC}" ;;
            Off)          SM="${GREY}Basic${NC}/${GREY}Intermediate${NC}/${GREY}Advanced${NC}/${YELLOW}Off${NC}" ;;
        esac

        case "$EnMode" in
            Basic)        EM="${YELLOW}Basic${NC}${GREY}/Intermediate${NC}${GREY}/Advanced${NC}${GREY}/Off${NC}" ;;
            Intermediate) EM="${GREY}Basic${NC}/${YELLOW}Intermediate${NC}${GREY}/Advanced${NC}/${GREY}Off${NC}" ;;
            Advanced)     EM="${GREY}Basic${NC}/${GREY}Intermediate${NC}/${YELLOW}Advanced${NC}${GREY}/Off${NC}" ;;
            Off)          EM="${GREY}Basic${NC}/${GREY}Intermediate${NC}/${GREY}Advanced${NC}/${YELLOW}Off${NC}" ;;
        esac

        case "$ExMode" in
            Basic)        XM="${YELLOW}Basic${NC}${GREY}/Intermediate${NC}${GREY}/Advanced${NC}${GREY}/Off${NC}" ;;
            Intermediate) XM="${GREY}Basic${NC}/${YELLOW}Intermediate${NC}${GREY}/Advanced${NC}/${GREY}Off${NC}" ;;
            Advanced)     XM="${GREY}Basic${NC}/${GREY}Intermediate${NC}/${YELLOW}Advanced${NC}${GREY}/Off${NC}" ;;
            Off)          XM="${GREY}Basic${NC}/${GREY}Intermediate${NC}/${GREY}Advanced${NC}/${YELLOW}Off${NC}" ;;
        esac

        # header
        echo -e "${YELLOW}... MENU ...${NC}"
        echo -e "${YELLOW}... Network Range: $NTADR    ...${NC}"
        echo -e "${YELLOW}... AD Domain:       $DOMAIN_NAME    ...${NC}"
        echo -e "${YELLOW}... AD User:         $AD_USER        ...${NC}"
        echo -e "${YELLOW}... Output Dir Name: $OUTPUT         ...${NC}"
        echo -e "${YELLOW}... Password list:   $PWLIST        ...${NC}"
        echo -e "${YELLOW}... Scanning Mode:   $SM            ...${NC}"
        echo -e "${YELLOW}... Enumeration Mode:$EM            ...${NC}"
        echo -e "${YELLOW}... Exploitation Mode:$XM           ...${NC}"
        echo -e "${YELLOW}... type the number to execute: ...${NC}"

        # options
        echo "1  - Install needed apps (will skip installation if not needed)"
        echo "2  - Check if I'm anonymous"
        echo "3  - Enter/Change Network Range"
        echo "4  - Change output directory name"
        echo "5  - Insert domain name and Active Directory credentials"

        # 6: Scanning mode toggle + CUMULATIVE description
        echo -e "6  - Scanning mode: $ScMode (type 6 to switch)"
        case "$ScMode" in
            Basic)
                echo "    Use the -Pn option in Nmap to assume all hosts are online, bypassing discovery."
                ;;
            Intermediate)
                echo "    Use the -Pn option in Nmap to assume all hosts are online, bypassing discovery."
                echo "    Scan all 65535 ports using the -p- flag"
                ;;
            Advanced)
                echo "    Use the -Pn option in Nmap to assume all hosts are online, bypassing discovery."
                echo "    Scan all 65535 ports using the -p- flag"
                echo "    Include UDP scanning for a thorough analysis"
                ;;
            Off)
                echo "    turned off"
                ;;
        esac

        # 7: Enumeration mode toggle + CUMULATIVE description (+ AD note on Advanced)
        echo -e "7  - Enumeration mode: $EnMode (type 7 to switch)"
        case "$EnMode" in
            Basic)
                echo "    Identifies services on open ports, domain-controller IP and DHCP-server IP."
                ;;
            Intermediate)
                echo "    Identifies services on open ports, domain-controller IP and DHCP-server IP."
                echo "    Enumerates key services (FTP, SSH, SMB, WinRM, LDAP, RDP) and shared folders."
                ;;
            Advanced)
                echo "    Identifies services on open ports, domain-controller IP and DHCP-server IP."
                echo "    Enumerates key services (FTP, SSH, SMB, WinRM, LDAP, RDP) and shared folders."
                echo "    Extracts users, groups, shares; shows password policy; finds disabled/never-expired accounts and Domain Admins."
                echo -e "${YELLOW}    (Available only if AD creds entered)${NC}"
                ;;
            Off)
                echo "    turned off"
                ;;
        esac

        # 8: Exploitation mode toggle + CUMULATIVE description
        echo -e "8  - Exploitation mode: $ExMode (type 8 to switch)"
        case "$ExMode" in
            Basic)
                echo "    Deploy the NSE vulnerability scanning script"
                ;;
            Intermediate)
                echo "    Deploy the NSE vulnerability scanning script"
                echo "    Execute domain-wide password spraying to identify weak credentials."
                ;;
            Advanced)
                echo "    Deploy the NSE vulnerability scanning script"
                echo "    Execute domain-wide password spraying to identify weak credentials."
                echo "    Extract and attempt to crack Kerberos tickets using pre-supplied passwords."
                ;;
            Off)
                echo "    turned off"
                ;;
        esac

        # 9: Execute (yellow number, white label)
        echo -e "${YELLOW}9${NC}  - Execute"

        # bumped options
        echo "10 - Password list options"
        echo "11 - Search output"
        echo "12 - Exit"

        num="$(_read_menu_choice)"
        case "$num" in
            1)  install_apps            ;;
            2)  isAnon                  ;;
            3)  EnterAdr                ;;
            4)  OutputDirName           ;;
            5)  InsertAD                ;;
            6)  # cycle Scanning mode
                case "$ScMode" in
                    Basic)        ScMode="Intermediate" ;;
                    Intermediate) ScMode="Advanced"     ;;
                    Advanced)     ScMode="Off"          ;;
                    Off)          ScMode="Basic"        ;;
                esac
                ;;
            7)  # cycle Enumeration mode
                case "$EnMode" in
                    Basic)        EnMode="Intermediate" ;;
                    Intermediate) EnMode="Advanced"     ;;
                    Advanced)     EnMode="Off"          ;;
                    Off)          EnMode="Basic"        ;;
                esac
                ;;
            8)  # cycle Exploitation mode
                case "$ExMode" in
                    Basic)        ExMode="Intermediate" ;;
                    Intermediate) ExMode="Advanced"     ;;
                    Advanced)     ExMode="Off"          ;;
                    Off)          ExMode="Basic"        ;;
                esac
                ;;
            9)  # Execute: validation then run ModesExecute
                if [[ "$NTADR" == "None" ]]; then
                    echo -e "\e[91m... No network range set. Please set one with option 3 ...\e[0m"
                    _press_key "Press any key to continue…"
                elif [[ "$ScMode" == "Off" && "$EnMode" == "Off" && "$ExMode" == "Off" ]]; then
                    echo -e "\e[91m... All modes are Off. Please enable at least one mode ...\e[0m"
                    _press_key "Press any key to continue…"
                elif [[ "$EnMode" == "Advanced" && ( "$DOMAIN_NAME" == "None" || "$AD_USER" == "None" ) ]]; then
                    echo -e "\e[91m... AD credentials required for Advanced enumeration. Set them with option 5 ...\e[0m"
                    _press_key "Press any key to continue…"
                else
                    ModesExecute
                fi
                ;;
            10) PWMenu                  ;;
            11) SearchDir               ;;
            12) break                   ;;
            *)
                echo -e "\e[91m... wrong number. try again ...\e[0m"
                _press_key
                ;;
        esac
    done
}



# ensure defaults remain:
ScMode="Basic"
EnMode="Basic"
ExMode="Basic"


# Global variables 
ScMode="Basic"
EnMode="Basic"
ExMode="Basic"
NTADR="None"
OUTPUT="None"
PWLIST="Default - rockyou"
PWLDir="/usr/share/wordlists/rockyou.txt"
DOMAIN_NAME="None"
AD_USER="None"
AD_PASS="None"
# Calling Menu Function
Menu

# Log data collection
echo -e "\e[93m... Data collection log: ...\e[0m"
echo -e "\e[93m... Script ended on: $(date) ...\e[0m"

# Closing the log file
# If script stdin isn’t a tty, reattach for all reads
if [[ ! -t 0 && -r /dev/tty ]]; then
  exec < /dev/tty
fi


### Network Security Project ###
### Nissim Atar ###
### s17 ###
### JMagen773630 ###
