#! /bin/bash

### Penetration Testing Project ###
### Nissim Atar ###
### s17 ###
### JMagen773630 ###

#3.2 creating log file
log_file="/var/log/project3.log"


#function for log message
log_message()
{
        echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$log_file"
}

# Install apps function
install_apps() {
    # Document start of the check
    log_message "checking apps installation"

    apps=(nmap hydra medusa searchsploit metasploit)

    for app in "${apps[@]}"; do
        if dpkg -s "$app" &>/dev/null; then
            # Already installed: only echo to user, no logging
            echo -e "\e[95m... $app is already installed ...\e[0m"
        else
            # Not installed: echo and log before installing
            echo -e "\e[95m... $app is not installed, installing... ...\e[0m"
            log_message "installing $app"
            sudo apt-get update
            sudo apt-get install -y "$app"
            log_message "$app is installed."
        fi
    done

    # Final status
    echo -e "\e[95m... All required apps are installed and up to date ...\e[0m"
    log_message "all apps exist"
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
    #1.4: display the spoofed country name
	    echo "Spoofed Country: $(curl -s https://api.myip.com | grep -oP '(?<="country":")[^"]*')"
    fi
}

# 1.1 + 1.4 Function - Get address and validate
# 1.2 Enter output directory name option 
EnterAdr() {
    local ip octets valid
    # regex for basic IPv4 structure: four 1–3 digit numbers separated by dots
    local re='^([0-9]{1,3}\.){3}[0-9]{1,3}$'

    while true; do
        # 1. prompt in purple
        echo -e "\e[95mPlease type a network address, for example 127.0.0.11\e[0m"
        read -r ip

        # 2. validate structure first
        if [[ $ip =~ $re ]]; then
            valid=1
            IFS='.' read -r -a octets <<< "$ip"
            # check each octet is in 0–255
            for oct in "${octets[@]}"; do
                if (( oct < 0 || oct > 255 )); then
                    valid=0
                    break
                fi
            done

            if (( valid )); then
                # 3. assign to external NTADR and 4. log it
                NTADR="$ip"
                log_message "Network address entered: $NTADR"
                break
            fi
        fi

        # invalid: inform and loop again
        echo -e "\e[91mInvalid address — please try again. For example: 127.0.0.11\e[0m"
    done

    # --- New: default OUTPUT prompt ---
    local default_dir="${NTADR}_output"
    echo -e "\e[95mDefault output directory name is \"$default_dir\". would you like to change it? (Y/N)\e[0m"

    while true; do
        read -r choice
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
                echo -e "\e[91mWrong input. please try again\e[0m"
                ;;
        esac
    done
}


# 1.2 Choosing output directory name
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
                read -r choice
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

# 1.3 + 1.3.1 Basic scan (TCP, UDP, Service versions, trying weak passwords)
# 4.4 Option to zip resaults
BasicScn() {
    local masscan_file nmout outfile hosts host \
          tcp_ports udp_ports portspec zip_file choice success_count=0

    # 0. Prepare output file
    [[ ! -d "$OUTPUT" ]] && mkdir -p "$OUTPUT"
    outfile="$OUTPUT/${NTADR}_basic.txt"
    : > "$outfile"
    echo "Basic scan results for network $NTADR" >> "$outfile"

    # 1. Fast TCP+UDP discovery with masscan
    masscan_file="$OUTPUT/${NTADR}_masscan.txt"
    echo -e "\e[95m... Performing fast TCP+UDP discovery on $NTADR with masscan ...\e[0m"
    log_message "Starting masscan on $NTADR"
    sudo masscan "$NTADR" -p1-1000,U:1-1000 --rate=1000 -oL "$masscan_file"

    # 2. Parse masscan for unique hosts
    hosts=( $(awk '$1=="open"{print $4}' "$masscan_file" | sort -u) )
    if (( ${#hosts[@]} == 0 )); then
        echo -e "\e[91m... No hosts with open ports found in $NTADR ...\e[0m"
        return
    fi
    echo -e "\e[95m... Hosts with open ports: ${hosts[*]} ...\e[0m"
    log_message "Hosts discovered via masscan: ${hosts[*]}"

    # 3. For each host, deeper scan+bruteforce
    for host in "${hosts[@]}"; do
        echo -e "\e[95m... Starting deeper scan on $host ...\e[0m"
        log_message "Scanning $host"
        echo "Host: $host" >> "$outfile"

        # build port lists
        tcp_ports=$(awk -v h="$host" '$1=="open"&&$4==h&&$2=="tcp"{print $3}' "$masscan_file" | paste -sd, -)
        udp_ports=$(awk -v h="$host" '$1=="open"&&$4==h&&$2=="udp"{print $3}' "$masscan_file" | paste -sd, -)
        portspec=""
        [[ -n "$tcp_ports" ]] && portspec="$tcp_ports"
        [[ -n "$udp_ports" ]] && portspec+="${portspec:+,}U:$udp_ports"

        if [[ -z "$portspec" ]]; then
            echo -e "\e[91m... No open ports on $host ...\e[0m"
            echo "No open ports on $host" >> "$outfile"
            continue
        fi

        nmout=$(mktemp)
        nmap -sTU -sV -p"$portspec" "$host" -oG "$nmout"

        #  nmap + brute‐force
        while IFS= read -r entry; do
            IFS='/' read -r port _ proto _ service _ version <<<"$entry"
            echo "Found $service on port $port/$proto" >> "$outfile"

            if [[ "$proto" == "tcp" ]]; then
                echo -e "\e[95m... Trying login on $service/$port ...\e[0m"
                if [[ "$service" =~ ^(ssh|telnet)$ ]]; then
                    # Medusa for SSH/Telnet
                    medusa_out="${nmout}_${service}_medusa.txt"
                    medusa -h "$host" -U "$PWLDir" -P "$PWLDir" \
                           -M "$service" -n "$port" -f -O "$medusa_out" &>/dev/null
                    if grep -q SUCCESS "$medusa_out"; then
                        while read -r line; do
                            user=$(echo "$line" | sed -n 's/.*login:\([^ ]*\).*/\1/p')
                            pass=$(echo "$line" | sed -n 's/.*password:\([^ ]*\).*/\1/p')
                            cred="$user:$pass"
                            echo -e "\e[95m... SUCCESS: $service/$port → $cred\e[0m"
                            echo "[$service @ $port] SUCCESS: $cred" >> "$outfile"
                            (( success_count++ ))
                        done < <(grep SUCCESS "$medusa_out")
                        log_message "Valid creds for $service on $port of $host"
                    else
                        echo -e "\e[91m... FAIL: no valid creds for $service/$port\e[0m"
                        echo "[$service @ $port] FAIL: no valid credentials" >> "$outfile"
                    fi
                    rm -f "$medusa_out"
                else
                    # Hydra for other TCP services
                    hydra_out="${nmout}_${service}_hydra.txt"
                    hydra -L "$PWLDir" -P "$PWLDir" -s "$port" \
                          "$service"://"$host" -f -o "$hydra_out" &>/dev/null
                    if [[ -s "$hydra_out" ]]; then
                        while read -r cred; do
                            echo -e "\e[95m... SUCCESS: $service/$port → $cred\e[0m"
                            echo "[$service @ $port] SUCCESS: $cred" >> "$outfile"
                            (( success_count++ ))
                        done < "$hydra_out"
                        log_message "Valid creds for $service on $port of $host"
                    else
                        echo -e "\e[91m... FAIL: no valid creds for $service/$port\e[0m"
                        echo "[$service @ $port] FAIL: no valid credentials" >> "$outfile"
                    fi
                    rm -f "$hydra_out"
                fi
            fi
        done < <(grep '/open/' "$nmout" | sed -e 's/.*Ports: //' -e 's/, /\n/g')

        rm -f "$nmout"
        echo >> "$outfile"
    done

    # 5. Summary
    echo -e "\e[95m... Successful logins: $success_count\e[0m"
    log_message "BasicScn: $success_count successful logins"

    # 6. Offer to compress results
    zip_file="${outfile%.txt}.zip"
    echo -e "\e[95m... Compress results to $zip_file? (Y/N) ...\e[0m"
    read -r choice
    if [[ "$choice" =~ ^(Y|y|Yes|yes)$ ]]; then
        zip -j "$zip_file" "$outfile" &>/dev/null
        echo -e "\e[95m... Results compressed to $zip_file ...\e[0m"
        log_message "Results compressed to $zip_file"
    fi

    log_message "BasicScn complete for network $NTADR"
}


# 1.3 + 1.3.2 Full scan 
# 4.4 Option to zip resaults
FullScn() {
    local hosts nmout host outfile
    local scanned_hosts scanned_ports=0 open_ports=0 vuln_count=0 success_count=0
    local zip_file choice

    outfile="$OUTPUT/${NTADR}_full.txt"

    # 0. Ensure output directory exists and start fresh file
    [[ ! -d "$OUTPUT" ]] && mkdir -p "$OUTPUT"
    : > "$outfile"
    echo "Full scan results for network $NTADR" >> "$outfile"

    # 1. Discover live hosts
    echo -e "\e[95m... Discovering hosts in network $NTADR ...\e[0m"
    log_message "Host discovery for full scan started on $NTADR"
    hosts=($(nmap -sn "$NTADR" -oG - | awk '/Up$/{print $2}'))
    scanned_hosts=${#hosts[@]}
    if (( scanned_hosts == 0 )); then
        echo -e "\e[91m... No live hosts found in $NTADR ...\e[0m"
        return
    fi
    # approximate total ports scanned (1000 TCP + 1000 UDP per host)
    scanned_ports=$(( scanned_hosts * 2000 ))
    echo -e "\e[95m... Hosts found: ${hosts[*]} ...\e[0m"
    log_message "Hosts discovered for full scan: ${hosts[*]}"
    echo >> "$outfile"

    # 2. Loop over each live host
    for host in "${hosts[@]}"; do
        echo -e "\e[95m... Starting full scan on $host ...\e[0m"
        log_message "Full scan started on $host"
        echo "Host: $host" >> "$outfile"

        nmout=$(mktemp)
        nmap -sTU -sV -A --script vuln "$host" \
             -oG "$nmout" \
             -oN "$OUTPUT/${host}_nmap_full.txt"

        # 3. Parse open ports and handle each
        while IFS= read -r entry; do
            IFS='/' read -r port _ proto _ service _ version <<<"$entry"
            (( open_ports++ ))
            echo "Found $service ($version) on port $port/$proto" | tee -a "$outfile"
            log_message "Discovered $service ($version) on $port/$proto of $host"

            # 4. Brute-force login on every TCP service
            if [[ "$proto" == "tcp" ]]; then
                echo -e "\e[95m... Trying login on $service/$port ...\e[0m"

                if [[ "$service" =~ ^(ssh|telnet)$ ]]; then
                    # Medusa for SSH/Telnet
                    medusa_out="${nmout}_${service}_medusa.txt"
                    medusa -h "$host" -U "$PWLDir" -P "$PWLDir" \
                           -M "$service" -n "$port" -f -O "$medusa_out" &>/dev/null

                    if grep -q SUCCESS "$medusa_out"; then
                        while read -r line; do
                            user=$(sed -n 's/.*login:\([^ ]*\).*/\1/p' <<<"$line")
                            pass=$(sed -n 's/.*password:\([^ ]*\).*/\1/p' <<<"$line")
                            cred="$user:$pass"
                            echo -e "\e[95m... SUCCESS: $service/$port → $cred\e[0m"
                            echo "[$service @ $port] SUCCESS: $cred" >> "$outfile"
                            (( success_count++ ))
                        done < <(grep SUCCESS "$medusa_out")
                        log_message "Valid credentials for $service on $port of $host"
                    else
                        echo -e "\e[91m... FAIL: no valid creds for $service/$port\e[0m"
                        echo "[$service @ $port] FAIL: no valid credentials" >> "$outfile"
                    fi
                    rm -f "$medusa_out"
                else
                    # Hydra for other TCP services
                    hydra_out="${nmout}_${service}_hydra.txt"
                    hydra -L "$PWLDir" -P "$PWLDir" -s "$port" \
                          "$service"://"$host" -f -o "$hydra_out" &>/dev/null

                    if [[ -s "$hydra_out" ]]; then
                        while read -r cred; do
                            echo -e "\e[95m... SUCCESS: $service/$port → $cred\e[0m"
                            echo "[$service @ $port] SUCCESS: $cred" >> "$outfile"
                            (( success_count++ ))
                        done < "$hydra_out"
                        log_message "Valid credentials for $service on $port of $host"
                    else
                        echo -e "\e[91m... FAIL: no valid creds for $service/$port\e[0m"
                        echo "[$service @ $port] FAIL: no valid credentials" >> "$outfile"
                    fi
                    rm -f "$hydra_out"
                fi
            fi

            # 5. Vulnerability lookup and count
            exploit_file="${nmout}_${service}_exploits.txt"
            searchsploit "$service $version" > "$exploit_file"
            if [[ -s "$exploit_file" ]]; then
                vuln_lines=$(wc -l < "$exploit_file")
                (( vuln_count += vuln_lines ))
                echo "Exploits for $service ($version):" >> "$outfile"
                sed 's/^/    /' "$exploit_file" >> "$outfile"
                log_message "Exploits found for $service on $host"
            else
                echo "No exploits found for $service ($version)" >> "$outfile"
            fi
            rm -f "$exploit_file"
        done < <(grep '/open/' "$nmout" \
                  | sed -e 's/.*Ports: //' -e 's/, /\n/g')

        rm -f "$nmout"
        echo >> "$outfile"
        echo -e "\e[95m... Full scan complete on $host ...\e[0m"
        log_message "Full scan complete on $host"
    done

    # 6. Summary
    echo -e "\e[95m... Scan Summary ...\e[0m"
    echo -e "\e[95mHosts scanned: $scanned_hosts\e[0m"
    echo -e "\e[95mPorts scanned (approx): $scanned_ports\e[0m"
    echo -e "\e[95mOpen ports found: $open_ports\e[0m"
    echo -e "\e[95mVulnerabilities found: $vuln_count\e[0m"
    echo -e "\e[95mSuccessful logins: $success_count\e[0m"
    log_message "Scan summary - hosts:$scanned_hosts, ports:$scanned_ports, open:$open_ports, vulns:$vuln_count, successes:$success_count"

    # 7. Offer to compress the results
    zip_file="${outfile%.txt}.zip"
    echo -e "\e[95m... Compress results to $zip_file? (Y/N) ...\e[0m"
    read -r choice
    if [[ "$choice" =~ ^(Y|y|Yes|yes)$ ]]; then
        zip -j "$zip_file" "$outfile" &>/dev/null
        echo -e "\e[95m... Results compressed to $zip_file ...\e[0m"
        log_message "Results compressed to $zip_file"
    fi

    log_message "Full network scan complete on $NTADR"
}


function bruteAtempt() {
    # This function uses:
    # - Global variable ip (the target server's IP)
    # - Keywords passed as arguments ($@)
    # - An existing username list in usernames.txt
    # - A base wordlist (rockyou.txt)
    #
    # It creates a temporary password file by appending the provided keywords
    # to the base wordlist, then uses hydra to try SSH logins.
    #
    # If a valid login is found, it detects the OS type and calls getInfoL (for Linux)
    # or getInfoW (for Windows). Otherwise, it notifies, logs the failure, and exits.

    # Check that the global variable ip is set
    if [[ -z "$ip" ]]; then
        echo "Error: Target IP is not set."
        return 1
    fi

    # Define the base wordlist location.
    local base_wordlist="/usr/share/wordlists/rockyou.txt"
    if [[ ! -f "$base_wordlist" ]]; then
        echo -e "\e[31mrockyou.txt not found in /usr/share/wordlists.\e[0m"
        echo -e "\e[34mWould you like to download rockyou.txt to the current directory? (yes/no):\e[0m"
        read download_choice
        if [[ "$download_choice" != "yes" ]]; then
            echo -e "\e[31mDownload aborted by user. Exiting bruteAtempt function.\e[0m"
            log_message "User declined to download rockyou.txt; bruteAtempt aborted on $ip"
            return 1
        fi

        # Download rockyou.txt using curl or wget to /usr/share/wordlists/
	if command -v curl >/dev/null 2>&1; then
   		 curl -L -o /usr/share/wordlists/rockyou.txt "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
	elif command -v wget >/dev/null 2>&1; then
    		wget -O /usr/share/wordlists/rockyou.txt "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
	else
    		echo -e "\e[31mNeither curl nor wget found. Cannot download rockyou.txt.\e[0m"
    		log_message "Download failed: neither curl nor wget found; bruteAtempt aborted on $ip"
    		return 1
	fi

       base_wordlist="/usr/share/wordlists/rockyou.txt"
       echo -e "\e[34mrockyou.txt downloaded to /usr/share/wordlists/rockyou.txt.\e[0m"
       log_message "rockyou.txt downloaded to /usr/share/wordlists/rockyou.txt; bruteAtempt continuing on $ip"
    fi

    # Define the temporary password file name.
    local temp_pwd_file="temp_wordlist_${ip}.txt"

    # Create the temporary wordlist by copying the base wordlist.
    cp "$base_wordlist" "$temp_pwd_file"

    # Append each provided keyword on its own line.
    for keyword in "$@"; do
        echo "$keyword" >> "$temp_pwd_file"
    done

    echo -e "\e[95m... Starting brute-force attempt on $ip using temporary wordlist $temp_pwd_file ...\e[0m"
    log_message "Starting brute-force attempt on $ip with keywords: $*"

    # Run Hydra with the username list (usernames.txt) and our temporary password list.
    local hydra_output_file="hydra_results_${ip}.txt"
    hydra -vV -L usernames.txt -P "$temp_pwd_file" -t 3 ssh://"$ip" -o "$hydra_output_file"
# > /dev/null 2>&1

    # Check if Hydra found any valid credentials by testing if the output file is non-empty.
    if [[ ! -s "$hydra_output_file" ]]; then
        echo -e "\e[31m Brute-force attack failed. No valid credentials found for $ip.\e[0m"
        log_message "Brute-force attack failed on $ip"
        rm -f "$temp_pwd_file" "$hydra_output_file"
        return 1
    fi

    # Parse Hydra's output for valid credentials.
    # Hydra output typically contains a line like:
    # [ssh] host: 192.168.126.128   login: admin   password: admin
    local creds_line
    creds_line=$(grep "login:" "$hydra_output_file")
    local found_user
    local found_pass
    found_user=$(echo "$creds_line" | awk '{for(i=1;i<=NF;i++){if($i=="login:") print $(i+1)}}')
    found_pass=$(echo "$creds_line" | awk '{for(i=1;i<=NF;i++){if($i=="password:") print $(i+1)}}')

    echo -e "\e[32m Successful login found: $found_user:$found_pass\e[0m"
    log_message "Successful brute-force login found: $found_user:$found_pass on $ip"

    # Determine OS type using the found credentials.
    local os_type
    os_type=$(sshpass -p "$found_pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$found_user@$ip" 'uname -s 2>/dev/null')

    if [[ -z "$os_type" ]]; then
        os_type="Windows"
    fi

    # Proceed with the appropriate function based on OS type.
    if [[ "$os_type" == "Linux" ]]; then
        echo -e "\e[95m Linux OS detected via brute-force credentials!\e[0m"
        getInfoL "$found_user" "$ip" "$found_pass"
    elif [[ "$os_type" == "Windows" ]]; then
        echo -e "\e[95m Windows OS detected via brute-force credentials!\e[0m"
        getInfoW "$found_user" "$ip" "$found_pass"
    else
        echo -e "\e[31m Unknown OS detected via brute-force credentials. Exiting.\e[0m"
        log_message "Brute-force login succeeded on $ip but OS detection failed."
        rm -f "$temp_pwd_file" "$hydra_output_file"
        return 1
    fi

    # Clean up temporary files.
    rm -f "$temp_pwd_file" "$hydra_output_file"
}

# 4.3 Allow the user to search inside the resaults
SearchDir() {
    local search results

    # 1. Check if OUTPUT was set
    if [[ "$OUTPUT" == "None" ]]; then
        echo -e "\e[91m... No output directory name was selected ...\e[0m"
        return
    fi

    # 2. Check that the directory exists
    if [[ ! -d "$OUTPUT" ]]; then
        echo -e "\e[91m... Selected output directory \"$OUTPUT\" does not exist ...\e[0m"
        return
    fi

    # 2b. Check if it contains any files
    if [[ -z "$(ls -A "$OUTPUT")" ]]; then
        echo -e "\e[91m... Selected output directory is empty ...\e[0m"
        return
    fi

    # 3. Ask for the search term
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

# 2.1.1 + 2.1.2 Choose passwrod list 
PWMenu() {
    local choice dir file_loc words modified_file

    while true; do
        # Menu header
        echo -e "\e[95m... Passwords/Wordlist Menu ...\e[0m"
        echo -e "\e[95m... Current Passwords/Words list: $PWLIST    ...\e[0m"
        echo -e "\e[95m... Passwords/Wordlist directory: $PWLDir    ...\e[0m"
        echo -e "\e[95m... type number to execute: ...\e[0m"

        # Options
        echo -e "1 - Create and change to basic Password list (1111, 1234, Kali, aA12345678, etc)"
        echo -e "2 - Select Password/Word list location"
        echo -e "3 - Add to current Password/Word list"
        echo -e "4 - Back to default - rockyou"
        echo -e "5 - Back to main menu"
        read -r choice

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
                echo -e "\e[95m... Basic password list created and selected ...\e[0m"
                ;;
            2)
                # Prompt for existing file or back
                while true; do
                    echo -e "\e[95mInsert new file location (or type 'back' to return):\e[0m"
                    read -r file_loc
                    if [[ "$file_loc" == "back" ]]; then
                        break
                    elif [[ -f "$file_loc" ]]; then
                        PWLDir="$file_loc"
                        PWLIST="Selected file"
                        log_message "Password list changed to $PWLDir"
                        echo -e "\e[95m... Password list set to $PWLDir ...\e[0m"
                        break
                    else
                        echo -e "\e[91mfile wasn't found\e[0m"
                    fi
                done
                ;;
            3)
                # Add words to current list
                echo -e "\e[95mType the words or numbers you would like to add to the current list, with space between them, and then Enter:\e[0m"
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
                    echo -e "\e[95m... Modified password list created and selected ...\e[0m"
                fi
                ;;
            4)
                # Reset to default rockyou
                PWLIST="Default - rockyou"
                PWLDir="/usr/share/wordlists/rockyou.txt"
                log_message "Password list reset to default rockyou"
                echo -e "\e[95m... Password list reset to default rockyou ...\e[0m"
                ;;
            5)
                # Back to main menu
                break
                ;;
            *)
                echo -e "\e[95m... wrong input. try again ...\e[0m"
                ;;
        esac
    done
}


#Menu function
function Menu() {
    while true; do
        echo -e "\e[95m... MENU ...\e[0m"
        echo -e "\e[95m... Network Address: $NTADR    ...\e[0m"
        echo -e "\e[95m... Output Directory Name: $OUTPUT    ...\e[0m"
        echo -e "\e[95m... Password list: $PWLIST    ...\e[0m"
        echo -e "\e[95m... type the number to execute: ...\e[0m"
        echo -e "1 - Install needed apps (will skip installation if not needed)"
        echo -e "2 - Check if I'm anonymous"
        echo -e "3 - Enter/Change Network Address"
        echo -e "4 - Change output directory name"
        echo -e "5 - Basic scan (TCP, UDP, services versions, weak passwords)"
        echo -e "6 - Full scan (NSE, weak passwords, vulnerability analysis)"
        echo -e "7 - Password list options"
        echo -e "8 - Search output"
        echo -e "9 - Exit"
        read -r num

        case "$num" in
            1) install_apps ;;
            2) isAnon ;;
            3) EnterAdr ;;
            4) OutputDirName ;;
            5)
                if [ "$NTADR" = "None" ]; then
                    echo -e "\e[91m... Network address wasn't set ...\e[0m"
                else
                    BasicScn
                fi
                ;;
            6)
                if [ "$NTADR" = "None" ]; then
                    echo -e "\e[91m... Network address wasn't set ...\e[0m"
                else
                    FullScn
                fi
                ;;
            7) PWMenu ;;
            8) SearchDir ;;
            9) break ;;
            *)
                echo -e "\e[91m... wrong number. try again ...\e[0m"
                ;;
        esac
    done
}

# Global variables 
NTADR="None"
OUTPUT="None"
PWLIST="Default - rockyou"
PWLDir="/usr/share/wordlists/rockyou.txt"
# Calling Menu Function
Menu

# 3.2 Log data collection
echo -e "\e[95m... Data collection log: ...\e[0m"
echo -e "\e[95m... Script ended on: $(date) ...\e[0m"

# Closing the log file
exec > /dev/tty 2>&1

### Penetration Testing Project ###
### Nissim Atar ###
### s17 ###
### JMagen773630 ###
