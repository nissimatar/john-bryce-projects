#! /bin/bash

### Windows Forensics Project ###
### Nissim Atar ###
### s17 ###
### JMagen773630 ###

#3.2 creating log file
log_file="/var/log/projectWindows.log"


#function for log message
log_message()
{
        echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$log_file"
}

# 1.1 exit if user isn't root
IsRoot() {
    if [ "$EUID" -eq 0 ]; then
        echo -e "\e[32myou have root access. can proceed\e[0m"
        log_message "user has root access"
    else
        echo -e "\e[32mroot access is required.\e[0m"
        log_message "user don't have root access"
        exit 1
    fi
}

# 1.2 asking the user for file name, and checking it's existance 
ask_for_file() {
    # Get the directory of the currently running script
    local script_dir
    script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

    while true; do
        # Prompt the user to enter a file name (in green)
        echo -e "\e[32mPlease enter a file name:\e[0m"
        read file_name
	publicFN="$file_name"

        # Check if the file exists in the same directory as the script
        if [ -e "$script_dir/$file_name" ]; then
            echo -e "\e[32mFound the file '$file_name'\e[0m"
            log_message "Found the file '$file_name'"
            Menu
        else
            echo -e "\e[31mCouldn't find a file with that name, let's try again\e[0m"
            log_message "File '$file_name' not found. Trying again."
            echo -e "\e[31mPlease make sure the file is in the current location.\e[0m"
        fi
    done
}

# 1.3 install apps function
install_apps() {
    # Install standard tools via apt-get
    declare -A apps
    apps=(
        ["Bulk Extractor"]="bulk-extractor"
        ["Binwalk"]="binwalk"
        ["Foremost"]="foremost"
        ["Strings"]="binutils"      # "strings" is provided by binutils
        ["Scalpel"]="scalpel"
    )
 
    for app in "${!apps[@]}"; do
        pkg="${apps[$app]}"
        if dpkg -s "$pkg" 2>/dev/null | grep -qi "Status: install ok installed"; then
            log_message "$app is installed."
            echo -e "\e[32m... $app is already installed ...\e[0m"
        else
            log_message "$app is not installed"
            echo -e "\e[32m... $app is not installed, installing... ...\e[0m"
            sudo apt-get install "$pkg" -y
            log_message "$app is installed."
        fi
    done

    # Ensure pipx bin directory is in PATH so that commands installed via pipx can be found
    export PATH="$HOME/.local/bin:$PATH"

    # Install Volatility
    if ! command -v volatility &> /dev/null; then
        echo -e "\e[32mVolatility is not installed. Attempting to download and install from GitHub...\e[0m"
        log_message "Volatility not installed. Downloading standalone version from GitHub."
        wget -O /tmp/volatility.zip "https://github.com/volatilityfoundation/volatility/releases/download/2.6.1/volatility_2.6_lin64_standalone.zip" > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo -e "\e[31mDownload of Volatility failed. Please check https://github.com/volatilityfoundation/volatility manually.\e[0m"
            log_message "Volatility download failed."
        else
            echo -e "\e[32mDownload succeeded. Unzipping Volatility package...\e[0m"
            log_message "Volatility package downloaded successfully. Unzipping..."
            unzip -o /tmp/volatility.zip -d /tmp > /dev/null 2>&1
            if [ $? -ne 0 ]; then
                echo -e "\e[31mUnzipping failed. Please check https://github.com/volatilityfoundation/volatility manually.\e[0m"
                log_message "Unzipping Volatility package failed."
            else
                echo -e "\e[32mUnzipping succeeded. Deleting downloaded zip file...\e[0m"
                log_message "Unzipping succeeded. Deleting downloaded zip file."
                rm -f /tmp/volatility.zip
                echo -e "\e[32mMoving Volatility binary to /usr/local/bin...\e[0m"
                log_message "Moving Volatility binary to /usr/local/bin."
                sudo mv /tmp/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone /usr/local/bin/volatility
                sudo chmod +x /usr/local/bin/volatility
                if command -v volatility &> /dev/null; then
                    echo -e "\e[32mVolatility installed successfully from standalone package.\e[0m"
                    log_message "Volatility installed successfully from standalone package."
                else
                    echo -e "\e[31mVolatility installation failed. Please check manually.\e[0m"
                    log_message "Volatility installation failed."
                fi
            fi
        fi
    else
        echo -e "\e[32mVolatility is already installed.\e[0m"
        log_message "Volatility is installed."
    fi


    # Install TrID manually if not already installed
    if ! command -v trid &> /dev/null; then
        echo -e "\e[32mTrID is not installed. Installing manually...\e[0m"
        log_message "TrID not installed. Installing manually."
        # Download TrID zip file (update the URL if needed)
        wget -O /tmp/trid.zip "http://www.mark0.net/download/trid_linux.zip"
        if [ $? -eq 0 ]; then
            unzip /tmp/trid.zip -d /tmp/trid
            sudo cp /tmp/trid/trid /usr/local/bin/
            sudo chmod +x /usr/local/bin/trid
            if command -v trid &> /dev/null; then
                echo -e "\e[32mTrID installed successfully.\e[0m"
                log_message "TrID installed successfully."
            else
                echo -e "\e[31mTrID installation failed. Please install manually.\e[0m"
                log_message "TrID installation failed."
            fi
        else
            echo -e "\e[31mFailed to download TrID. Please check the URL and install manually.\e[0m"
            log_message "TrID download failed."
        fi
    else
        echo -e "\e[32mTrID is already installed.\e[0m"
        log_message "TrID is installed."
    fi

    # Check for TrID definitions file, and download it if missing
    if [ ! -f "/usr/local/bin/triddefs.trd" ]; then
        echo -e "\e[31mTrID definitions file not found at /usr/local/bin/triddefs.trd.\e[0m"
        log_message "TrID definitions file not found at /usr/local/bin/triddefs.trd. Attempting download from https://mark0.net/download/triddefs.zip."
    
        echo -e "\e[32mDownloading TrID definitions file from https://mark0.net/download/triddefs.zip...\e[0m"
        wget -O /tmp/triddefs.zip "https://mark0.net/download/triddefs.zip"
        if [ $? -ne 0 ]; then
            echo -e "\e[31mDownload failed. Please check https://mark0.net manually.\e[0m"
            log_message "TrID definitions download failed."
        else
            echo -e "\e[32mDownload succeeded. Unzipping definitions file...\e[0m"
            log_message "TrID definitions downloaded successfully, proceeding to unzip."
            unzip -o /tmp/triddefs.zip -d /tmp
            if [ $? -ne 0 ]; then
                echo -e "\e[31mUnzipping failed. Please check https://mark0.net manually.\e[0m"
                log_message "TrID definitions unzipping failed."
            else
                echo -e "\e[32mMoving unzipped triddefs.trd to /usr/local/bin/...\e[0m"
                log_message "Unzipped file found. Attempting to move triddefs.trd to /usr/local/bin/."
                sudo mv /tmp/triddefs.trd /usr/local/bin/
                if [ $? -ne 0 ]; then
                    echo -e "\e[31mFailed to move TrID definitions to /usr/local/bin. Please check manually.\e[0m"
                    log_message "Failed to move triddefs.trd to /usr/local/bin."
                fi
            fi
            # Clean up downloaded zip file
            rm -f /tmp/triddefs.zip
            # Check again if the definitions file exists
            if [ -f "/usr/local/bin/triddefs.trd" ]; then
                echo -e "\e[32mTrID definitions file successfully installed at /usr/local/bin/triddefs.trd.\e[0m"
                log_message "TrID definitions file successfully installed."
            else
                echo -e "\e[31mTrID definitions file still not found. Please check https://mark0.net manually.\e[0m"
                log_message "TrID definitions file not found after download attempt. Please check https://mark0.net manually."
            fi
        fi
    fi

}



# 2.1 Check if file can be analyzed in Volatility
# 2.1 If the function finds the file to be a memory dump, it will call mDumpCarve, that runs Volatility on the file
# 1.4 If the function finds the file to be a disk img, it will call diskImgCarve, that will extract data from the file
check_file_type() {
    local file="$1"
    local description trid_result binwalk_result imageinfo_output profile

    # Set locale to avoid TrID locale issues
    export LC_ALL=C

    # Use the 'file' command for a basic description
    description=$(file "$file")
    echo -e "\e[32mFile description (file command): $description\e[0m"
    log_message "File description (file command): $description"

    # Determine file type based on file command heuristics
    if echo "$description" | grep -qiE "DOS/MBR|MBR boot sector|partition"; then
        echo -e "\e[32m         !The file appears to be a disk image!         \e[0m"
        log_message "File identified as disk image by file command."
        diskImgCarve "$file"
        return
    elif echo "$description" | grep -qiE "memory|core|dump"; then
        echo -e "\e[32m         !The file appears to be a memory dump!         \e[0m"
        log_message "File identified as memory dump by file command."
        mDumpCarve "$file" "$profile"
        return
    else
        echo -e "\e[32mFile type not conclusively identified by file command. Proceeding with header analysis...\e[0m"
        log_message "File type inconclusive by file command. Proceeding with header analysis."
    fi

    # Header Analysis for Disk Image and Memory Dump markers
    # Extract the first 1024 bytes of the file (for header analysis)
    local header
    header=$(dd if="$file" bs=1024 count=1 2>/dev/null | xxd -p -c 1024) > /dev/null 2>&1
    # Note: The warning "ignored null byte" from dd is expected since we're reading binary data.

    # --- Check for Disk Image Markers ---
    # MBR Signature: Last two bytes of first 512 bytes should be "55aa"
    local mbr_header mbr_sig
    mbr_header=$(dd if="$file" bs=512 count=1 2>/dev/null | xxd -p -c 512)
    mbr_sig=${mbr_header: -4}
    if [ "$mbr_sig" = "55aa" ]; then
        echo -e "\e[32m         !MBR signature detected; file appears to be a disk image!         \e[0m"
        log_message "Disk image identified by MBR signature in header."
        diskImgCarve "$file"
        return
    fi

    # GPT Header: Check second sector for "EFI PART" (hex: 45 46 49 20 50 41 52 54)
    local sector2
    sector2=$(dd if="$file" bs=512 skip=1 count=1 2>/dev/null | xxd -p -c 512)
    if echo "$sector2" | grep -qi "4546492050415254"; then
        echo -e "\e[32m         !GPT header detected; file appears to be a disk image!         \e[0m"
        log_message "Disk image identified by GPT signature in header."
        diskImgCarve "$file"
        return
    fi

    # Filesystem-specific markers in the boot sector (first 512 bytes).
    # Using grep -a to force text search on binary data.
    local boot_sector
    boot_sector=$(dd if="$file" bs=512 count=1 2>/dev/null)
    if echo "$boot_sector" | grep -a -qi "NTFS"; then
         echo -e "\e[32m         !NTFS marker detected in boot sector; file appears to be a disk image!         \e[0m"
         log_message "Disk image identified by NTFS marker in boot sector."
         diskImgCarve "$file"
         return
    elif echo "$boot_sector" | grep -a -qiE "FAT32|FAT16|FAT12"; then
         echo -e "\e[32m         !FAT marker detected in boot sector; file appears to be a disk image!         \e[0m"
         log_message "Disk image identified by FAT marker in boot sector."
         diskImgCarve "$file"
         return
    fi

    # --- Check for Memory Dump Markers ---
    # For example, search for ASCII "MEMORY" (hex: 4d454d4f5259) in the header.
    if echo "$header" | grep -qi "4d454d4f5259"; then
        echo -e "\e[32m         !Memory dump marker detected; file appears to be a memory dump!         \e[0m"
        log_message "Memory dump identified by header marker."
        mDumpCarve "$file" "$profile"
        return
    fi

    # Check File Name for Common Disk Image Markers
    local file_lower
    file_lower=$(echo "$file" | tr '[:upper:]' '[:lower:]')
    if echo "$file_lower" | grep -qiE "ntfs|fat32|fat16|fat12"; then
         echo -e "\e[32m         !File name contains a filesystem marker (NTFS/FAT); assuming disk image!         \e[0m"
         log_message "File name indicates disk image (NTFS/FAT markers found)."
         diskImgCarve "$file"
         return
    fi

    # Fallback: Ask the user for file type
    echo -e "\e[32m         !Unable to determine file type from automated checks.!         \e[0m"
    log_message "File type still unclear after header analysis. Prompting user for input."
    while true; do
        echo -e "\e[32mPlease enter the file type (1 for disk image, 2 for memory dump, 3 for unknown): \e[0m"
        read user_type
        case "$user_type" in
            1)
                log_message "User manually indicated disk image."
                diskImgCarve "$file"
                break
                ;;
            2)
                log_message "User manually indicated memory dump."
                mDumpCarve "$file" "$profile"
                break
                ;;
            3)
                log_message "User indicated unknown file type."
                echo -e "\e[32mFile type set to unknown. Manual verification required.\e[0m"
                break
                ;;
            *)
                echo -e "\e[31mInvalid input. Please enter 1, 2, or 3.\e[0m"
                ;;
        esac
    done
}

#1.4 Function -  Disk img data carving
#1.5 Data being saved in a directory
diskImgCarve() {
    local file="$1"
    local filename filename_noext data_dir

    # Get base file name and create a main data directory
    filename=$(basename "$file")
    filename_noext="${filename%.*}"
    data_dir="${filename}_data"
    mkdir -p "$data_dir"
    echo -e "\e[32mCreated data directory: $data_dir\e[0m"
    log_message "Created data directory: $data_dir"

    ### Run Bulk Extractor
    local bulk_dir="$data_dir/bulk_extractor"
    mkdir -p "$bulk_dir"
    echo -e "\e[32mRunning Bulk Extractor...\e[0m"
    log_message "Running Bulk Extractor on $file"
    bulk_extractor -q -o "$bulk_dir" "$file" > /dev/null 2>&1
    echo -e "\e[32m     Bulk Extractor completed. Output saved to $bulk_dir\e[0m"
    log_message "Bulk Extractor output saved to $bulk_dir"

    ### Run Binwalk
    local binwalk_dir="$data_dir/binwalk"
    mkdir -p "$binwalk_dir"
    echo -e "\e[32mRunning Binwalk...\e[0m"
    log_message "Running Binwalk on $file"
    binwalk -q -e -C "$binwalk_dir" "$file" > /dev/null 2>&1
    echo -e "\e[32m     Binwalk completed. Extracted files saved to $binwalk_dir\e[0m"
    log_message "Binwalk output saved to $binwalk_dir"

    ### Run Foremost
    local foremost_dir="$data_dir/foremost"
    mkdir -p "$foremost_dir"
    echo -e "\e[32mRunning Foremost...\e[0m"
    log_message "Running Foremost on $file"
    foremost -q -i "$file" -o "$foremost_dir" > /dev/null 2>&1
    echo -e "\e[32m     Foremost completed. Output saved to $foremost_dir\e[0m"
    log_message "Foremost output saved to $foremost_dir"

    ### Run Scalpel
    local scalpel_dir="$data_dir/scalpel"
    mkdir -p "$scalpel_dir"
    echo -e "\e[32mRunning Scalpel...\e[0m"
    log_message "Running Scalpel on $file"
    scalpel "$file" -o "$scalpel_dir" > /dev/null 2>&1
    echo -e "\e[32m     Scalpel completed. Output saved to $scalpel_dir\e[0m"
    log_message "Scalpel output saved to $scalpel_dir"

    ### Run TrID
    local trid_dir="$data_dir/trid"
    mkdir -p "$trid_dir"
    echo -e "\e[32mRunning TrID...\e[0m"
    log_message "Running TrID on $file"
    trid "$file" > "$trid_dir/trid_output.txt"
    echo -e "\e[32m     TrID completed. Output saved to $trid_dir/trid_output.txt\e[0m"
    log_message "TrID output saved to $trid_dir/trid_output.txt"

    ### Run strings on each tool's output
    for tool in bulk_extractor binwalk foremost scalpel; do
        local tool_dir="$data_dir/$tool"
        if [ -d "$tool_dir" ]; then
            echo -e "\e[32mRunning strings on output from $tool...\e[0m"
            log_message "Running strings on output from $tool"
            local strings_file="$data_dir/${tool}_strings.txt"
            find "$tool_dir" -type f -exec strings {} \; > "$strings_file"
            echo -e "\e[32m     Strings extraction for $tool completed. Output saved to $strings_file\e[0m"
            log_message "Strings output for $tool saved to $strings_file"
        fi
    done

    ### Search for network traffic files (.pcap, .pcapng)
    echo -e "\e[32mSearching for network traffic files...\e[0m"
    log_message "Searching for network traffic files in $data_dir"
    local pcap_files
    pcap_files=$(find "$data_dir" -type f \( -iname "*.pcap" -o -iname "*.pcapng" \))
    if [ -n "$pcap_files" ]; then
        local nw_folder="$data_dir/NWTraffic"
        mkdir -p "$nw_folder"
        for pcap in $pcap_files; do
            local file_size
            file_size=$(stat -c%s "$pcap")
            echo -e "\e[32m     Found network traffic file: $pcap (size: $file_size bytes)\e[0m"
            log_message "Found network traffic file: $pcap (size: $file_size bytes)"
            cp "$pcap" "$nw_folder"
        done
        echo -e "\e[32m     Network traffic files copied to $nw_folder\e[0m"
        log_message "Network traffic files copied to $nw_folder"
    else
        local no_nw_folder="$data_dir/NoNWTraffic"
        mkdir -p "$no_nw_folder"
        echo -e "\e[32m     No network traffic files found. Created empty folder: $no_nw_folder\e[0m"
        log_message "No network traffic files found. Created folder: $no_nw_folder"
    fi

    ### Run PhotoRec for additional file carving
    local photorec_dir="$data_dir/photorec"
    mkdir -p "$photorec_dir"
    echo -e "\e[32mRunning PhotoRec to carve additional files...\e[0m"
    log_message "Running PhotoRec on $file"
    # Note: This command assumes a non-interactive mode or pre-configured settings for PhotoRec.
    photorec /log /d "$photorec_dir" /cmd "$file" options > "$photorec_dir/photorec_output.txt" 2>&1
    if [ -s "$photorec_dir/photorec_output.txt" ]; then
        echo -e "\e[32m     PhotoRec completed. Output saved to $photorec_dir/photorec_output.txt\e[0m"
        log_message "PhotoRec output saved to $photorec_dir/photorec_output.txt"
    else
        echo -e "\e[31m     PhotoRec did not extract any files or failed.\e[0m"
        log_message "PhotoRec did not extract any files or failed."
    fi

    ### Run The Sleuth Kit (fls) for file system analysis
    local tsk_dir="$data_dir/tsk"
    mkdir -p "$tsk_dir"
    echo -e "\e[32mRunning The Sleuth Kit (fls) to list file system artifacts...\e[0m"
    log_message "Running fls (The Sleuth Kit) on $file"
    fls -r -m / "$file" > "$tsk_dir/fls_output.txt" 2>&1
    if [ -s "$tsk_dir/fls_output.txt" ]; then
        echo -e "\e[32m     fls output saved to $tsk_dir/fls_output.txt\e[0m"
        log_message "fls output saved to $tsk_dir/fls_output.txt"
    else
        echo -e "\e[31m     fls did not produce any output or failed.\e[0m"
        log_message "fls did not produce any output or failed."
    fi

    # Ask User if They Want to Display a Summary Report
    while true; do
        echo -e "\e[32mWould you like to display the summary report? (yes/no): \e[0m"
        read answer
        case "$answer" in
            y|Y|yes|Yes|YES)
                summery "$file"
                break
                ;;
            n|N|no|No|NO)
                break
                ;;
            *)
                echo -e "\e[31mInvalid input. Please answer yes or no.\e[0m"
                ;;
        esac
    done
}


# 2.1 Function - run volatility on a dump memory file
mDumpCarve() {
    local file="$1"
    local profile="$2"
    local filename filename_noext data_dir
    filename=$(basename "$file")
    filename_noext="${filename%.*}"
    data_dir="${filename}_data"
    mkdir -p "$data_dir"
    echo -e "\e[32mCreated data directory: $data_dir\e[0m"
    log_message "Created data directory: $data_dir"

    # Ensure pipx-installed binaries are in PATH
    export PATH="$HOME/.local/bin:$PATH"

    # 2.2 Find the memory profile and save into variable 
    local mem_info mem_profile_details
    echo -e "\e[32mDetermining memory profile using Volatility windows.info...\e[0m"
    log_message "Determining memory profile using Volatility windows.info on $file"
    mem_info=$(vol -q -f "$file" windows.info 2>&1)
    
    # Extract various fields from the output
    local os_build is_64bit nt_system_root nt_product_type nt_major nt_minor pe_os_major pe_os_minor
    os_build=$(echo "$mem_info" | grep -i "NTBuildLab" | head -n 1 | cut -d ":" -f2 | xargs)
    is_64bit=$(echo "$mem_info" | grep -i "Is64Bit" | head -n 1 | cut -d ":" -f2 | xargs)
    nt_system_root=$(echo "$mem_info" | grep -i "NtSystemRoot" | head -n 1 | cut -d ":" -f2 | xargs)
    nt_product_type=$(echo "$mem_info" | grep -i "NtProductType" | head -n 1 | cut -d ":" -f2 | xargs)
    nt_major=$(echo "$mem_info" | grep -i "NtMajorVersion" | head -n 1 | cut -d ":" -f2 | xargs)
    nt_minor=$(echo "$mem_info" | grep -i "NtMinorVersion" | head -n 1 | cut -d ":" -f2 | xargs)
    pe_os_major=$(echo "$mem_info" | grep -i "PE MajorOperatingSystemVersion" | head -n 1 | cut -d ":" -f2 | xargs)
    pe_os_minor=$(echo "$mem_info" | grep -i "PE MinorOperatingSystemVersion" | head -n 1 | cut -d ":" -f2 | xargs)
    
    # Combine the extracted fields into one summary string
    mem_profile_details="Build: ${os_build:-Unknown}, Architecture: ${is_64bit:-Unknown}, System Root: ${nt_system_root:-Unknown}, Product Type: ${nt_product_type:-Unknown}, OS Version: ${nt_major:-Unknown}.${nt_minor:-Unknown}, PE OS Version: ${pe_os_major:-Unknown}.${pe_os_minor:-Unknown}"
    echo -e "\e[32m     Memory profile determined: $mem_profile_details\e[0m"
    log_message "Memory profile determined: $mem_profile_details"
    export MEM_PROFILE_DETAILS="$mem_profile_details"

    # 2.3 Display the running processes
    local processes_file="$data_dir/${filename_noext}_PL.txt"
    echo -e "\e[32mExtracting running processes with Volatility pslist...\e[0m"
    log_message "Extracting running processes using Volatility pslist"
    vol -q -f "$file" pslist 2>&1 < /dev/null | tee "$processes_file"
    echo -e "\e[32m     Processes List extracted and saved to $processes_file\e[0m"
    log_message "Saved running processes to $processes_file"

    # 2.4 Display network connections 
    local nwconn_file="$data_dir/${filename_noext}_NWConnections.txt"
    echo -e "\e[32mExtracting network connections with Volatility netscan...\e[0m"
    log_message "Extracting network connections using Volatility netscan"
    vol -q -f "$file" netscan 2>&1 | tee "$nwconn_file"
    echo -e "\e[32m     Network connections extracted and saved to $nwconn_file\e[0m"
    log_message "Saved network connections to $nwconn_file"

    # 2.5 Attempt to Extract Registry Information
    local reginfo_file="$data_dir/${filename_noext}_RegInfo.txt"
    echo -e "\e[32mAttempting registry extraction with Volatility hivelist...\e[0m"
    log_message "Attempting registry extraction using Volatility hivelist"
    local hive_output
    hive_output=$(vol -q -f "$file" hivelist 2>&1)
    if echo "$hive_output" | grep -qi "No plugins matched"; then
        echo -e "\e[31m     Registry information could not be extracted.\e[0m"
        log_message "Registry extraction failed: $hive_output"
    else
        echo "$hive_output" > "$reginfo_file"
        echo -e "\e[32m     Registry information extracted and saved to $reginfo_file\e[0m"
        log_message "Registry information extracted and saved to $reginfo_file"
    fi

    # Dump Files with Volatility dumpfiles
    local dumpfiles_dir="$data_dir/dumpfiles"
    mkdir -p "$dumpfiles_dir"
    local dumpfiles_log="$data_dir/${filename_noext}_dumpfiles_log.txt"
    echo -e "\e[32mDumping files using Volatility dumpfiles...\e[0m"
    log_message "Dumping files using Volatility dumpfiles"
    vol -q -f "$file" dumpfiles -D "$dumpfiles_dir" > "$dumpfiles_log" 2>&1
    if [ -z "$(ls -A "$dumpfiles_dir")" ]; then
        echo -e "\e[31m     No files were found or extracted by dumpfiles.\e[0m"
        log_message "No files were extracted by dumpfiles. Removing empty directory."
        rmdir "$dumpfiles_dir"
    else
        echo -e "\e[32m     Dumpfiles completed. Dumped files are in $dumpfiles_dir; log saved to $dumpfiles_log\e[0m"
        log_message "Dumpfiles output saved to $dumpfiles_dir; log saved to $dumpfiles_log"
    fi

    # Extract DLL List with Volatility windows.dlllist
    local dlllist_file="$data_dir/${filename_noext}_dlllist.txt"
    echo -e "\e[32mExtracting DLL list with Volatility windows.dlllist...\e[0m"
    log_message "Extracting DLL list using Volatility windows.dlllist"
    vol -q -f "$file" windows.dlllist > "$dlllist_file" 2>&1
    echo -e "\e[32m     DLL list extracted and saved to $dlllist_file\e[0m"
    log_message "DLL list extracted and saved to $dlllist_file"

    # Run Strings on the Memory Dump
    local strings_file="$data_dir/${filename_noext}_strings.txt"
    echo -e "\e[32mRunning strings on the memory dump...\e[0m"
    log_message "Running strings on the memory dump"
    strings "$file" > "$strings_file" 2>&1
    echo -e "\e[32m     Strings output saved to $strings_file\e[0m"
    log_message "Strings output saved to $strings_file"

    # Ask User if They Want to Display a Summary Report
     while true; do
        echo -e "\e[32m     Would you like to display the summary report? (yes/no): \e[0m"
        read answer
        case "$answer" in
            y|Y|yes|Yes|YES)
                summery "$file"
                break
                ;;
            n|N|no|No|NO)
                break
                ;;
            *)
                echo -e "\e[31m     Invalid input. Please answer yes or no.\e[0m"
                ;;
        esac
    done
}

# 3 Resaults
summery() {
    local file="$1"
    local filename
    local filename_noext
    local data_dir

    # Get the base file name and compute the data directory (assumes previous functions used this naming convention)
    filename=$(basename "$file")
    filename_noext="${filename%.*}"
    data_dir="${filename}_data"

    # Create Summery folder if it doesn't exist
    local summery_dir="Summery"
    mkdir -p "$summery_dir"

    # Create a report file with a timestamp
    local report_file="$summery_dir/$publicFN-report_$(date +%Y%m%d).txt"

    # Record analysis time
    local analysis_time
    analysis_time=$(date '+%Y-%m-%d %H:%M:%S')

    # Count the number of files extracted (all files under the data directory)
    local extracted_count
    extracted_count=$(find "$data_dir" -type f | wc -l)

    # Determine if network traffic files were found:
    # If folder NWTraffic exists, then yes; if NoNWTraffic exists, then no.
    local nw_traffic_status="Not determined"
    if [ -d "$data_dir/NWTraffic" ] || [ -n "$(find "$data_dir" -type f -name '*NWConnections*')" ]; then
        nw_traffic_status="Yes"
    elif [ -d "$data_dir/NoNWTraffic" ]; then
        nw_traffic_status="No"
    fi

    # Check if registry info was extracted by looking for the expected file
    local reg_info_file="$data_dir/${filename_noext}_RegInfo.txt"
    local reg_info_status="No"
    if [ -s "$reg_info_file" ]; then
        reg_info_status="Yes"
    fi

    # If Volatility was run (for memory dumps), attempt to extract the profile from the volatility output.
    local profile_name="Not applicable"
    local volatility_dir="$data_dir/volatility"
    if [ -d "$volatility_dir" ] && [ -f "$volatility_dir/imageinfo.txt" ]; then
        profile_name=$(grep -i "Suggested Profile" "$volatility_dir/imageinfo.txt" | head -n1 | cut -d ":" -f2 | awk -F, '{print $1}' | xargs)
        [ -z "$profile_name" ] && profile_name="Not determined"
    fi

# 3.2 Generate the report
    {
        echo "Analysis Report"
        echo "========================"
        echo "Analysis Time: $analysis_time"
        echo "Input File: $file"
        echo "Data Directory: $data_dir"
        echo "Number of Extracted Files: $extracted_count"
        echo "Memory Profile: $MEM_PROFILE_DETAILS"
        echo "Network Traffic Files Found: $nw_traffic_status"
        echo "Registry Info Extracted: $reg_info_status"
        echo ""
        echo "Tools Used:"
        echo " - Bulk Extractor"
        echo " - Binwalk"
        echo " - Foremost"
        echo " - Scalpel"
        echo " - TrID"
        echo " - Volatility"
        echo " - Strings"
        echo " - PhotoRec"
        echo " - The Sleuth Kit"
    } > "$report_file"

# 3.1 Display the report
    echo -e "\e[32mAnalysis Report:\e[0m"
    cat "$report_file"
    log_message "Generated analysis report at $report_file"

# 3.3 Zip all extracted data and the report file.
    # The resulting zip file will be saved in the Summery folder.
    local zip_file="$summery_dir/${filename}_archive.zip"
    echo -e "\e[32mCreating zip archive: $zip_file\e[0m"
    log_message "Creating zip archive: $zip_file"
    zip -r "$zip_file" "$data_dir" "$report_file"
    echo -e "\e[32mZip archive created: $zip_file\e[0m"
    log_message "Zip archive created: $zip_file"
}

#Menu function
function Menu()
{
while true; do
	echo -e "\e[32m... Current file: $publicFN ...\e[0m"
	echo -e "\e[32m... MENU ...\e[0m"
	echo -e "\e[32m... Type the number to execute: ...\e[0m"
	echo -e "1 - Install needed apps (will skip installation if not needed)"
	echo -e "2 - Extract data from file"
	echo -e "3 - Choose another file" 
	echo -e "4 - Exit"
	read num
	
	if [ "$num" == "4" ]; then 
		exit
	elif [ "$num" == "1" ]; then
		install_apps
	elif [ "$num" == "2" ]; then
		check_file_type $publicFN
	elif [ "$num" == "3" ]; then
		ask_for_file
	else
		echo -e "\e[32m... wrong number. try again ...\e[0m"
	fi
done
}

#calling Menu Function
IsRoot
ask_for_file
#Menu

# 3.2 Log data collection
echo -e "\e[32m... Data collection log: ...\e[0m"
echo -e "\e[32m... Script ended on: $(date) ...\e[0m"

# Closing the log file
exec > /dev/tty 2>&1

### Windows Forensics Project ###
### Nissim Atar ###
### s17 ###
### JMagen773630 ###
