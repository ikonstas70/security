#!/bin/bash

# Log file path
log_file="cd /home/kbzl2l3oqogc/access-logs/it-solutionsusa.com-ssl_log"
output_file="attack.txt"

# Function to get the current timestamp
current_timestamp() {
    date +"%Y-%m-%d %H:%M:%S"
}

# Function to display text in red
red_text() {
    echo -e "\033[31m$1\033[0m"
}

# Function to display text in white
white_text() {
    echo -e "\033[37m$1\033[0m"
}

# Function to display POST access counts for an IP address
display_post_counts() {
    local ip_address="$1"
    
    # Display IP Address label in white and IP address in red
    white_text "      IP Address: $(red_text "$ip_address")"
    
    # Extract and display POST request access counts for the given IP address
    grep "POST" "$log_file" | awk -v ip="$ip_address" '$1 == ip {print $7}' | sort | uniq -c | sort -nr | sed 's/^/        /'

    echo
}

# Function to execute the extraction and display
execute_queries() {
    clear
    echo "Query by Ioannis Konstas"
    echo "Processing log file for POST requests"

    # Get the current timestamp
    local timestamp=$(current_timestamp)

    # Clear the output file before writing new data
    > "$output_file"

    # Write timestamp to output file
    echo "Timestamp: $timestamp" | tee -a "$output_file"
    echo -e "\nIP Address Counts for POST Requests" | tee -a "$output_file"
    echo "--------------------------------" | tee -a "$output_file"

    # Extract unique IP addresses with POST requests
    ip_addresses=$(grep "POST" "$log_file" | awk '{print $1}' | sort | uniq)

    for ip in $ip_addresses; do
        # Display IP Address label in white and IP address in red
        echo -e "      IP Address: $(red_text "$ip") (Last checked: $timestamp)" | tee -a "$output_file"
        
        # Display POST counts below the IP address and write to the output file
        grep "POST" "$log_file" | awk -v ip="$ip" '$1 == ip {print $7}' | sort | uniq -c | sort -nr | sed 's/^/        /' | tee -a "$output_file"

        echo >> "$output_file"  # Add a newline for separation
    done
}

# Main loop
while true; do
    clear
    execute_queries

    # Wait for 5 minutes (300 seconds) before reloading
    sleep 300
done

