#!/bin/bash

# Header with user name
header="Query by Ioannis Konstas"
divider="------------------------"

# Log file path
log_file="/home/kbzl2l3oqogc/access-logs/it-solutionsusa.com-ssl_log"

# Function to prompt for IP address and validate input
get_ip_address() {
    while true; do
        echo "Enter a 24-bit IP address (e.g., 31.13.115):"
        read ip_address
        if [[ $ip_address =~ ^([0-9]{1,3}\.){2}[0-9]{1,3}$ ]]; then
            break
        else
            echo "Invalid IP address format. Please try again."
        fi
    done
}

# Function to execute the grep and awk commands
execute_queries() {
    clear
    echo "Query by Ioannis Konstas"
    echo "Querying for IP address pattern: $ip_address"

    # Prepare IP address counts
    echo -e "\nIP Address Counts"
    echo "--------------------------------"
    grep "$ip_address" "$log_file" | awk '{print $1}' | sort | uniq -c | sort -nr | sed 's/^/      /'

    # Prepare website counts
    echo -e "\nWebsite Access Counts"
    echo "--------------------------------"
    grep "$ip_address" "$log_file" | awk '{print $7}' | sort | uniq -c | sort -nr | sed 's/^/      /'
}

# Initial clear
clear
echo "Query by Ioannis Konstas"

# Main loop
while true; do
    # Clear screen at the beginning of each loop iteration
    clear
    echo "Query by Ioannis Konstas"
    get_ip_address
    execute_queries

    echo -e "\nDo you want to run the script again? (y/n):"
    read answer
    if [[ "$answer" != "y" ]]; then
        break
    fi
done

echo "Exiting script."

