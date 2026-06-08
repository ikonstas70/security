#!/bin/bash

# Clear screen function
clear_screen() {
  printf "\033c"
}

# Print header function
print_header() {
  clear_screen
  center_text "Ioannis Konstas - WHOIS IP Information Script"
  center_text "Querying RIPE NCC Database"
  center_text ""
}

# Center text function
center_text() {
  local text="$1"
  local term_width=$(tput cols)
  local text_width=${#text}
  local padding=$(( (term_width - text_width) / 2 ))
  printf "%*s%s%*s\n" $padding "" "$text" $padding ""
}

# Draw box function
draw_box() {
  local content="$1"
  local max_length=0

  # Find the longest line in the content
  while IFS= read -r line; do
    length=${#line}
    if (( length > max_length )); then
      max_length=$length
    fi
  done <<< "$content"

  local box_width=$((max_length + 6))  # Add padding for the box

  # Draw the box
  center_text "╔$(printf '═%.0s' $(seq 1 $((box_width - 2))))╗"
  while IFS= read -r line; do
    center_text "║ $(printf "%-*s" $((box_width - 4)) "$line") ║"
  done <<< "$content"
  center_text "╚$(printf '═%.0s' $(seq 1 $((box_width - 2))))╝"
  center_text ""
}

# Run WHOIS function
run_whois() {
  local ip_address="$1"
  local whois_output=$(whois -h whois.ripe.net "$ip_address" | awk '
    /^inetnum:/ {
      gsub(/^[ \t]+|[ \t]+$/, "");
      inetnum=$2 "-" $4
    }
    /^address:/ {
      gsub(/^[ \t]+|[ \t]+$/, "");
      address=$0
    }
    /^netname:/ {
      gsub(/^[ \t]+|[ \t]+$/, "");
      netname=$2
    }
    /^descr:/ {
      gsub(/^[ \t]+|[ \t]+$/, "");
      descr=$0
    }
    /^country:/ {
      gsub(/^[ \t]+|[ \t]+$/, "");
      country=$2
    }
    END {
      output = "inetnum: " inetnum "\n\naddress: " address "\n\nnetname: " netname "\n\ndescr: " descr "\n\ncountry: " country
      printf "%s\n", output
    }')

  print_header  # Print the full header before the WHOIS output
  center_text "Information for $ip_address:"
  center_text ""

  # Draw the box around WHOIS output dynamically
  draw_box "$whois_output"

  # Ask the user for the next action
  read -p "Press Enter for another query, 'e' to exit: " next_action

  # Exit if the user wants to
  if [[ "$next_action" == "e" ]]; then
    print_header
    echo "Exiting the script."
    exit 0
  fi
}

# Prompt for IP address function
prompt_for_ip() {
  print_header  # Print the full header before prompting

  # Content to put inside the box
  local box_content=$(cat <<-EOF
Please enter an IP address in the format: xxx.xxx.xxx.xxx
Options: 'e' to exit, 'example' for a sample IP address
EOF
  ) # Removed the help option

  # Draw the box dynamically
  draw_box "$box_content"

  # Calculate the position for the prompt
  local prompt_text="Enter the IP address: "
  local prompt_length=${#prompt_text}
  local term_width=$(tput cols)
  local prompt_padding=$(( (term_width - prompt_length) / 2 ))

  # Print the prompt
  tput cup $((10)) $prompt_padding  # Adjusted position below the box
  printf "%s" "$prompt_text"

  # Read user input
  read -r ip_address
}

# Log file path
log_file="/home/qiyt67wummuz/access-logs/pitt.agency-ssl_log"

# Function to execute the grep and awk commands for logs
execute_queries() {
  clear_screen
  print_header
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
clear_screen
print_header

# Initial prompt for IP address
echo "Welcome to the WHOIS IP Information Script"
prompt_for_ip

# Main loop
while true; do
  case "$ip_address" in
    example)
      ip_address="8.8.8.8"
      run_whois "$ip_address"
      ;;
    e) # Exit option
      print_header
      echo "Exiting the script."
      exit 0
      ;;
    *)
      if [[ "$ip_address" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        execute_queries
        run_whois "$ip_address"
      else
        print_header
        echo "Invalid IP address format. Please enter a valid IP address."
      fi
      ;;
  esac 

  # If the user didn't exit in `run_whois`, prompt for another IP
  if [[ "$next_action" != "e" ]]; then 
    prompt_for_ip
  else
    break  # Exit the loop
  fi
done

