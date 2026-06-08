#!/bin/bash

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
MAGENTA='\033[0;35m'
WHITE='\033[0;37m'
NC='\033[0m' # No Color

# Following the log file
tail -f -n 1000 /home/qiyt67wummuz/access-logs/pitt.agency-ssl_log | awk -v red="$RED" -v green="$GREEN" -v blue="$BLUE" -v yellow="$YELLOW" -v magenta="$MAGENTA" -v white="$WHITE" -v nc="$NC" '
BEGIN {
    prev_method = "";
    ulcorner = "┌";
    urcorner = "┐";
    llcorner = "└";
    lrcorner = "┘";
    hline = "─";
    vline = "│";
}

{
    split($4, array, "[");
    datestamp = array[2];
    website = $11;
    method = $6;
    ip = $1;
    gsub("\"", "", method);
    gsub("\"", "", http_version); # Ensure http_version is defined and used correctly if needed

    # Exclude specified IP addresses
    if (ip == "73.138.243.185" || ip == "172.226.190.238") {
        next;
    }

    # Extract OS and device information from user-agent (simplified)
    user_agent = $0;
    os = "Unknown OS";
    device = "Unknown Device";

    if (user_agent ~ /Windows/) { os = "Windows"; }
    else if (user_agent ~ /Macintosh/) { os = "MacOS"; }
    else if (user_agent ~ /Linux/) { os = "Linux"; }
    else if (user_agent ~ /Android/) { os = "Android"; }
    else if (user_agent ~ /iOS/) { os = "iOS"; }

    if (user_agent ~ /iPhone/) { device = "iPhone"; }
    else if (user_agent ~ /iPad/) { device = "iPad"; }
    else if (user_agent ~ /Android/) { device = "Android Device"; }
    else if (user_agent ~ /Macintosh/ || user_agent ~ /Mac_PowerPC/) { device = "Mac"; }

    # Determine method color
    if (method == "POST") {
        method_color = red;
    } else if (method == "GET") {
        method_color = green;
    }

    # Calculate frame width based on content length (including website)
    content_length = length(datestamp) + length(ip) + length(method) + length(os) + length(device) + length(website) + 7; # For spaces and separators
    frame_width = content_length + 4; # Adjust padding as needed

    # Print the frame and content
    printf "\n%s", ulcorner;
    for (i = 0; i < frame_width; i++) printf "%s", hline;
    printf "%s\n", urcorner;

    printf "%s %s %s%s%s %s%s%s %s%s%s %s%s%s %s\n",
           vline, datestamp,
           white, ip, nc,
           method_color, method, nc,
           yellow, os, nc,
           magenta, device, nc,
           website;

    printf "%s", llcorner;
    for (i = 0; i < frame_width; i++) printf "%s", hline;
    printf "%s\n", lrcorner;
}
'
