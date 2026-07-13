#!/usr/bin/env bash

# Valid IPv4 octet: 0-255, allowing 1-3 digits (no leading-zero requirement
# issues since we're matching value, not enforcing canonical formatting)
_octet='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'

#-----------------------------------------------------------------------
# IPv6 helpers
#-----------------------------------------------------------------------

# Syntax check only - does NOT check address range.
_is_valid_ipv6_syntax() {
    local addr="$1"

    # Reject 3+ consecutive colons outright (catches cases the "::" count
    # check below can miss due to overlapping matches, e.g. "fe80:::1")
    [[ "$addr" == *":::"* ]] && return 1

    # Reject more than one "::"
    local dc_count
    dc_count=$(grep -o "::" <<< "$addr" | wc -l)
    (( dc_count > 1 )) && return 1

    if [[ "$addr" == *"::"* ]]; then
        local left="${addr%%::*}"
        local right="${addr##*::}"
        local left_n=0 right_n=0
        [[ -n "$left" ]] && left_n=$(awk -F: '{print NF}' <<< "$left")
        [[ -n "$right" ]] && right_n=$(awk -F: '{print NF}' <<< "$right")
        local total=$((left_n + right_n))
        (( total > 7 )) && return 1
    else
        local n
        n=$(awk -F: '{print NF}' <<< "$addr")
        (( n != 8 )) && return 1
    fi

    local part
    local addr_nocolons="${addr//::/:}"
    IFS=':' read -ra parts <<< "$addr_nocolons"
    for part in "${parts[@]}"; do
        [[ -z "$part" ]] && continue
        [[ "$part" =~ ^[0-9a-fA-F]{1,4}$ ]] || return 1
    done

    return 0
}

_ipv6_first_hextet_decimal() {
    local addr="$1"
    local first="${addr%%:*}"
    [[ -z "$first" ]] && first="0"
    echo $((16#$first))
}

# Syntax + accepted-range check: link-local (fe80::/10), unique local
# (fc00::/7), or global unicast (2000::/3).
_is_valid_ipv6_range() {
    local addr="$1"
    _is_valid_ipv6_syntax "$addr" || return 1
    local dec
    dec=$(_ipv6_first_hextet_decimal "$addr")
    (( dec >= 0xfe80 && dec <= 0xfebf )) && return 0  # link-local
    (( dec >= 0xfc00 && dec <= 0xfdff )) && return 0  # unique local
    (( dec >= 0x2000 && dec <= 0x3fff )) && return 0  # global unicast
    return 1
}

#-----------------------------------------------------------------------
# Argument parsing
#-----------------------------------------------------------------------

_ip_is_v6=0

if options="$(getopt -o "" -l ip:,port: -- "$@")"; then
    eval set -- "$options"
    while true; do
        case "${1,,}" in
            --ip)
                # Try IPv4 (private/link-local ranges) first, then IPv6.
                if [[ $2 =~ ^192\.168\.${_octet}\.${_octet}$ ]]; then
                    _val_ip="$2"
                elif [[ $2 =~ ^10\.${_octet}\.${_octet}\.${_octet}$ ]]; then
                    _val_ip="$2"
                elif [[ $2 =~ ^172\.(1[6-9]|2[0-9]|3[01])\.${_octet}\.${_octet}$ ]]; then
                    _val_ip="$2"
                elif [[ $2 =~ ^169\.254\.${_octet}\.${_octet}$ ]]; then
                    _val_ip="$2"
                elif _is_valid_ipv6_range "$2"; then
                    _val_ip="$2"
                    _ip_is_v6=1
                else
                    exit 3  # Invalid IP
                fi
                shift
                ;;
            --port)
                # Validate port value - numeric, 1-65535
                if [[ $2 =~ ^[0-9]{1,5}$ ]] && (( 10#$2 >= 1 && 10#$2 <= 65535 )); then
                    _val_port="$2"
                else
                    exit 4  # Invalid port
                fi
                shift
                ;;
            --)
                shift
                break
                ;;
            *)
                exit 2  # Invalid arguments
                ;;
        esac
        shift
    done
else
    exit 2  # Invalid or missing options
fi

if [[ -z "${_val_ip:-}" || -z "${_val_port:-}" ]]; then
    exit 2  # Missing --ip or --port
fi

#-----------------------------------------------------------------------
# Reachability check
#-----------------------------------------------------------------------

if [[ "$_ip_is_v6" == "1" ]]; then
    _val_host="[${_val_ip}]"  # IPv6 literals must be bracketed in a URL
else
    _val_host="${_val_ip}"
fi

_val_url="http://${_val_host}:${_val_port}/webapi/query.cgi?api=SYNO.API.Info&method=query&version=1&query=SYNO.API.Auth"
_val_resp=$(wget -q -T 4 -t 1 -O - "$_val_url" 2>/dev/null)
# A response came back, but it needs to actually be DSM's API discovery
# response - not just any web service that happened to be listening on
# the IP and port the user typed.
if [[ "$_val_resp" == *'"success":true'* && "$_val_resp" == *'SYNO.API.Auth'* ]]; then
    exit 0
else
    exit 1
fi

