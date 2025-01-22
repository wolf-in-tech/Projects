#!/bin/bash
#
#

NETWORK=$1
IP_LIST=$(nmap -sn ${NETWORK} | grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}")
OUTPUT_FILE="${HOME}/output.txt"
TABLE=()

mktb() {
	local ip=$1
	local port=$2
	TABLE+=("${ip}\t${port}")
}

parse() {
	local line=$1
	local ip=$(echo "${line}" | awk -F ' -> ' '{print $1}')
	local ports=$(echo "${1}" | awk -F ' -> ' '{print $2}' | sed -E 's/\[|\]//g; s/,/ /g')
	local no_of_ports=$(echo "${ports}" | awk -F ' ' '{print NF}')

	if [[ ${no_of_ports} -gt 1 ]]; then  
		for port in ${ports}; do
			mktb "${ip}" "${port}"
		done
	else	
		mktb "${ip}" "${ports}"
	fi
}

snatch() {
	local ip=$1
	local port=$2
	nmap -sV ${ip} -p ${port} | grep -A 1 -E "PORT\s+STATE\s+SERVICE\s+VERSION" | tail -n 1
}
 
#
# HOST DISCOVERY
# This performs a ping sweep (nmap -sn) of a network and generates a list of IPv4s
# Check if IP_LIST returns empty. If empty, print diagnostic and exit script.
#

if [[ -z ${IP_LIST} ]]; then
	echo "No hosts found on network: ${NETWORK}"
	exit 1
fi

#
# PORT SCANNING
# This performs a port scan of hosts discovered and stored in IP_LIST in a regex friendly format.
# Check if PORT_LIST returns empty. If empty, print diagnostic and exit script.
#

PORT_LIST=$(docker run --network=host -it --rm --name rustscan rustscan/rustscan:2.1.1  -g -a ${IP_LIST})

if [[ -z ${PORT_LIST} ]]; then
	echo "No ports found on network: ${NETWORK}"
	echo "These hosts were found: ${IP_LIST}"
	exit 1
fi

#
# INFORMATION PROCESSING
# Preparing the info from PORT_LIST for banner grabbing by parsing it into the TABLE array.
#

while read -r line; do
	parse "${line}"
done <<< ${PORT_LIST}

#
# BANNER GRABBING
# Pull SERVICE and VERSION info from IP and PORT and output to a file in the root.
#

echo -e "PORT\tSTATE\tSERVICE\tVERSION" > $OUTPUT_FILE
for entry in ${TABLE[@]}; do
	IP_PORT=$(echo -e ${entry} | sed 's/\t/ /g')
	snatch $IP_PORT | sed 's/[[:space:]]+/\t/g'  >> $OUTPUT_FILE
done

cat $OUTPUT_FILE
