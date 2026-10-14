#!/bin/bash 

show_help() {
cat << EOF
Deploy the pfsense_zbx.php script and configure the parameters to a pfSense host. 
Usage: ${0##*/} --k PRIVATE_KEY -f firewalls.csv
Options:
    -h|--help: Print this help and exit
    -f|--csvfile: File with CSV values for connection
    -k|--keyfile: Path to a file containing the private key in PEM format (required)
    -v|--verbose: debug info.
EOF
}

FILE=""
KEY=""
VERBOSE=0

# Command line interface
TEMP=`getopt -o hvf:k: --long help,verbose,csvfile:,keyfile:, \
             -n '${0##*/}' -- "$@"`
if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi
eval set -- "$TEMP"
while true; do
  case "$1" in
    -h | --help )
        show_help >&2
        exit 1
        shift
        ;;
    -f | --csvfile ) FILE="$2"; shift 2 ;;
    -k | --keyfile ) KEY="$2"; shift 2 ;;
    -v | --verbose) VERBOSE=1; shift 1 ;;
    -- ) shift; break ;;
    * ) break ;;
  esac
done
echoerr() { printf "\033[0;31m%s\n\033[0m" "$*" >&2; }
SCRIPT_DIR=$(dirname "$0")
while IFS=',' read -r PFNAME HOSTNAME PORT VER
do
    echo "Deploying ${PFNAME} @ ${HOSTNAME}..."; 
    if (( $VERBOSE == 1 )); then  
        $SCRIPT_DIR/deploy.sh -v -k $KEY -p $PORT -u admin -s $HOSTNAME -z $VER
    else 
        $SCRIPT_DIR/deploy.sh -k $KEY -p $PORT -u admin -s $HOSTNAME -z $VER
    fi
    if [ $? -ne 0 ]; then
        echoerr "Error updating script and settings for ${PFNAME} @ ${HOSTNAME}"
        echo "Continuing..."
    fi
done <<< "$(tail +2 "$FILE")" 
echo 0;