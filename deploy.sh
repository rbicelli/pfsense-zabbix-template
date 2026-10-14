#!/bin/bash

show_help() {
cat << EOF
Deploy the pfsense_zbx.php script and configure the parameters to a pfSense host. 
Usage: ${0##*/} --k PRIVATE_KEY -s hostname [-p port] [-u username] [-v]
Options:
    -h|--help: Print this help and exit
    -s|--hostname: Hostname or IP of the pfsense box. (required)
    -k|--keyfile: Path to a file containing the private key in PEM format (required)
    -p|--port: Port to use for SSH connection (default: 22)
    -u|--username: Username to use for login (default: admin)
    -z|--zabbixversion: Version of the pfsense zabbix client (default: 7)
    -v|--verbose: Print debug information
EOF
}

HOST=""
KEY=""
PORT=22
USER=admin
VERBOSE=0
VER=7

# Command line interface
TEMP=`getopt -o hvk:p:s:u:z: --long help,verbose,keyfile:,port:,hostname:,username:,zabbixversion:, \
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
    -v | --verbose) VERBOSE=1; shift 1 ;;
    -z | --zabbixversion) VER="$2"; shift 2 ;;
    -k | --keyfile ) KEY="$2"; shift 2 ;;
    -p | --port ) PORT="$2"; shift 2 ;;
    -s | --hostname ) HOST="$2"; shift 2 ;;
    -u | --username ) USER="$2"; shift 2 ;;
    -- ) shift; break ;;
    * ) break ;;
  esac
done

echoerr() { printf "\033[0;31m%s\n\033[0m" "$*" >&2; }
SCRIPT_DIR=$(dirname "$0")

if (( $VERBOSE == 1 )); then echo "create script dir..."; fi
ssh -n -T -i $KEY -p $PORT $USER@$HOST 'mkdir -p ~/scripts'
if [ $? -ne 0 ]; then
    # Can't connect 
    echoerr "Can't connect to $HOST"
    echo 1
    exit
fi 
if (( $VERBOSE == 1 )); then echo "copying script..."; fi
scp -i $KEY -P $PORT $SCRIPT_DIR/pfsense_zbx.php $USER@$HOST:~/scripts/pfsense_zbx.php

if [ $? -ne 0 ]; then
    # Can't connect 
    echoerr "Can't transfer file to $HOST"
    echo 1
    exit
fi 
if (( $VERBOSE == 1 )); then 
    echo  "configuring user parameter settings...";
fi          
CFG="/usr/local/etc/zabbix$VER/zabbix_agentd.conf.d/user_params.conf"
scp -i $KEY -P $PORT user_params.cfg $USER@$HOST:$CFG 
if [ $? -ne 0 ]; then
    # Can't connect 
    echoerr "Can't transfer file to $HOST"
    echo 1
    exit
fi 
# Restart zabbix service.
ssh -n -T -i $KEY -p $PORT $USER@$HOST '/usr/local/sbin/pfSsh.php playback svc restart zabbix_agentd'
if [ $? -ne 0 ]; then
    # Can't connect 
    echoerr "Failed or timed out restarting zabbix service on $HOST. Do so manually."
    echo 1
    exit
fi 
echo 0;