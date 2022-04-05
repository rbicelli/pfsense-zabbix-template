# pfSense Zabbix Template

This is a pfSense active template for Zabbix, based on Standard Agent and a php script using pfSense functions library for monitoring specific data.


Tested with pfSense 2.5.x, Zabbix 4.0, Zabbix 5.0

## What it does

**Template pfSense Active**
 
 - Network interface Discovery and Monitoring with User Assigned Names
 - Gateway Discovery and Monitoring (Gateway Status/RTT) 
 - OpenVPN Server Discovery and Monitoring (Server Status/Tunnel Status)
 - OpenVPN Clients Discovery and Monitoring (Client Status/Tunnel Status)
 - CARP Monitoring (Global CARP State)
 - Basic Service Discovery and Monitoring (Service Status)
 - pfSense Version/Update Available
 - Packages Update Available
 - Certificats Monitoring
 
**Template pfSense Active: OpenVPN Server User Auth**

 - Discovery of OpenVPN Clients connected to OpenVPN Servers in user auth mode
 - Monitoring of Client Parameters (Bytes sent/received, Connection Time...) 

**Template pfSense Active: IPsec**

 - Discovery of IPsec Site-to-Site tunnels
 - Monitoring tunnel status (Phase 1 and Phase 2)
 
**Template pfSense Active: Speedtest**

 - Discovery of WAN Interfaces
 - Perform speed tests and collect metrics

**Template pfSense Active: Speedtest**

 - Discovery of WAN Interfaces
 - Perform speed tests and collect metrics


## Configuration

### Install PHP script for Agent

- Option 1: via Web GUI **Diagnostics/Command Prompt**

```bash
[ -d "/root/scripts" ] || mkdir /root/scripts ; curl -o /root/scripts/pfsense_zbx.php https://raw.githubusercontent.com/Futur-Tech/futur-tech-zabbix-pfsense/main/pfsense_zbx.php
```
> You can add this command to **Services** > **Shellcmd** in order to download the latest version of the script, each time you reboot or restore a config backup.

- Option 2 : via pfSense shell

```bash
mkdir /root/scripts
curl -o /root/scripts/pfsense_zbx.php https://raw.githubusercontent.com/Futur-Tech/futur-tech-zabbix-pfsense/main/pfsense_zbx.php 
```


### Zabbix Package Install

From the package manager install package "Zabbix Agent 5" and "Zabbix Proxy 5"

### Setup Zabbix Proxy

Make sure to fill the following fields:

```
TLS Connect: psk
TLS Accept: psk
TLS PSK Identity: <hostname-of-the-pfsense>
TLS PSK: <random-key>
```
To generate a PSK key you can use the command in Linux: 
    
```bash
openssl rand -hex 32
```

Click on **Show Advanced Options**

In Advanced Features-> User Parameters

```
EnableRemoteCommands=1
```

### Setup Zabbix Agent

Make sure to fill the following fields:

```
Timeout: 10
TLS Connect: psk
TLS Accept: psk
TLS PSK Identity: <auto-registration-identity>
TLS PSK: <auto-registration-key>
```
Click on **Show Advanced Options**

In Advanced Features-> User Parameters

```bash
# https://github.com/Futur-Tech/futur-tech-zabbix-pfsense
AllowRoot=1
HostMetadataItem=system.uname
UserParameter=pfsense.states.max,grep "limit states" /tmp/rules.limits | cut -f4 -d ' '
UserParameter=pfsense.states.current,grep "current entries" /tmp/pfctl_si_out | tr -s ' ' | cut -f4 -d ' '
UserParameter=pfsense.mbuf.current,netstat -m | grep "mbuf clusters" | cut -f1 -d ' ' | cut -d '/' -f1
UserParameter=pfsense.mbuf.cache,netstat -m | grep "mbuf clusters" | cut -f1 -d ' ' | cut -d '/' -f2
UserParameter=pfsense.mbuf.max,netstat -m | grep "mbuf clusters" | cut -f1 -d ' ' | cut -d '/' -f4
UserParameter=pfsense.discovery[*],/usr/local/bin/php /root/scripts/pfsense_zbx.php discovery $1
UserParameter=pfsense.value[*],/usr/local/bin/php /root/scripts/pfsense_zbx.php $1 $2 $3
```

### Zabbix Server Install Note

- Add the proxy in: **Administration** -> **Proxies** (don't forget to put the correct PSK).
- Create a new host-group for the proxy **Configuration** -> **Host groups**
- Create a new "Autoregistration actions" **Configuration** -> **Action** -- in the top left select **Autoregistration actions**
- Create a new "Discovery rules" **Configuration** -> **Discovery**

The new host should automatically register in Zabbix with all templates correctly assigned.

The Host Name will be the hostname of the Pfsense.

* Modify the visible name
* Correct the Agent interface if it is incorrect
* Under the tab **Encryption** put the same PSK ID and Key as the proxy *(it doesn't need to be the same as the proxy BUT make sure to not use 2 keys on separate host/proxy with the same identity).*
* **Update the PSK ID and Key in the Pfsense Zabbix Agent!**

## Note on the script and template

_Please note that **AllowRoot=1** option is required in order to execute correctly OpenVPN checks and others._

Also increase the **Timeout** value at least to **5**, otherwise some checks will fail.

Then import xml templates in Zabbix and add your pfSense hosts.

If you are running a redundant CARP setup you should adjust the macro {$EXPECTED_CARP_STATUS} to a value representing what is CARP expected status on monitored box.

Possible values are:

 - 0: Disabled
 - 1: Master
 - 2: Backup

This is useful when monitoring services which could stay stopped on CARP Backup Member.


### Setup Speedtest

For running speedtests on WAN interfaces you have to install the speedtest package.


From **Diagnostics/Command Prompt** input this commands:

```bash
pkg update && pkg install -y  -g 'py*-speedtest-cli'
```

> You can add this command also to **Services** > **Shellcmd** if you want automatic install at boot.

Speedtest python package could be broken at the moment, so you could need an extra step, *only if manually executing speedtest results in an error*: download the latest version from package author's github repo.

```bash
/usr/local/bin/speedtest
```

If you get an error while testing you can overide the Python script from the original version.

```bash
curl -Lo /usr/local/lib/python3.7/site-packages/speedtest.py https://raw.githubusercontent.com/Futur-Tech/speedtest-cli/master/speedtest.py
```

> Note that for pfSense 2.4, Python 3.7 is installed. In 2.5, it's Python 3.8... so adjust the path if needed.

Remember that you will need to install the package on *every* pfSense upgrade, to avoid this inconvenience you can add the install command in **Schellcmd**.

Speedtest template creates a cron job and check for entry everytime Zabbix requests its items. If you want to uninstall the cron jobs simply run, from **Diagnostics/Command Prompt**:

```bash
/usr/local/bin/php /root/scripts/pfsense_zbx.php cron_cleanup
```

## Credits

Original GIT: https://github.com/rbicelli/pfsense-zabbix-template

[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/rbicelli)

[Keenton Zabbix Template](https://github.com/keentonsas/zabbix-template-pfsense) for Zabbix Agent freeBSD part.
