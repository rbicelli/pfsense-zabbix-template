[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/rbicelli)

# pfSense Zabbix Template

This is a pfSense active template for Zabbix, based on Standard Agent and a php script using pfSense functions library for monitoring specific data.

Tested with pfSense 2.7.x, Zabbix 6.0.

I'm actively maintaning template only for the current Zabbix LTS Release. Newest features will be explicitily added on current LTS.

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
 - Certificate Discovery and Monitoring
 
**Template pfSense Active: OpenVPN Server User Auth**

 - Discovery of OpenVPN Clients connected to OpenVPN Servers in user auth mode
 - Monitoring of Client Parameters (Bytes sent/received, Connection Time...) 

**Template pfSense Active: IPsec**

 - Discovery of IPsec Site-to-Site tunnels
 - Monitoring tunnel status (Phase 1 and Phase 2)
 
**Template pfSense Active: Speedtest**

 - Discovery of WAN Interfaces
 - Discover public IP Address/ISP Name of WAN Interfaces
 - Perform speed tests and collect metrics


## Configuration

First copy the file pfsense_zbx.php to your pfsense box (e.g. to /root/scripts).

From **Diagnostics/Command Prompt** input this one-liner:

```bash
curl --create-dirs -o /root/scripts/pfsense_zbx.php https://raw.githubusercontent.com/rbicelli/pfsense-zabbix-template/master/pfsense_zbx.php
```

Then install package "Zabbix Agent 6" (or "Zabbix Agent 5") on your pfSense Box

In Advanced Features-> User Parameters

```bash
AllowRoot=1
UserParameter=pfsense.states.max,grep "limit states" /tmp/rules.limits | cut -f4 -d ' '
UserParameter=pfsense.states.current,grep "current entries" /tmp/pfctl_si_out | tr -s ' ' | cut -f4 -d ' '
UserParameter=pfsense.mbuf.current,netstat -m | grep "mbuf clusters" | cut -f1 -d ' ' | cut -d '/' -f1
UserParameter=pfsense.mbuf.cache,netstat -m | grep "mbuf clusters" | cut -f1 -d ' ' | cut -d '/' -f2
UserParameter=pfsense.mbuf.max,netstat -m | grep "mbuf clusters" | cut -f1 -d ' ' | cut -d '/' -f4
UserParameter=pfsense.discovery[*],/usr/local/bin/php /root/scripts/pfsense_zbx.php discovery $1
UserParameter=pfsense.value[*],/usr/local/bin/php /root/scripts/pfsense_zbx.php $1 $2 $3
```

_Please note that **AllowRoot=1** option is required in order to correctly execute OpenVPN checks and others._

Also increase the **Timeout** value at least to **5**, otherwise some checks will fail.

Then import xml templates in Zabbix and add your pfSense hosts.

If you are running a redundant CARP setup you should adjust the macro {$EXPECTED_CARP_STATUS} to a value representing what is CARP expected status on monitored box.

Possible values are:

 - 0: Disabled
 - 1: Master
 - 2: Backup

This is useful when monitoring services which could stay stopped on CARP Backup Member.

## Setup Speedtest

For running speedtests on WAN interfaces on the latest pfSense CE (2.7.2), it's recommended to check the available speedtest package first using:

```bash
pkg search speedtest
```

This will provide you with the latest package information. To install the speedtest package, use the following commands in **Diagnostics/Command Prompt**:
Then, setup the system version cronjob with: 

```bash 
/usr/local/bin/php /root/scripts/pfsense_zbx.php sysversion_cron
```

```bash
pkg update && pkg install -y py311-speedtest-cli
```

Make sure to replace `py311-speedtest-cli` with the correct package name based on the results of the pkg search speedtest command.

Speedtest python package could be broken at the moment, so you could need an extra step, *only if manually executing speedtest results in an error*: download the latest version from package author's github repo.

```bash
curl -Lo /usr/local/lib/python3.8/site-packages/speedtest.py https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py
```

For testing if speedtest is installed properly you can try it:

```bash
/usr/local/bin/speedtest
```

Then, setup the cronjob with: 

```bash 
/usr/local/bin/php /root/scripts/pfsense_zbx.php speedtest_cron
```

Remember that you will need to install the package on *every* pfSense upgrade.

Speedtest template creates a cron job and check for entry everytime Zabbix requests its items. If you  want to uninstall the cron jobs simply run, from **Diagnostics/Command Prompt**:

```bash
/url/local/bin/php /root/scripts/pfsense_zbx.php cron_cleanup
```

## Credits

[Keenton Zabbix Template](https://github.com/keentonsas/zabbix-template-pfsense) for Zabbix Agent freeBSD part.
