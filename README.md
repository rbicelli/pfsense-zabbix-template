[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/rbicelli)

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


## Configuration

First copy the file pfsense_zbx.php to your pfsense box (e.g. to /root/scripts).

From **Diagnostics/Command Prompt** input this one-liner:

```bash
curl --create-dirs -o /root/scripts/pfsense_zbx.php https://raw.githubusercontent.com/rbicelli/pfsense-zabbix-template/master/pfsense_zbx.php
```

> You can add this command to **Services** > **Shellcmd** (which is available in pfSense Package Manager) in order to download the latest version of the script, each time you reboot or restore a config backup.

Then install package "Zabbix Agent 5" (or "Zabbix Agent 4") on your pfSense Box

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

For running speedtests on WAN interfaces you have to install the speedtest package.


From **Diagnostics/Command Prompt** input this commands:

```bash
pkg update && pkg install -y  -g 'py*-speedtest-cli'
```

> You can add this command also to **Services** > **Shellcmd** if you want automatic install at boot.

Speedtest python package could be broken at the moment, so you could need an extra step, *only if manually executing speedtest results in an error*: download the latest version from package author's github repo.

```bash
curl -Lo /usr/local/lib/python3.8/site-packages/speedtest.py https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py
```

For testing if speedtest is installed properly you can try it:

```bash
/usr/local/bin/speedtest
```

Remember that you will need to install the package on *every* pfSense upgrade.

Speedtest template creates a cron job and check for entry everytime Zabbix requests its items. If you  want to uninstall the cron jobs simply run, from **Diagnostics/Command Prompt**:

```bash
/usr/local/bin/php /root/scripts/pfsense_zbx.php cron_cleanup
```

## Credits

[Keenton Zabbix Template](https://github.com/keentonsas/zabbix-template-pfsense) for Zabbix Agent freeBSD part.