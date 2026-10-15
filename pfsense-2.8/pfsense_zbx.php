<?php

/*** 
pfsense_zbx.php - pfSense Zabbix Interface
Version 0.24.7 - 2024-04-27

Written by Riccardo Bicelli <r.bicelli@gmail.com>
This program is licensed under Apache 2.0 License
 */

/**
 * Notas de manutencao e homologacao (2026-10-15):
 * - Compatibilidade exercitada em pfSense CE 2.7.2 e CE 2.8.1.
 * - O numero SCRIPT_VERSION permanece o da versao upstream; este arquivo
 *   contem correcoes locais ainda sujeitas a homologacao integral.
 * - Comandos de leitura nao devem criar tarefas de cron.
 * - Speedtest: cliente Python speedtest-cli 2.1.3, cache de 8 horas;
 *   agendamento a cada 15 minutos instalado explicitamente.
 * - Os comentarios identificam responsabilidades e limites do teste;
 *   nao implicam suporte validado para todas as configuracoes do pfSense.
 */

//Some Useful defines
define('SCRIPT_VERSION', '0.24.7');

define('SPEEDTEST_INTERVAL', 8); //Speedtest Interval (in hours)
define('CRON_TIME_LIMIT', 300); // Time limit in seconds of speedtest and sysinfo 
define('DEFAULT_TIME_LIMIT', 30); // Time limit in seconds otherwise

require_once('globals.inc');
require_once('functions.inc');
require_once('config.inc');
require_once('util.inc');

//For Interfaces Discovery
require_once('interfaces.inc');

//For OpenVPN Discovery
require_once('openvpn.inc');

//For Service Discovery
require_once("service-utils.inc");

//For System
require_once('pkg-utils.inc');

//For DHCP

//Backporting php 8 functions
if (!function_exists('str_contains')) {

	function str_contains($haystack, $needle)
	{

		return strstr($haystack, $needle);
	}
}

//Testing function, for template creating purpose
/** Diagnostico detalhado para manutencao. Pode imprimir dados de configuracao; nao utilizar como item Zabbix. */
function pfz_test()
{
	$line = "-------------------\n";

	$ovpn_servers = pfz_openvpn_get_all_servers();
	echo "OPENVPN Servers:\n";
	print_r($ovpn_servers);
	echo $line;

	$ovpn_clients = openvpn_get_active_clients();
	echo "OPENVPN Clients:\n";
	print_r($ovpn_clients);
	echo $line;

	$ifdescrs = get_configured_interface_with_descr(true);
	$ifaces = array();
	foreach ($ifdescrs as $ifdescr => $ifname) {
		$ifinfo = get_interface_info($ifdescr);
		$ifaces[$ifname] = $ifinfo;
	}
	echo "Network Interfaces:\n";
	print_r($ifaces);
	print_r(get_interface_arr());
	print_r(get_configured_interface_list());
	echo $line;

	$services = get_services();
	echo "Services: \n";
	print_r($services);
	echo $line;

	echo "IPsec: \n";

	require_once("ipsec.inc");
	global $config;
	init_config_arr(array('ipsec', 'phase1'));
	init_config_arr(array('ipsec', 'phase2'));
	$a_phase2 = &$config['ipsec']['phase2'];
	$status = ipsec_list_sa();
	echo "IPsec Status: \n";
	print_r($status);

	$a_phase1 = &$config['ipsec']['phase1'];
	$a_phase2 = &$config['ipsec']['phase2'];

	echo "IPsec Config Phase 1: \n";
	print_r($a_phase1);

	echo "IPsec Config Phase 2: \n";
	print_r($a_phase2);

	echo $line;

	//Packages
	echo "Packages: \n";
	require_once("pkg-utils.inc");
	$installed_packages = get_pkg_info('all', false, true);
	print_r($installed_packages);
}


// Interface Discovery
// Improved performance
/** Descobre interfaces e, opcionalmente, filtra WAN. No modo cron retorna nomes fisicos em array. */
function pfz_interface_discovery($is_wan = false, $is_cron = false)
{
	$ifdescrs = get_configured_interface_with_descr(true);
	$ifaces = get_interface_arr();
	$ifcs = array();
	$if_ret = array();

	$json_string = '{"data":[';

	foreach ($ifdescrs as $ifname => $ifdescr) {
		$ifinfo = get_interface_info($ifname);
		$ifinfo["description"] = $ifdescr;
		$ifcs[$ifname] = $ifinfo;
	}

	foreach ($ifaces as $hwif) {

		$ifdescr = $hwif;
		$has_gw = false;
		$is_vpn = false;
		$has_public_ip = false;

		foreach ($ifcs as $ifc => $ifinfo) {
			if ($ifinfo["hwif"] == $hwif) {
				$ifdescr = $ifinfo["description"];
				if (array_key_exists("gateway", $ifinfo)) $has_gw = true;
				//	Issue #81 - https://stackoverflow.com/a/13818647/15093007
				if (filter_var($ifinfo["ipaddr"], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) $has_public_ip = true;
				if (strpos($ifinfo["if"], "ovpn") !== false) $is_vpn = true;
				break;
			}
		}

		if (($is_wan == false) ||  (($is_wan == true) && (($has_gw == true) || ($has_public_ip == true)) && ($is_vpn == false))) {
			$if_ret[] = $hwif;
			$json_string .= '{"{#IFNAME}":"' . $hwif . '"';
			$json_string .= ',"{#IFDESCR}":"' . $ifdescr . '"';
			$json_string .= '},';
		}
	}
	$json_string = rtrim($json_string, ",");
	$json_string .= "]}";

	if ($is_cron) return $if_ret;

	echo $json_string;
}


//Interface Speedtest

/** Le apenas metricas escalares do cache JSON. Nao instala agendamentos e nao gera trafego. */
function pfz_interface_speedtest_value($ifname, $value)
{
    $parts = explode(".", $value, 2);
    $key = $parts[0];
    $subvalue = $parts[1] ?? null;

    $filename = "/tmp/speedtest-$ifname";

    if (!is_file($filename)) {
        return;
    }

    $speedtest_data = json_decode(
        file_get_contents($filename),
        true
    );

    if (!is_array($speedtest_data) ||
        !array_key_exists($key, $speedtest_data)) {
        return;
    }

    $result = $speedtest_data[$key];

    if ($subvalue !== null) {
        if (!is_array($result) ||
            !array_key_exists($subvalue, $result)) {
            return;
        }

        $result = $result[$subvalue];
    }

    if (is_scalar($result)) {
        echo $result;
    }
}

// This is supposed to run via cron job
/** Percorre WANs configuradas e encaminha cada IPv4 a rotina de coleta. Nao instala cron. */
function pfz_speedtest_cron()
{
    $ifdescrs = get_configured_interface_with_descr(true);
    $wanInterfaces = pfz_interface_discovery(true, true);

    foreach ($wanInterfaces as $ifname) {
        $ipaddr = null;

        foreach ($ifdescrs as $ifn => $ifdescr) {
            $ifinfo = get_interface_info($ifn);

            if (($ifinfo['hwif'] ?? null) !== $ifname) {
                continue;
            }

            $ipaddr = $ifinfo['ipaddr'] ?? null;
            break;
        }

        if (!filter_var($ipaddr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            continue;
        }

        pfz_speedtest_exec($ifname, $ipaddr);
    }
}

// Agendamento explicito: a rotina de coleta nao deve alterar o proprio cron.
/** Instala ou remove explicitamente a entrada do Speedtest em /etc/crontab a cada 15 minutos. */
function pfz_speedtest_cron_install($enable = true)
{
	//Install Cron Job
	$command = "/usr/local/bin/php " . __FILE__ . " speedtest_cron";
	install_cron_job($command, $enable, $minute = "*/15", "*", "*", "*", "*", "root", true);
}



/** Executa Speedtest Python se cache ausente, invalido ou expirado; publica JSON validado via rename. */
function pfz_speedtest_exec($ifname, $ipaddr)
{
    $speedtest = '/usr/local/bin/speedtest';

    $filename = "/tmp/speedtest-$ifname";
    $filerun = '/tmp/speedtest-run';

    if (!is_executable($speedtest)) {
        return false;
    }

    if (!filter_var($ipaddr, FILTER_VALIDATE_IP)) {
        return false;
    }

    $cacheValid = false;

    if (is_file($filename)) {
        $cached = json_decode(
            (string) @file_get_contents($filename),
            true
        );

        $cacheValid = is_array($cached)
            && isset($cached['download'], $cached['upload'], $cached['ping'])
            && is_numeric($cached['download'])
            && is_numeric($cached['upload'])
            && is_numeric($cached['ping']);
    }

    if (
        $cacheValid &&
        (time() - filemtime($filename)) < SPEEDTEST_INTERVAL * 3600
    ) {
        return true;
    }

    // Bloqueio local por firewall; o arquivo de lock pode persistir apos a execucao.
    $lock = @fopen($filerun, 'c');

    if ($lock === false) {
        return false;
    }

    if (!flock($lock, LOCK_EX | LOCK_NB)) {
        fclose($lock);
        return false;
    }

    try {
        // Atraso aleatorio entre firewalls; nao substitui coordenacao global.
        sleep(rand(1, 90));

        // Arquivo temporario exclusivo; cache antigo so e substituido por JSON valido.
        $filetemp = tempnam('/tmp', "speedtest-");

        if ($filetemp === false) {
            return false;
        }

        $command = escapeshellarg($speedtest)
            . ' --secure'
            . ' --source ' . escapeshellarg($ipaddr)
            . ' --json'
            . ' > ' . escapeshellarg($filetemp)
            . ' 2>/dev/null';

        $output = [];
        $exitCode = 0;

        exec($command, $output, $exitCode);

        $raw = @file_get_contents($filetemp);
        $data = json_decode((string) $raw, true);

        if (
            $exitCode !== 0 ||
            !is_array($data) ||
            !isset($data['download'], $data['upload'], $data['ping']) ||
            !is_numeric($data['download']) ||
            !is_numeric($data['upload']) ||
            !is_numeric($data['ping'])
        ) {
            @unlink($filetemp);
            return false;
        }

        @chmod($filetemp, 0600);

        if (!@rename($filetemp, $filename)) {
            @unlink($filetemp);
            return false;
        }

        return true;

    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}


// OpenVPN Server Discovery
/** Reune servidores OpenVPN convencionais e point-to-point para consulta e descoberta. */
function pfz_openvpn_get_all_servers()
{
	$servers = openvpn_get_active_servers();
	$sk_servers = openvpn_get_active_servers("p2p");
	$servers = array_merge($servers, $sk_servers);
	return ($servers);
}


/** Gera macros LLD dos servidores OpenVPN. */
function pfz_openvpn_serverdiscovery()
{
	$servers = pfz_openvpn_get_all_servers();

	$json_string = '{"data":[';

	foreach ($servers as $server) {
		$name = trim(preg_replace('/\w{3}(\d)?\:\d{4,5}/i', '', $server['name']));
		$json_string .= '{"{#SERVER}":"' . $server['vpnid'] . '"';
		$json_string .= ',"{#NAME}":"' . $name . '"';
		$json_string .= '},';
	}

	$json_string = rtrim($json_string, ",");
	$json_string .= "]}";

	echo $json_string;
}


// Get OpenVPN Server Value

/** Consulta propriedades dos servidores OpenVPN, com mapeamento de estados para Zabbix. */
function pfz_openvpn_servervalue($server_id, $valuekey)
{
	$servers = pfz_openvpn_get_all_servers();
	$value = null;

	foreach ($servers as $server) {
		if (($server['vpnid'] ?? null) == $server_id) {
			$value = $server[$valuekey] ?? null;

			if ($valuekey == "status") {
				if (
					($server['mode'] == "server_user") ||
					($server['mode'] == "server_tls_user") ||
					($server['mode'] == "server_tls")
				) {
					if ($value == "") {
						$value = "server_user_listening";
					}
				} else if ($server['mode'] == "p2p_tls") {
					if ($value == "") {
						$value = (
							is_array($server["conns"] ?? null) &&
							count($server["conns"]) > 0
						) ? "up" : "down";
					}
				}
			}

			break;
		}
	}

	switch ($valuekey) {
		case "conns":
			$value = is_array($value) ? count($value) : 0;
			break;

		case "status":
			$value = pfz_valuemap("openvpn.server.status", $value);
			break;

		case "mode":
			$value = pfz_valuemap("openvpn.server.mode", $value);
			break;

		case "bytes_recv":
		case "bytes_sent":
			$value = is_numeric($value) ? $value : 0;
			break;
	}

	echo $value;
}

//OpenVPN Server/User-Auth Discovery
/** Descobre usuarios conectados aos servidores OpenVPN que disponibilizam conexoes. */
function pfz_openvpn_server_userdiscovery()
{
	$servers = pfz_openvpn_get_all_servers();

	$json_string = '{"data":[';

	foreach ($servers as $server) {
		if (($server['mode'] == 'server_user') || ($server['mode'] == 'server_tls_user') || ($server['mode'] == 'server_tls')) {
			if (is_array($server['conns'])) {
				$name = trim(preg_replace('/\w{3}(\d)?\:\d{4,5}/i', '', $server['name']));

				foreach ($server['conns'] as $conn) {

					$common_name = pfz_replacespecialchars($conn['common_name']);

					$json_string .= '{"{#SERVERID}":"' . $server['vpnid'] . '"';
					$json_string .= ',"{#SERVERNAME}":"' . $name . '"';
					$json_string .= ',"{#UNIQUEID}":"' . $server['vpnid'] . '+' . $common_name . '"';
					$json_string .= ',"{#USERID}":"' . $conn['common_name'] . '"';
					$json_string .= '},';
				}
			}
		}
	}

	$json_string = rtrim($json_string, ",");
	$json_string .= "]}";

	echo $json_string;
}


/**
 * Returns a field from an authenticated OpenVPN client session.
 *
 * The unique identifier contains:
 * SERVER_ID + encoded COMMON_NAME.
 *
 * $default defines the fallback value when the client
 * is disconnected or a field is unavailable.
 *
 * Used by:
 * - openvpn_server_uservalue
 * - openvpn_server_uservalue_numeric
 */
function pfz_openvpn_server_uservalue(
    $unique_id,
    $valuekey,
    $default = ""
) {
    $value = $default;

    $unique_id = pfz_replacespecialchars(
        $unique_id,
        true
    );

    $atpos = strpos($unique_id, '+');

    if ($atpos === false) {
        echo $default;
        return;
    }

    $server_id = substr($unique_id, 0, $atpos);
    $user_id = substr($unique_id, $atpos + 1);

    $servers = pfz_openvpn_get_all_servers();

    foreach ($servers as $server) {
        if (($server['vpnid'] ?? null) != $server_id) {
            continue;
        }

        $connections = $server['conns'] ?? [];

        if (!is_array($connections)) {
            continue;
        }

        foreach ($connections as $conn) {
            if (($conn['common_name'] ?? null) != $user_id) {
                continue;
            }

            $value = $conn[$valuekey] ?? $default;
            break 2;
        }
    }

    if ($value === null || $value === "") {
        $value = $default;
    }

    if (is_scalar($value)) {
        echo $value;
    }
}

// OpenVPN Client Discovery
/** Gera macros LLD de clientes OpenVPN configurados. */
function pfz_openvpn_clientdiscovery()
{
	$clients = openvpn_get_active_clients();

	$json_string = '{"data":[';

	foreach ($clients as $client) {
		$name = trim(preg_replace('/\w{3}(\d)?\:\d{4,5}/i', '', $client['name']));
		$json_string .= '{"{#CLIENT}":"' . $client['vpnid'] . '"';
		$json_string .= ',"{#NAME}":"' . $name . '"';
		$json_string .= '},';
	}

	$json_string = rtrim($json_string, ",");
	$json_string .= "]}";

	echo $json_string;
}

/** Codifica ou restaura caracteres especiais usados em identificadores de descoberta. */
function pfz_replacespecialchars($inputstr, $reverse = false)
{
	$specialchars = ",',\",`,*,?,[,],{,},~,$,!,&,;,(,),<,>,|,#,@,0x0a";
	$specialchars = explode(",", $specialchars);
	$resultstr = $inputstr;

	for ($n = 0; $n < count($specialchars); $n++) {
		if ($reverse == false)
			$resultstr = str_replace($specialchars[$n], '%%' . $n . '%', $resultstr);
		else
			$resultstr = str_replace('%%' . $n . '%', $specialchars[$n], $resultstr);
	}

	return ($resultstr);
}


/** Consulta status e demais campos de cliente OpenVPN, com valores padrao. */
function pfz_openvpn_clientvalue($client_id, $valuekey, $default = "none")
{
	$clients = openvpn_get_active_clients();
	$value = null;

	foreach ($clients as $client) {
		if (($client['vpnid'] ?? null) == $client_id) {
			$value = $client[$valuekey] ?? null;
			break;
		}
	}

	switch ($valuekey) {
		case "status":
			$value = pfz_valuemap("openvpn.client.status", $value);
			break;

		case "bytes_recv":
		case "bytes_sent":
			$value = is_numeric($value) ? $value : 0;
			break;
	}

	if ($value === null || $value === "") {
		$value = $default;
	}

	echo $value;
}


// Services Discovery
// 2020-03-27: Added space replace with __ for issue #12
/** Descobre servicos monitoraveis sem consultar status durante a descoberta. */
function pfz_services_discovery()
{
	$services = get_services();

	$json_string = '{"data":[';

	foreach ($services as $service) {
		if (!empty($service['name'])) {


			$id = "";
			//id for OpenVPN               
			if (!empty($service['id'])) $id = "." . $service["id"];
			//zone for Captive Portal
			if (!empty($service['zone'])) $id = "." . $service["zone"];

			$json_string .= '{"{#SERVICE}":"' . str_replace(" ", "__", $service['name']) . $id . '"';
			$json_string .= ',"{#DESCRIPTION}":"' . $service['description'] . '"';
			$json_string .= '},';
		}
	}
	$json_string = rtrim($json_string, ",");
	$json_string .= "]}";

	echo $json_string;
}

// Get service value
// 2020-03-27: Added space replace in service name for issue #12
// 2020-09-28: Corrected Space Replace
/** Retorna status ou metadados de um servico; inclui regra de CARP secundario. */
function pfz_service_value($name, $value)
{
	$services = get_services();
	$name = str_replace("__", " ", $name);

	//List of service which are stopped on CARP Slave.
	//For now this is the best way i found for filtering out the triggers
	//Waiting for a way in Zabbix to use Global Regexp in triggers with items discovery
	$stopped_on_carp_slave = array("haproxy", "radvd", "openvpn.", "openvpn", "avahi");

	foreach ($services as $service) {
		$namecfr = $service["name"];
		$carpcfr = $service["name"];

		//OpenVPN          
		if (!empty($service['id'])) {
			$namecfr = $service['name'] . "." . $service["id"];
			$carpcfr = $service['name'] . ".";
		}

		//Captive Portal
		if (!empty($service['zone'])) {
			$namecfr = $service['name'] . "." . $service["zone"];
			$carpcfr = $service['name'] . ".";
		}

		if ($namecfr == $name) {
			switch ($value) {

				case "status":
					$status = get_service_status($service);
					if ($status == "") $status = 0;
					echo $status;
					return;

				case "name":
					echo $namecfr;
					return;

				case "enabled":
					if (is_service_enabled($service['name']))
						echo 1;
					else
						echo 0;
					return;

				case "run_on_carp_slave":
					if (in_array($carpcfr, $stopped_on_carp_slave))
						echo 0;
					else
						echo 1;
					return;
				default:
					if (array_key_exists($value, $service)) {
						echo $service[$value];
					}
					return;
			}
		}
	}

	echo 0;
}


//Gateway Discovery
/** Retorna estado textual nativo dos gateways (ex.: WAN_DHCP.down). */
function pfz_gw_rawstatus()
{
	// Return a Raw Gateway Status, useful for action Scripts (e.g. Update Cloudflare DNS config)
	$gws = return_gateways_status(true);
	$gw_string = "";
	foreach ($gws as $gw) {
		$gw_string .= ($gw['name'] . '.' . $gw['status'] . ",");
	}
	echo rtrim($gw_string, ",");
}


/** Gera descoberta LLD de gateways. */
function pfz_gw_discovery()
{
	$gws = return_gateways_status(true);

	$json_string = '{"data":[';
	foreach ($gws as $gw) {
		$json_string .= '{"{#GATEWAY}":"' . $gw['name'] . '"';
		$json_string .= '},';
	}
	$json_string = rtrim($json_string, ",");
	$json_string .= "]}";

	echo $json_string;
}



/** Consulta metrica de gateway; para status, substatus valido tem precedencia. */
function pfz_gw_value($gw, $valuekey)
{
	$gws = return_gateways_status(true);

	if (!isset($gws[$gw]) || !array_key_exists($valuekey, $gws[$gw])) {
		return;
	}

	$value = $gws[$gw][$valuekey];

	if ($valuekey == "status") {
		// Issue #70: Gateway Forced Down
		if (($gws[$gw]["substatus"] ?? "none") != "none") {
			$value = $gws[$gw]["substatus"];
		}

		$value = pfz_valuemap("gateway.status", $value);
	}

	echo $value;
}


// IPSEC Discovery
/** Descobre tunel IPsec Phase 1 por IKEID. */
function pfz_ipsec_discovery_ph1()
{

	require_once("ipsec.inc");
	global $config;
	init_config_arr(array('ipsec', 'phase1'));
	$a_phase1 = &$config['ipsec']['phase1'];

	$json_string = '{"data":[';

	foreach ($a_phase1 as $data) {
		$json_string .= '{"{#IKEID}":"' . $data['ikeid'] . '"';
		$json_string .= ',"{#NAME}":"' . $data['descr'] . '"';
		$json_string .= '},';
	}

	$json_string = rtrim($json_string, ",");
	$json_string .= "]}";

	echo $json_string;
}

/** Consulta status e parametros configurados da Phase 1. */
function pfz_ipsec_ph1($ikeid, $valuekey)
{
	// Get Value from IPsec Phase 1 Configuration
	// If Getting "disabled" value only check item presence in config array

	require_once("ipsec.inc");
	global $config;
	init_config_arr(array('ipsec', 'phase1'));
	$a_phase1 = &$config['ipsec']['phase1'];

	$value = "";
	switch ($valuekey) {
		case 'status':
			$value = pfz_ipsec_status($ikeid);
			break;
		case 'disabled':
			$value = "0";
		default:
			foreach ($a_phase1 as $data) {
				if ($data['ikeid'] == $ikeid) {
					if (array_key_exists($valuekey, $data)) {
						if ($valuekey == 'disabled')
							$value = "1";
						else
							$value = pfz_valuemap("ipsec." . $valuekey, $data[$valuekey], $data[$valuekey]);
						break;
					}
				}
			}
	}
	echo $value;
}

/** Descobre Phase 2, incluindo EXTID composto por IKEID.REQID. */
function pfz_ipsec_discovery_ph2()
{

	require_once("ipsec.inc");

	global $config;
	init_config_arr(array('ipsec', 'phase2'));
	$a_phase2 = &$config['ipsec']['phase2'];

	$json_string = '{"data":[';

	foreach ($a_phase2 as $data) {
		$json_string .= '{"{#IKEID}":"' . $data['ikeid'] . '"';
		$json_string .= ',"{#NAME}":"' .  $data['descr'] . '"';
		$json_string .= ',"{#UNIQID}":"' .  $data['uniqid'] . '"';
		$json_string .= ',"{#REQID}":"' .  $data['reqid'] . '"';
		$json_string .= ',"{#EXTID}":"' .  $data['ikeid'] . '.' . $data['reqid'] . '"';
		$json_string .= '},';
	}

	$json_string = rtrim($json_string, ",");
	$json_string .= "]}";

	echo $json_string;
}

/** Consulta Phase 2 pelo identificador usado no template Zabbix. */
function pfz_ipsec_ph2($uniqid, $valuekey)
{
	require_once("ipsec.inc");
	global $config;
	init_config_arr(array('ipsec', 'phase2'));
	$a_phase2 = &$config['ipsec']['phase2'];

	$valuecfr = explode(".", $valuekey);

	switch ($valuecfr[0]) {
		case 'status':
			$idarr = explode(".", $uniqid);
			$statuskey = "state";
			if (isset($valuecfr[1])) $statuskey = $valuecfr[1];
			$value = pfz_ipsec_status($idarr[0], $idarr[1], $statuskey);
			break;
		case 'disabled':
			$value = "0";
	}

	foreach ($a_phase2 as $data) {
		if ($data['uniqid'] == $uniqid) {
			if (array_key_exists($valuekey, $data)) {
				if ($valuekey == 'disabled')
					$value = "1";
				else
					$value = pfz_valuemap("ipsec_ph2." . $valuekey, $data[$valuekey], $data[$valuekey]);
				break;
			}
		}
	}
	echo $value;
}

/** Converte estado de SAs IPsec em valores para Zabbix; sem SA, aplica o mapeamento de estado vazio. */
function pfz_ipsec_status($ikeid, $reqid = -1, $valuekey = 'state')
{

	require_once("ipsec.inc");
	global $config;
	init_config_arr(array('ipsec', 'phase1'));

	$a_phase1 = &$config['ipsec']['phase1'];
	$conmap = array();
	foreach ($a_phase1 as $ph1ent) {
		if (function_exists('get_ipsecifnum')) {
			if (get_ipsecifnum($ph1ent['ikeid'], 0)) {
				$cname = "con" . get_ipsecifnum($ph1ent['ikeid'], 0);
			} else {
				$cname = "con{$ph1ent['ikeid']}00000";
			}
		} else {
			$cname = ipsec_conid($ph1ent);
		}

		$conmap[$cname] = $ph1ent['ikeid'];
	}

	$status = ipsec_list_sa();
	$ipsecconnected = array();

	// Default state when no matching IPsec SA exists
	$tmp_value = null;

	$carp_status = pfz_carp_status(false);

	//Phase-Status match borrowed from status_ipsec.php	
	if (is_array($status)) {
		foreach ($status as $l_ikeid => $ikesa) {

			if (isset($ikesa['con-id'])) {
				$con_id = substr($ikesa['con-id'], 3);
			} else {
				$con_id = filter_var($ikeid, FILTER_SANITIZE_NUMBER_INT);
			}
			$con_name = "con" . $con_id;
			if ($ikesa['version'] == 1) {
				$ph1idx = $conmap[$con_name];
				$ipsecconnected[$ph1idx] = $ph1idx;
			} else {
				if (!ipsec_ikeid_used($con_id)) {
					// probably a v2 with split connection then
					$ph1idx = $conmap[$con_name];
					$ipsecconnected[$ph1idx] = $ph1idx;
				} else {
					$ipsecconnected[$con_id] = $ph1idx = $con_id;
				}
			}
			if ($ph1idx == $ikeid) {
				if ($reqid != -1) {
					// Asking for Phase2 Status Value
					foreach ($ikesa['child-sas'] as $childsas) {
						if ($childsas['reqid'] == $reqid) {
							if (strtolower($childsas['state']) == 'rekeyed') {
								//if state is rekeyed go on
								$tmp_value = $childsas[$valuekey];
							} else {
								$tmp_value = $childsas[$valuekey];
								break;
							}
						}
					}
				} else {
					$tmp_value = $ikesa[$valuekey];
				}

				break;
			}
		}
	}

	switch ($valuekey) {
		case 'state':
			$value = pfz_valuemap('ipsec.state', strtolower((string) ($tmp_value ?? '')));
			if ($carp_status != 0) $value = $value + (10 * ($carp_status - 1));
			break;
		default:
			$value = $tmp_value;
			break;
	}

	return $value;
}

// Temperature sensors Discovery
/** Descobre sensores de temperatura publicados em sysctl. */
function pfz_temperature_sensors_discovery()
{


	$json_string = '{"data":[';
	$sensors = [];
	exec("sysctl -a | grep temperature | cut -d ':' -f 1", $sensors, $code);
	if ($code != 0) {
		echo "";
		return;
	} else {
		foreach ($sensors as $sensor) {
			$json_string .= '{"{#SENSORID}":"' . $sensor . '"';
			$json_string .= '},';
		}
	}

	$json_string = rtrim($json_string, ",");
	$json_string .= "]}";

	echo $json_string;
}

// Temperature sensor get value
/** Consulta o valor textual de um sensor por identificador sysctl. */
function pfz_get_temperature($sensorid)
{

	exec("sysctl '$sensorid' | cut -d ':' -f 2", $value, $code);
	if ($code != 0 or count($value) != 1) {
		echo "";
		return;
	} else {
		echo trim($value[0]);
	}
}


/** Retorna estado CARP; quando echo=false, deve apenas retornar o valor. */
function pfz_carp_status($echo = true)
{
	//Detect CARP Status
	global $config;
	$status_return = 0;
	$status = get_carp_status();
	$carp_detected_problems = get_single_sysctl("net.inet.carp.demotion");

	//CARP is disabled
	$ret = 0;

	if ($status != 0) { //CARP is enabled

		if ($carp_detected_problems != 0) {
			//There's some Major Problems with CARP
			$ret = 4;
			if ($echo == true) echo $ret;
			return $ret;
		}

		$status_changed = false;
		$prev_status = "";
		foreach ($config['virtualip']['vip'] as $carp) {
			if ($carp['mode'] != "carp") {
				continue;
			}
			$if_status = get_carp_interface_status("_vip{$carp['uniqid']}");

			if (($prev_status != $if_status) && (empty($if_status) == false)) { //Some glitches with GUI
				if ($prev_status != "") $status_changed = true;
				$prev_status = $if_status;
			}
		}
		if ($status_changed) {
			//CARP Status is inconsistent across interfaces
			$ret = 3;
			echo 3;
		} else {
			if ($prev_status == "MASTER")
				$ret = 1;
			else
				$ret = 2;
		}
	}

	if ($echo == true) echo $ret;
	return $ret;
}

// DHCP Checks (copy of status_dhcp_leases.php, waiting for pfsense 2.5)
/** Remove registros duplicados conservando os indices definidos pelo algoritmo original. */
function pfz_remove_duplicate($array, $field)
{
	foreach ($array as $sub) {
		$cmp[] = $sub[$field];
	}
	$unique = array_unique(array_reverse($cmp, true));
	foreach ($unique as $k => $rien) {
		$new[] = $array[$k];
	}
	return $new;
}

// Get DHCP Arrays (copied from status_dhcp_leases.php, waiting for pfsense 2.5, in order to use system_get_dhcpleases();)
/** Analisa leases do ISC DHCP e pools de failover; nao implementa interpretacao do Kea. */
function pfz_dhcp_get($valuekey)
{
	global $g;

	require_once("config.inc");

	$leasesfile = "{$g['dhcpd_chroot_path']}/var/db/dhcpd.leases";

	$awk = "/usr/bin/awk";
	/* this pattern sticks comments into a single array item */
	$cleanpattern = "'{ gsub(\"#.*\", \"\");} { gsub(\";\", \"\"); print;}'";
	/* We then split the leases file by } */
	$splitpattern = "'BEGIN { RS=\"}\";} {for (i=1; i<=NF; i++) printf \"%s \", \$i; printf \"}\\n\";}'";

	/* stuff the leases file in a proper format into a array by line */
	@exec("/bin/cat {$leasesfile} 2>/dev/null| {$awk} {$cleanpattern} | {$awk} {$splitpattern}", $leases_content);
	$leases_count = count($leases_content);
	@exec("/usr/sbin/arp -an", $rawdata);


	$leases = [];
	$pools = [];

	// Lease labels used by the original parser.
	$dynamic_string = "dynamic";
	$active_string = "active";
	$expired_string = "free";
	$reserved_string = "backup";
	$online_string = "online";
	$offline_string = "offline";

	// Build the list of IP addresses found in the ARP table.
	$arpdata_ip = [];

	foreach ($rawdata as $arp_line) {
		if (preg_match('/\((\d{1,3}(?:\.\d{1,3}){3})\)/', $arp_line, $matches)) {
			$arpdata_ip[] = $matches[1];
		}
	}

	$i = 0;
	$l = 0;
	$p = 0;

	foreach ($leases_content as $lease) {
		/* split the line by space */
		$data = explode(" ", $lease);
		/* walk the fields */
		$f = 0;
		$fcount = count($data);
		/* with less than 20 fields there is nothing useful */
		if ($fcount < 20) {
			$i++;
			continue;
		}
		while ($f < $fcount) {
			switch ($data[$f]) {
				case "failover":
					$pools[$p]['name'] = trim($data[$f + 2], '"');
					$pools[$p]['name'] = "{$pools[$p]['name']} (" . convert_friendly_interface_to_friendly_descr(substr($pools[$p]['name'], 5)) . ")";
					$pools[$p]['mystate'] = $data[$f + 7];
					$pools[$p]['peerstate'] = $data[$f + 14];
					$pools[$p]['mydate'] = $data[$f + 10];
					$pools[$p]['mydate'] .= " " . $data[$f + 11];
					$pools[$p]['peerdate'] = $data[$f + 17];
					$pools[$p]['peerdate'] .= " " . $data[$f + 18];
					$p++;
					$i++;
					continue 3;
				case "lease":
					$leases[$l]['ip'] = $data[$f + 1];
					$leases[$l]['type'] = $dynamic_string;
					$f = $f + 2;
					break;
				case "starts":
					$leases[$l]['start'] = $data[$f + 2];
					$leases[$l]['start'] .= " " . $data[$f + 3];
					$f = $f + 3;
					break;
				case "ends":
					if ($data[$f + 1] == "never") {
						// Quote from dhcpd.leases(5) man page:
						// If a lease will never expire, date is never instead of an actual date.
						$leases[$l]['end'] = gettext("Never");
						$f = $f + 1;
					} else {
						$leases[$l]['end'] = $data[$f + 2];
						$leases[$l]['end'] .= " " . $data[$f + 3];
						$f = $f + 3;
					}
					break;
				case "tstp":
					$f = $f + 3;
					break;
				case "tsfp":
					$f = $f + 3;
					break;
				case "atsfp":
					$f = $f + 3;
					break;
				case "cltt":
					$f = $f + 3;
					break;
				case "binding":
					switch ($data[$f + 2]) {
						case "active":
							$leases[$l]['act'] = $active_string;
							break;
						case "free":
							$leases[$l]['act'] = $expired_string;
							$leases[$l]['online'] = $offline_string;
							break;
						case "backup":
							$leases[$l]['act'] = $reserved_string;
							$leases[$l]['online'] = $offline_string;
							break;
					}
					$f = $f + 1;
					break;
				case "next":
					/* skip the next binding statement */
					$f = $f + 3;
					break;
				case "rewind":
					/* skip the rewind binding statement */
					$f = $f + 3;
					break;
				case "hardware":
					$leases[$l]['mac'] = $data[$f + 2];
					/* check if it's online and the lease is active */
					if (in_array($leases[$l]['ip'], $arpdata_ip)) {
						$leases[$l]['online'] = $online_string;
					} else {
						$leases[$l]['online'] = $offline_string;
					}
					$f = $f + 2;
					break;
				case "client-hostname":
					if ($data[$f + 1] <> "") {
						$leases[$l]['hostname'] = preg_replace('/"/', '', $data[$f + 1]);
					} else {
						$hostname = gethostbyaddr($leases[$l]['ip']);
						if ($hostname <> "") {
							$leases[$l]['hostname'] = $hostname;
						}
					}
					$f = $f + 1;
					break;
				case "uid":
					$f = $f + 1;
					break;
			}
			$f++;
		}
		$l++;
		$i++;
		/* slowly chisel away at the source array */
		array_shift($leases_content);
	}
	/* remove duplicate items by mac address */
	if (count($leases) > 0) {
		$leases = pfz_remove_duplicate($leases, "ip");
	}

	if (count($pools) > 0) {
		$pools = pfz_remove_duplicate($pools, "name");
		asort($pools);
	}

	switch ($valuekey) {
		case "pools":
			return $pools;
			break;
		case "failover":
			return $pools;
			break;
		case "leases":
		default:
			return $leases;
	}
}



/** Gera LLD valida dos pools DHCP failover, inclusive quando a lista esta vazia. */
function pfz_dhcpfailover_discovery()
{
    require_once('system.inc');
    $leases = system_get_dhcpleases();
    $groups = is_array($leases) ? ($leases['failover'] ?? []) : [];
    $data = [];
    foreach (is_array($groups) ? $groups : [] as $group) {
        if (!is_array($group) || empty($group['name'])) continue;
        $data[] = ['{#FAILOVER_GROUP}' => str_replace(' ', '__', (string) $group['name'])];
    }
    echo json_encode(['data' => $data], JSON_INVALID_UTF8_SUBSTITUTE);
}

/** Conta pools ISC DHCP com estados divergentes ou diferentes de normal. */
function pfz_dhcp_check_failover()
{
	// Check DHCP Failover Status
	// Returns number of failover pools which state is not normal or
	// different than peer state
	$failover = pfz_dhcp_get("failover") ?? [];
	$ret = 0;
	foreach ($failover as $f) {
		if (($f["mystate"] != "normal") || ($f["mystate"] != $f["peerstate"])) {
			$ret++;
		}
	}
	return $ret;
}

/** Dispatcher local para metricas de DHCP. */
function pfz_dhcp($section, $valuekey = "")
{
	switch ($section) {
		case "failover":
			echo pfz_dhcp_check_failover();
			break;
		default:
	}
}

//Packages
/** Conta pacotes cujas versoes instalada e disponivel diferem. */
function pfz_packages_uptodate()
{
	require_once("pkg-utils.inc");
	$installed_packages = get_pkg_info('all', false, true);

	$ret = 0;

	foreach ($installed_packages as $package) {
		if ($package['version'] != $package['installed_version']) {
			$ret++;
		}
	}

	return $ret;
}


/** Gerencia o agendamento periodico de atualizacao do cache de versoes. */
function pfz_syscheck_cron_install($enable = true)
{
	//Install Cron Job
	$command = "/usr/local/bin/php " . __FILE__ . " syscheck_cron";
	install_cron_job($command, $enable, $minute = "0", "*/8", "*", "*", "*", "root", true);

	// FIX previous, wrong-coded install command
	$command = "/usr/local/bin/php " . __FILE__ . " systemcheck_cron";
	install_cron_job($command, false, $minute = "0", "9,21", "*", "*", "*", "root", true);
}

// System information takes a long time to get on slower systems. 
// So it is saved via a cronjob.
/** Atualiza /tmp/sysversion.json com versoes do sistema e contagem de pacotes. */
function pfz_syscheck_cron()
{
	$filename = "/tmp/sysversion.json";
	$upToDate = pfz_packages_uptodate();
	$sysVersion = get_system_pkg_version();
	$sysVersion["packages_update"] = $upToDate;
	$sysVersionJson = json_encode($sysVersion);
	if (file_exists($filename)) {
		if ((time() - filemtime($filename) > CRON_TIME_LIMIT)) {
			@unlink($filename);
		}
	}
	if (file_exists($filename) == false) {
		touch($filename);
		file_put_contents($filename, $sysVersionJson);
	}
	return true;
}

//System Information
/** Le dados de versao do cache; se ausente, preserva a instalacao automatica do syscheck. */
function pfz_get_system_value($section)
{
    if ($section === 'script_version') {
        echo SCRIPT_VERSION;
        return;
    }
    $filename = '/tmp/sysversion.json';
    $sysVersion = [];
    if (is_file($filename)) {
        $decoded = json_decode(file_get_contents($filename), true);
        if (is_array($decoded)) $sysVersion = $decoded;
    }
    if (empty($sysVersion)) {
        // Retain the existing on-demand scheduling behavior.
        pfz_syscheck_cron_install();
        if ($section === 'new_version_available') echo 0;
        return;
    }
    switch ($section) {
        case 'version': echo $sysVersion['version'] ?? ''; break;
        case 'installed_version': echo $sysVersion['installed_version'] ?? ''; break;
        case 'new_version_available':
            $available = $sysVersion['version'] ?? null;
            $installed = $sysVersion['installed_version'] ?? null;
            echo ($available === null || $installed === null || $available === $installed) ? 0 : 1;
            break;
        case 'packages_update': echo $sysVersion['packages_update'] ?? 0; break;
    }
}


/**
 * S.M.A.R.T Status - pfSense CE 2.7.x / 2.8.x
 *
 * Supports ATA/SATA, SCSI and NVMe devices.
 *
 * Return values:
 *   0 = Healthy
 *   1 = Failed
 *   2 = Unknown
 */
/** Consulta SMART via smartctl; 0 saudavel, 1 falha, 2 desconhecido. */
function pfz_get_smart_status()
{
	$smartctl = '/usr/local/sbin/smartctl';
	$devices = [];

	// Register supported devices and eliminate duplicates.
	// NVMe health is queried through nvmeN, not ndaN/nvdN.
	$add_device = static function ($name, $type = null) use (&$devices) {
		if (!is_string($name)) {
			return;
		}

		$name = basename(trim($name));

		if (!preg_match('/^(ada|da|ad|nvme)[0-9]+$/', $name)) {
			return;
		}

		if ($type === null && strpos($name, 'nvme') === 0) {
			$type = 'nvme';
		}

		// Prefer protocol information from smartctl discovery.
		if (!isset($devices[$name]) || $type !== null) {
			$devices[$name] = $type;
		}
	};

	// Native pfSense disk discovery.
	if (function_exists('get_smart_drive_list')) {
		$native = get_smart_drive_list();

		if (is_array($native)) {
			foreach ($native as $device) {
				$add_device($device);
			}
		}
	}

	// Merge disks discovered through FreeBSD.
	$disk_list = trim((string) get_single_sysctl('kern.disks'));

	foreach (preg_split('/\s+/', $disk_list) as $device) {
		$add_device($device);
	}

	// Discover NVMe controllers.
	foreach (glob('/dev/nvme[0-9]*') ?: [] as $path) {
		$add_device($path, 'nvme');
	}

	// Additional discovery using smartctl.
	// Ignore commented entries and devices that failed probing.
	if (is_executable($smartctl)) {
		$scan_lines = [];
		$scan_code = 0;

		exec(
			escapeshellarg($smartctl) . ' --scan-open 2>/dev/null',
			$scan_lines,
			$scan_code
		);

		foreach ($scan_lines as $line) {
			if (preg_match(
				'~^(/dev/(?:ada|da|ad|nvme)[0-9]+)\s+-d\s+(atacam|scsi|nvme)\b~',
				$line,
				$match
			)) {
				$add_device($match[1], $match[2]);
			}
		}
	}

	// No supported disks or smartctl unavailable.
	if (empty($devices) || !is_executable($smartctl)) {
		echo 2;
		return;
	}

	$unknown = false;

	foreach ($devices as $device => $type) {
		$command = escapeshellarg($smartctl) . ' -H';

		if ($type !== null) {
			$command .= ' -d ' . escapeshellarg($type);
		}

		$command .= ' '
			. escapeshellarg('/dev/' . $device)
			. ' 2>&1';

		$lines = [];
		$exit_code = 0;

		exec($command, $lines, $exit_code);

		$result = implode("\n", $lines);

		// Health failure takes precedence over unknown states.
		// Bits 3, 4 and 5 indicate SMART health/attribute failures.
		if (
			preg_match(
				'/SMART overall-health self-assessment test result:\s*FAILED\b/i',
				$result
			)
			|| preg_match(
				'/SMART Health Status:\s*(?:FAILED|BAD)\b/i',
				$result
			)
			|| ($exit_code & 0x38)
		) {
			echo 1;
			return;
		}

		// Recognize healthy ATA, SCSI and NVMe responses.
		$passed = preg_match(
			'/SMART overall-health self-assessment test result:\s*PASSED\b/i',
			$result
		) || preg_match(
			'/SMART Health Status:\s*(?:OK|PASSED)\b/i',
			$result
		);

		// Bits 0-2 indicate command/device errors.
		// Bits 6-7 indicate errors recorded in SMART logs.
		if (
			!$passed
			|| $exit_code < 0
			|| ($exit_code & 0xC7)
		) {
			$unknown = true;
		}
	}

	// All disks healthy = 0
	// Any failure = 1
	// Any unknown without failure = 2
	echo $unknown ? 2 : 0;
}


/** Extrai referencias revogadas sem exigir configuracao CRL. */
function pfz_get_revoked_cert_refs()
{
    global $config;

    $revoked_cert_refs = [];

    foreach (($config['crl'] ?? []) as $crl) {
        foreach (($crl['cert'] ?? []) as $revoked_cert) {
            if (isset($revoked_cert['refid'])) {
                $revoked_cert_refs[] = $revoked_cert['refid'];
            }
        }
    }

    return $revoked_cert_refs;
}

// Certificate discovery
/** Descobre certificados e autoridades (indice CA = indice original + 65536). */
function pfz_cert_discovery()
{
	global $config;
	// Contains a list of refs that were revoked and should not be considered
	$revoked_cert_refs = pfz_get_revoked_cert_refs();
	$dataObject = new \stdClass();
	$dataObject->data = [];
	foreach (array("cert", "ca") as $cert_type) {
			foreach (($config[$cert_type] ?? []) as $i => $cert) {
			if (! in_array($cert['refid'], $revoked_cert_refs)) {
				$certObject = new \stdClass();
				// Trick to keep using only 3 parameters. 
				$certObject->{'{#CERT_INDEX}'} = $cert_type == "cert" ? $i : $i + 0x10000;
				$certObject->{'{#CERT_REFID}'} = $cert['refid'];
				$certObject->{'{#CERT_NAME}'} = $cert['descr'];
				$certObject->{'{#CERT_TYPE}'} = strtoupper($cert_type);
				$dataObject->data[] = $certObject;
			}
		}
	}
	$json_string = json_encode($dataObject);
	echo $json_string;
}

/** Garante diretorio /root/.ssl com modo 0700 e cache preexistente com modo 0600. */
function pfz_cert_cache_prepare($cacheFile)
{
    $cacheDir = '/root/.ssl';
    if (!is_dir($cacheDir) && !@mkdir($cacheDir, 0700, true) && !is_dir($cacheDir)) {
        return false;
    }
    if (!@chmod($cacheDir, 0700)) {
        return false;
    }
    if (is_file($cacheFile) && !@chmod($cacheFile, 0600)) {
        return false;
    }
    return true;
}

/** Grava JSON do certificado via arquivo temporario com permissao restrita. */
function pfz_cert_cache_write($cacheFile, $data)
{
    if (!pfz_cert_cache_prepare($cacheFile)) {
        return;
    }
    $json = json_encode($data);
    if ($json === false) {
        return;
    }
    $tmp = @tempnam('/root/.ssl', 'pfz_cert_');
    if ($tmp === false) {
        return;
    }
    @chmod($tmp, 0600);
    if (@file_put_contents($tmp, $json) === false || !@rename($tmp, $cacheFile)) {
        @unlink($tmp);
    }
}

/** Obtem X.509 analisado e utiliza cache temporario de cinco minutos. */
function pfz_get_cert_info($index)
{
    global $config;
    $index = filter_var($index, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]]);
    if ($index === false) return [];
    $cacheFile = "/root/.ssl/certinfo_{$index}.json";
    if (pfz_cert_cache_prepare($cacheFile) && is_file($cacheFile)) {
        $age = time() - filemtime($cacheFile);
        if ($age >= 0 && $age < 300) {
            $cached = json_decode(file_get_contents($cacheFile), true);
            if (is_array($cached)) return $cached;
        }
    }
    $type = $index >= 0x10000 ? 'ca' : 'cert';
    $idx = $type === 'ca' ? $index - 0x10000 : $index;
    $encoded = $config[$type][$idx]['crt'] ?? null;
    if (!is_string($encoded) || $encoded === '') return [];
    $pem = base64_decode($encoded, true);
    if ($pem === false) return [];
    $info = @openssl_x509_parse($pem);
    if (!is_array($info)) return [];
    pfz_cert_cache_write($cacheFile, $info);
    return $info;
}

/** Extrai informacoes da chave publica e utiliza cache separado de cinco minutos. */
function pfz_get_cert_pkey_info($index)
{
    global $config;
    $index = filter_var($index, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]]);
    if ($index === false) return [];
    $cacheFile = "/root/.ssl/certinfo_pk_{$index}.json";
    if (pfz_cert_cache_prepare($cacheFile) && is_file($cacheFile)) {
        $age = time() - filemtime($cacheFile);
        if ($age >= 0 && $age < 300) {
            $cached = json_decode(file_get_contents($cacheFile), true);
            if (is_array($cached)) return $cached;
        }
    }
    $type = $index >= 0x10000 ? 'ca' : 'cert';
    $idx = $type === 'ca' ? $index - 0x10000 : $index;
    $encoded = $config[$type][$idx]['crt'] ?? null;
    if (!is_string($encoded) || $encoded === '') return [];
    $pem = base64_decode($encoded, true);
    if ($pem === false) return [];
    $key = @openssl_pkey_get_public($pem);
    if ($key === false) return [];
    $details = @openssl_pkey_get_details($key);
    if (!is_array($details)) return [];
    pfz_cert_cache_write($cacheFile, $details);
    return $details;
}

/** Retorna comprimento nominal, em bits, da chave do certificado. */
function pfz_get_ref_cert_algo_len($index)
{
    $info = pfz_get_cert_pkey_info($index);
    echo $info['bits'] ?? 0;
}

# Get the number of bits of security in a cryptographic key. 
/** Estima os bits de seguranca da chave segundo a formula original. */
function pfz_get_ref_cert_algo_bits($index)
{
    $info = pfz_get_cert_pkey_info($index);
    $length = $info['bits'] ?? 0;
    if (!is_numeric($length) || $length <= 0) { echo 0; return; }
    switch ($info['type'] ?? null) {
        case OPENSSL_KEYTYPE_RSA:
        case OPENSSL_KEYTYPE_DSA:
        case OPENSSL_KEYTYPE_DH:
            $bits = floor(1 / log(2) * pow(64 / 9, 1 / 3) * pow($length * log(2), 1 / 3) * pow(log(2048 * log(2)), 2 / 3));
            break;
        case OPENSSL_KEYTYPE_EC: $bits = ((int) $length) >> 1; break;
        default: $bits = 0;
    }
    echo $bits;
}

/** Identifica o tipo de chave (RSA, DSA, DH ou EC). */
function pfz_get_ref_cert_algo($index)
{
    $info = pfz_get_cert_pkey_info($index);
    switch ($info['type'] ?? null) {
        case OPENSSL_KEYTYPE_RSA: echo 'RSA'; break;
        case OPENSSL_KEYTYPE_DSA: echo 'DSA'; break;
        case OPENSSL_KEYTYPE_DH: echo 'DH'; break;
        case OPENSSL_KEYTYPE_EC: echo 'EC'; break;
    }
}

/** Estima bits de seguranca do algoritmo de assinatura a partir do nome OpenSSL. */
function pfz_get_ref_cert_hash_bits($index)
{
	// Get the number of bits of security in the hash algorithm.
	$certinfo = pfz_get_cert_info($index);
	$sigType = (string) ($certinfo["signatureTypeSN"] ?? '');
	$upperSigType = strtoupper($sigType);
	if (str_contains($upperSigType, "MD2")) {
		echo 63;
		return;
	}
	if (str_contains($upperSigType, "MD4")) {
		echo 2;
		return;
	}
	if (str_contains($upperSigType, "MD5")) {
		echo 18;
		return;
	}
	if (str_contains($upperSigType, "SHA1")) {
		echo 61;
		return;
	}
	if (str_contains($upperSigType, "SHA224")) {
		echo 112;
		return;
	}
	if (str_contains($upperSigType, "SHA3-224")) {
		echo 112;
		return;
	}
	if (str_contains($upperSigType, "SHA256")) {
		echo 128;
		return;
	}
	if (str_contains($upperSigType, "SHA3-256")) {
		echo 128;
		return;
	}
	if (str_contains($upperSigType, "SHAKE128")) {
		echo 128;
		return;
	}
	if (str_contains($upperSigType, "SHA384")) {
		echo 192;
		return;
	}
	if (str_contains($upperSigType, "SHA3-384")) {
		echo 192;
		return;
	}
	if (str_contains($upperSigType, "SHA512")) {
		echo 256;
		return;
	}
	if (str_contains($upperSigType, "SHA3-512")) {
		echo 256;
		return;
	}
	if (str_contains($upperSigType, "SHAKE256")) {
		echo 256;
		return;
	}
	if (str_contains($upperSigType, "WHIRLPOOL")) {
		echo 256;
		return;
	}
	if (str_contains($upperSigType, "SHA")) {
		# Assuming 'SHA1' (worst case scenario) for other 'sha' things.
		echo 61;
		return;
	}
	echo 0;
	return;
}

/** Retorna o identificador curto do algoritmo de assinatura. */
function pfz_get_ref_cert_hash($index)
{
    $info = pfz_get_cert_info($index);
    echo $info['signatureTypeSN'] ?? '';
}

// Certificate validity for a specific certificate
/** Retorna inicio ou fim de validade Unix de um certificado pelo indice. */
function pfz_get_ref_cert_date($valuekey, $index)
{
    $info = pfz_get_cert_info($index);
    switch ($valuekey) {
        case 'validFrom': echo $info['validFrom_time_t'] ?? 0; break;
        case 'validTo': echo $info['validTo_time_t'] ?? 0; break;
    }
}

// Certificats validity date
/** Calcula a maior data inicial ou menor data final entre certificados nao revogados. */
function pfz_get_cert_date($valuekey)
{
    global $config;
    if (!in_array($valuekey, ['validFrom.max', 'validTo.min'], true)) return;
    $revoked = pfz_get_revoked_cert_refs();
    $value = null;
    foreach (['cert', 'ca'] as $type) {
        foreach (($config[$type] ?? []) as $cert) {
            if (!is_array($cert) || in_array($cert['refid'] ?? null, $revoked, true)) continue;
            $encoded = $cert['crt'] ?? null;
            if (!is_string($encoded) || $encoded === '') continue;
            $pem = base64_decode($encoded, true);
            if ($pem === false) continue;
            $info = @openssl_x509_parse($pem);
            if (!is_array($info)) continue;
            $field = $valuekey === 'validFrom.max' ? 'validFrom_time_t' : 'validTo_time_t';
            if (!is_numeric($info[$field] ?? null)) continue;
            $timestamp = (int) $info[$field];
            if ($value === null) $value = $timestamp;
            elseif ($valuekey === 'validFrom.max') $value = max($value, $timestamp);
            else $value = min($value, $timestamp);
        }
    }
    echo $value ?? 0;
}

// File is present
/** Converte existencia de arquivo em item numerico 1 ou 0. */
function pfz_file_exists($filename)
{
	if (file_exists($filename))
		echo "1";
	else
		echo "0";
}


// Value mappings
// Each value map is represented by an associative array
/** Traduz estados textuais para codigos utilizados nos itens e triggers. */
function pfz_valuemap($valuename, $value, $default = "0")
{
	switch ($valuename) {

		case "openvpn.server.status":
			$valuemap = array(
				"down" => "0",
				"up" => "1",
				"connected (success)" => "1",
				"none" => "2",
				"reconnecting; ping-restart" => "3",
				"waiting" => "4",
				"server_user_listening" => "5"
			);
			break;

		case "openvpn.client.status":
			$valuemap = array(
				"up" => "1",
				"connected (success)" => "1",
				"down" => "0",
				"none" => "0",
				"reconnecting; ping-restart" => "2"
			);
			break;

		case "openvpn.server.mode":
			$valuemap = array(
				"p2p_tls" => "1",
				"p2p_shared_key" => "2",
				"server_tls" => "3",
				"server_user" => "4",
				"server_tls_user" => "5"
			);
			break;

		case "gateway.status":
			$valuemap = array(
				"online" => "0",
				"none" => "0",
				"loss" => "1",
				"highdelay" => "2",
				"highloss" => "3",
				"force_down" => "4",
				"down" => "5"
			);
			break;

		case "ipsec.iketype":
			$valuemap = array(
				"auto" => 0,
				"ikev1" => 1,
				"ikev2" => 2
			);
			break;

		case "ipsec.mode":
			$valuemap = array(
				"main" => 0,
				"aggressive" => 1
			);
			break;

		case "ipsec.protocol":
			$valuemap = array(
				"both" => 0,
				"inet" => 1,
				"inet6" => 2
			);
			break;

		case "ipsec_ph2.mode":
			$valuemap = array(
				"transport" => 0,
				"tunnel" => 1,
				"tunnel6" => 2
			);
			break;

		case "ipsec_ph2.protocol":
			$valuemap = array(
				"esp" => 1,
				"ah" => 2
			);
			break;

		case "ipsec.state":
			$valuemap = array(
				"established" => 1,
				"connecting" => 2,
				"installed" => 1,
				"rekeyed" => 2
			);
			break;
	}

	if (is_array($valuemap)) {
		$value = strtolower($value);
		if (array_key_exists($value, $valuemap))
			return $valuemap[$value];
	}
	return $default;
}

//Argument parsers for Discovery
/** Encaminha tipos de descoberta LLD para as funcoes correspondentes. */
function pfz_discovery($section)
{
	switch (strtolower($section)) {
		case "certificates":
			pfz_cert_discovery();
			break;
		case "gw":
			pfz_gw_discovery();
			break;
		case "wan":
			pfz_interface_discovery(true);
			break;
		case "openvpn_server":
			pfz_openvpn_serverdiscovery();
			break;
		case "openvpn_server_user":
			pfz_openvpn_server_userdiscovery();
			break;
		case "openvpn_client":
			pfz_openvpn_clientdiscovery();
			break;
		case "services":
			pfz_services_discovery();
			break;
		case "interfaces":
			pfz_interface_discovery();
			break;
		case "ipsec_ph1":
			pfz_ipsec_discovery_ph1();
			break;
		case "ipsec_ph2":
			pfz_ipsec_discovery_ph2();
			break;
		case "dhcpfailover":
			pfz_dhcpfailover_discovery();
			break;
		case "temperature_sensors":
			pfz_temperature_sensors_discovery();
			break;
	}
}

// Ponto de entrada CLI: os subcomandos de consulta nao devem modificar o cron.
// Rotinas terminadas em _cron recebem limite de tempo ampliado.
//Main Code
$mainArgument = strtolower($argv[1]);
if (substr($mainArgument, -4, 4) == "cron") {
	// A longer time limit for cron tasks.
	set_time_limit(CRON_TIME_LIMIT);
} else {
	// Set a timeout to prevent a blocked call from stopping all future calls.
	set_time_limit(DEFAULT_TIME_LIMIT);
}

switch ($mainArgument) {
	case "discovery":
		pfz_discovery($argv[2]);
		break;
	case "gw_value":
		pfz_gw_value($argv[2], $argv[3]);
		break;
	case "gw_status":
		pfz_gw_rawstatus();
		break;
	case "if_speedtest_value":
		pfz_interface_speedtest_value($argv[2] ?? "", $argv[3] ?? "");
		break;
	case "openvpn_servervalue":
		pfz_openvpn_servervalue($argv[2], $argv[3]);
		break;
	case "openvpn_server_uservalue":
		pfz_openvpn_server_uservalue($argv[2], $argv[3]);
		break;
	case "openvpn_server_uservalue_numeric":
		pfz_openvpn_server_uservalue($argv[2], $argv[3], "0");
		break;
	case "openvpn_clientvalue":
		pfz_openvpn_clientvalue($argv[2], $argv[3]);
		break;
	case "service_value":
		pfz_service_value($argv[2], $argv[3]);
		break;
	case "carp_status":
		pfz_carp_status();
		break;
	case "system":
		pfz_get_system_value($argv[2]);
		break;
	case "ipsec_ph1":
		pfz_ipsec_ph1($argv[2], $argv[3]);
		break;
	case "ipsec_ph2":
		pfz_ipsec_ph2($argv[2], $argv[3]);
		break;
	case "dhcp":
		pfz_dhcp($argv[2] ?? "", $argv[3] ?? "");
		break;
	case "file_exists":
		pfz_file_exists($argv[2]);
		break;
	case "speedtest_cron":
		// O agendamento e instalado separadamente; aqui apenas executamos a rotina.
		pfz_speedtest_cron();
		break;
	case "syscheck_cron":
		pfz_syscheck_cron_install();
		pfz_syscheck_cron();
		break;
	case "cron_cleanup":
		pfz_speedtest_cron_install(false);
		pfz_syscheck_cron_install(false);
		break;
	case "smart_status":
		pfz_get_smart_status();
		break;
	case "cert_ref_date":
		pfz_get_ref_cert_date($argv[2], $argv[3]);
		break;
	case "cert_date":
		pfz_get_cert_date($argv[2]);
		break;
	case "cert_algo":
		pfz_get_ref_cert_algo($argv[2]);
		break;
	case "cert_algo_bits":
		pfz_get_ref_cert_algo_len($argv[2]);
		break;
	case "cert_algo_secbits":
		pfz_get_ref_cert_algo_bits($argv[2]);
		break;
	case "cert_hash":
		pfz_get_ref_cert_hash($argv[2]);
		break;
	case "cert_hash_secbits":
		pfz_get_ref_cert_hash_bits($argv[2]);
		break;
	case "temperature":
		pfz_get_temperature($argv[2]);
		break;
	default:
		pfz_test();
}
