<?php
/***
 * pfsense_zbx.php - pfSense Zabbix Interface
 * Version 1.1.1 - 2021-10-24
 *
 * Written by Riccardo Bicelli <r.bicelli@gmail.com>
 * This program is licensed under Apache 2.0 License
 */
require_once("config.inc");
require_once('globals.inc');
require_once('functions.inc');
require_once("util.inc");

// For Interfaces Discovery
require_once('interfaces.inc');

// For OpenVPN Discovery
require_once('openvpn.inc');

// For Service Discovery
require_once("service-utils.inc");

// For System
require_once('pkg-utils.inc');

//Some Useful defines
define('SPEEDTEST_INTERVAL', 8); // Speedtest Interval (in hours)

define("COMMAND_HANDLERS", build_method_lookup(PfzCommands::class));

// Argument parsers for Discovery
define('DISCOVERY_SECTION_HANDLERS', build_method_lookup(PfzDiscoveries::class));

define("VALUE_MAPPINGS", [
    "openvpn.server.status" => [
        "down" => "0",
        "up" => "1",
        "none" => "2",
        "reconnecting; ping-restart" => "3",
        "waiting" => "4",
        "server_user_listening" => "5"],
    "openvpn.client.status" => [
        "up" => "1",
        "down" => "0",
        "none" => "0",
        "reconnecting; ping-restart" => "2"],
    "openvpn.server.mode" => [
        "p2p_tls" => "1",
        "p2p_shared_key" => "2",
        "server_tls" => "3",
        "server_user" => "4",
        "server_tls_user" => "5"],
    "gateway.status" => [
        "online" => "0",
        "none" => "0",
        "loss" => "1",
        "highdelay" => "2",
        "highloss" => "3",
        "force_down" => "4",
        "down" => "5"],
    "ipsec.iketype" => [
        "auto" => 0,
        "ikev1" => 1,
        "ikev2" => 2],
    "ipsec.mode" => [
        "main" => 0,
        "aggressive" => 1],
    "ipsec.protocol" => [
        "both" => 0,
        "inet" => 1,
        "inet6" => 2],
    "ipsec_ph2.mode" => [
        "transport" => 0,
        "tunnel" => 1,
        "tunnel6" => 2],
    "ipsec_ph2.protocol" => [
        "esp" => 1,
        "ah" => 2],
    "ipsec.state" => [
        "established" => 1,
        "connecting" => 2,
        "installed" => 1,
        "rekeyed" => 2]]);

const SMART_DEV_PASSED = "PASSED";
const SMART_DEV_OK = "OK";
const SMART_DEV_UNKNOWN = "";

const SMART_OK = 0;
const SMART_UNKNOWN = 2;
const SMART_ERROR = 1;

const SMART_DEV_STATUS = [
    SMART_DEV_PASSED => SMART_OK,
    SMART_DEV_OK => SMART_OK,
    SMART_DEV_UNKNOWN => SMART_UNKNOWN
];

define("SERVICES_VALUES", [
    "status" => function ($service) {
        $status = PfEnv::get_service_status($service);

        return ($status == "") ? 0 : $status;
    },
    "name" => function ($service, $name) {
        echo $name;
    },
    "enabled" => function ($service, $name, $short_name) {
        return Util::b2int(PfEnv::is_service_enabled($short_name));
    },
    "run_on_carp_slave" => function ($service, $name, $short_name, $carpcfr, $stopped_on_carp_slave) {
        return Util::b2int(in_array($carpcfr, $stopped_on_carp_slave));
    }
]);

// Abstract undefined symbols and globals from code
class PfEnv
{
    public const CRT = crt;

    public static function cfg()
    {
        global $config;

        return $config;
    }

    private static function call_pfsense_method_with_same_name_and_arguments()
    {
        $caller_function_name = debug_backtrace()[1]['function'];

        return call_user_func($caller_function_name, ...func_get_args());
    }

    public static function convert_friendly_interface_to_friendly_descr()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function get_carp_status()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function get_carp_interface_status()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function get_configured_interface_list()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function get_configured_interface_with_descr()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function get_interface_arr()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function get_interface_info()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function get_service_status()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function get_services()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function get_smart_drive_list()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function get_ipsecifnum()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function get_pkg_info()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function get_single_sysctl()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function get_system_pkg_version()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function init_config_arr()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function install_cron_job()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function ipsec_ikeid_used()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function ipsec_list_sa()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function is_service_enabled()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function openvpn_get_active_clients()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function openvpn_get_active_servers()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function return_gateways_status()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function system_get_dhcpleases()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }
}

class Util
{
    public static function array_first(array $haystack, Callback $match)
    {
        foreach ($haystack as $needle) {
            if ($match($needle)) {
                return $needle;
            }
        }

        return null;
    }

    public static function b2int(bool $b): int
    {
        return (int)$b;
    }

    public static function replace_special_chars($inputstr, $reverse = false)
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

        return $resultstr;
    }
}

class PfzDiscoveries
{
    private static function print_json(array $json)
    {
        echo json_encode([
            "data" => $json
        ]);
    }

    public static function gw()
    {
        $gws = PfEnv::return_gateways_status(true);

        self::print_json(array_map(fn($gw) => ["{#GATEWAY}" => $gw["name"]], $gws));
    }

    public static function wan()
    {
        self::discover_interface(true);
    }

    public static function temperature_sensors()
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

    private static function sanitize_server_name(string $raw_name): string
    {
        return trim(preg_replace('/\w{3}(\d)?\:\d{4,5}/i', '', $raw_name));
    }

    public static function openvpn_server()
    {
        $servers = PfzOpenVpn::get_all_openvpn_servers();

        self::print_json(array_map(fn($server) => [
            "{#SERVER}" => $server['vpnid'],
            "{#NAME}" => self::sanitize_server_name($server["name"])],
            $servers));
    }

    private static function map_conn(string $server_name, string $vpn_id, array $conn): array
    {
        return [
            "{#SERVERID}" => $vpn_id,
            "{#SERVERNAME}" => $server_name,
            "{#UNIQUEID}" => sprintf("%s+%s", $vpn_id, Util::replace_special_chars($conn['common_name'])),
            "{#USERID}" => Util::replace_special_chars($conn['common_name']),
        ];
    }

    private static function map_conns(string $server_name, string $vpn_id, array $conns): array
    {
        return array_map(
            fn($conn) => self::map_conn($server_name, $vpn_id, $conn),
            $conns);
    }

    private static function map_server(array $server): array
    {
        return self::map_conns(
            self::sanitize_server_name($server["name"]),
            $server["vpnid"],
            $server["conns"]);
    }

    // OpenVPN Server/User-Auth Discovery
    public static function openvpn_server_user()
    {
        $servers = PfzOpenVpn::get_all_openvpn_servers();

        $servers_with_relevant_mode =
            array_filter(
                $servers,
                fn($server) => in_array($server["mode"], ["server_user", "server_tls_user", "server_tls"]));

        $servers_with_conns = array_filter(
            $servers_with_relevant_mode,
            fn($server) => is_array($server["conns"]));

        self::print_json(array_merge(...array_map(fn($s) => self::map_server($s), $servers_with_conns)));
    }

    // OpenVPN Client Discovery
    public static function openvpn_client()
    {
        $clients = PfEnv::openvpn_get_active_clients();

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

    // Services Discovery
    // 2020-03-27: Added space replace with __ for issue #12
    public
    static function services()
    {
        $services = PfEnv::get_services();

        $json_string = '{"data":[';

        foreach ($services as $service) {
            if (!empty($service['name'])) {

                $status = PfEnv::get_service_status($service);
                if ($status = "") $status = 0;

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

    public
    static function interfaces()
    {
        self::discover_interface();
    }

    // IPSEC Discovery
    public
    static function ipsec_ph1()
    {

        require_once("ipsec.inc");
        $config = PfEnv::cfg();
        PfEnv::init_config_arr(array('ipsec', 'phase1'));
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

    public
    static function ipsec_ph2()
    {
        require_once("ipsec.inc");

        $config = PfEnv::cfg();
        PfEnv::init_config_arr(array('ipsec', 'phase2'));
        $a_phase2 = &$config['ipsec']['phase2'];

        $json_string = '{"data":[';

        foreach ($a_phase2 as $data) {
            $json_string .= '{"{#IKEID}":"' . $data['ikeid'] . '"';
            $json_string .= ',"{#NAME}":"' . $data['descr'] . '"';
            $json_string .= ',"{#UNIQID}":"' . $data['uniqid'] . '"';
            $json_string .= ',"{#REQID}":"' . $data['reqid'] . '"';
            $json_string .= ',"{#EXTID}":"' . $data['ikeid'] . '.' . $data['reqid'] . '"';
            $json_string .= '},';
        }

        $json_string = rtrim($json_string, ",");
        $json_string .= "]}";

        echo $json_string;

    }

    public
    static function dhcpfailover()
    {
        //System public static functions regarding DHCP Leases will be available in the upcoming release of pfSense, so let's wait
        require_once("system.inc");
        $leases = PfEnv::system_get_dhcpleases();

        $json_string = '{"data":[';

        if (count($leases['failover']) > 0) {
            foreach ($leases['failover'] as $data) {
                $json_string .= '{"{#FAILOVER_GROUP}":"' . str_replace(" ", "__", $data['name']) . '"';
            }
        }

        $json_string = rtrim($json_string, ",");
        $json_string .= "]}";

        echo $json_string;
    }

    // Interface Discovery
    // Improved performance
    private
    static function discover_interface($is_wan = false, $is_cron = false)
    {
        $ifdescrs = PfEnv::get_configured_interface_with_descr(true);
        $ifaces = PfEnv::get_interface_arr();
        $ifcs = array();
        $if_ret = array();

        $json_string = '{"data":[';

        foreach ($ifdescrs as $ifname => $ifdescr) {
            $ifinfo = PfEnv::get_interface_info($ifname);
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

            if (($is_wan == false) || (($is_wan == true) && (($has_gw == true) || ($has_public_ip == true)) && ($is_vpn == false))) {
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
}

class PfzSpeedtest
{
    // Interface Speedtest
    public static function interface_speedtest_value($if_name, $value)
    {
        $tvalue = explode(".", $value);

        if (count($tvalue) > 1) {
            $value = $tvalue[0];
            $subvalue = $tvalue[1];
        }

        //If the interface has a gateway is considered WAN, so let's do the speedtest
        $filename = "/tmp/speedtest-$if_name";

        if (file_exists($filename)) {
            $speedtest_data = json_decode(file_get_contents($filename), true);

            if (array_key_exists($value, $speedtest_data)) {
                if ($subvalue == false)
                    echo $speedtest_data[$value];
                else
                    echo $speedtest_data[$value][$subvalue];
            }
        }
    }


    // Installs a cron job for speedtests
    public static function speedtest_cron_install($enable = true)
    {
        //Install Cron Job
        $command = "/usr/local/bin/php " . __FILE__ . " speedtest_cron";
        PfEnv::install_cron_job($command, $enable, $minute = "*/15", "*", "*", "*", "*", "root", true);
    }

    public static function speedtest_exec($if_name, $ip_address): bool
    {

        $filename = "/tmp/speedtest-$if_name";
        $filetemp = "$filename.tmp";
        $filerun = "/tmp/speedtest-run";

        // Issue #82
        // Sleep random delay in order to avoid problem when 2 pfSense on the same Internet line
        sleep(rand(1, 90));

        if ((time() - filemtime($filename) > SPEEDTEST_INTERVAL * 3600) || (file_exists($filename) == false)) {
            // file is older than SPEEDTEST_INTERVAL
            if ((time() - filemtime($filerun) > 180)) @unlink($filerun);

            if (file_exists($filerun) == false) {
                touch($filerun);
                $st_command = "/usr/local/bin/speedtest --source $ip_address --json > $filetemp";
                exec($st_command);
                rename($filetemp, $filename);
                @unlink($filerun);
            }
        }

        return true;
    }
}

class PfzOpenVpn
{
    public static function get_all_openvpn_servers()
    {
        $servers = PfEnv::openvpn_get_active_servers();
        $sk_servers = PfEnv::openvpn_get_active_servers("p2p");
        $servers = array_merge($servers, $sk_servers);
        return ($servers);
    }
}

class PfzCommands
{
    public static function discovery($section)
    {
        $is_known_section = in_array(strtolower($section), DISCOVERY_SECTION_HANDLERS);
        if (!$is_known_section) {
            return;
        }

        PfzDiscoveries::{$section}();
    }

    public static function gw_value($gw, $value_key)
    {
        $gws = PfEnv::return_gateways_status(true);
        if (array_key_exists($gw, $gws)) {
            $value = $gws[$gw][$value_key];
            if ($value_key == "status") {
                //Issue #70: Gateway Forced Down
                if ($gws[$gw]["substatus"] <> "none")
                    $value = $gws[$gw]["substatus"];

                $value = self::get_value_mapping("gateway.status", $value);
            }
            echo $value;
        }
    }

    public static function gw_status()
    {
        echo implode(",",
            array_map(
                fn($gw) => sprintf("%s.%s", $gw['name'], $gw['status']),
                PfEnv::return_gateways_status(true)));
    }

    public static function if_speedtest_value($if_name, $value)
    {
        PfzSpeedtest::speedtest_cron_install();
        PfzSpeedtest::interface_speedtest_value($if_name, $value);
    }

    public static function openvpn_servervalue($server_id, $value_key)
    {
        $servers = PfzOpenVpn::get_all_openvpn_servers();

        $maybe_server = Util::array_first($servers, fn($s) => $s['vpnid'] == $server_id);

        $server_value = self::get_server_value($maybe_server, $value_key);

        if ($value_key == "conns") {
            echo is_array($server_value) ? count($server_value) : 0;
            return;
        }

        if (in_array($value_key, ["status", "mode"])) {
            echo self::get_value_mapping("openvpn.server.status", $server_value);
            return;
        }

        echo $server_value;
    }

    public static function openvpn_server_uservalue($unique_id, $value_key)
    {
        return self::get_openvpn_server_uservalue_($unique_id, $value_key);
    }

    public static function openvpn_server_uservalue_numeric($unique_id, $value_key)
    {
        return self::get_openvpn_server_uservalue_($unique_id, $value_key, "0");
    }

    public static function openvpn_clientvalue($client_id, $value_key, $fallback_value = "none")
    {
        $clients = PfEnv::openvpn_get_active_clients();

        $client = Util::array_first($clients, fn($client) => $client['vpnid'] == $client_id);

        if (empty($client)) {
            return $fallback_value;
        }

        $maybe_value = $client[$value_key];

        $is_known_value_key = array_key_exists($value_key, OPENVPN_CLIENT_VALUE);
        if ($is_known_value_key) {
            return OPENVPN_CLIENT_VALUE[$value_key]($maybe_value);
        }

        return ($maybe_value == "") ? $fallback_value : $maybe_value;
    }

    public static function service_value($name, $value)
    {
        $services = PfEnv::get_services();
        $name = str_replace("__", " ", $name);

        // List of service which are stopped on CARP Slave.
        // For now this is the best way i found for filtering out the triggers
        // Waiting for a way in Zabbix to use Global Regexp in triggers with items discovery
        $stopped_on_carp_slave = array("haproxy", "radvd", "openvpn.", "openvpn", "avahi");

        $matching_services = array_filter($services, function ($server, $n) {
            foreach (["id", "zone"] as $key) {
                if (!empty($server[$key])) {
                    return printf("%s.%s", $server["name"], $server[$key]) == $n;
                }
            }

            return false;
        });

        foreach ($matching_services as $service) {
            $short_name = $service["name"];
            $carpcfr = $short_name . ".";

            $is_known_service_value = array_key_exists($value, SERVICES_VALUES);
            if (!$is_known_service_value) {
                echo $service[$value];
                continue;
            }

            echo SERVICES_VALUES[$value]($service, $name, $short_name, $carpcfr, $stopped_on_carp_slave);
        }
    }


    public static function temperature($sensorid)
    {
        exec("sysctl '$sensorid' | cut -d ':' -f 2", $value, $code);
        if ($code != 0 or count($value) != 1) {
            echo "";
            return;
        }

        echo trim($value[0]);
    }

    public static function carp_status($echo = true): int
    {
        //Detect CARP Status
        $config = PfEnv::cfg();
        $status_return = 0;
        $status = PfEnv::get_carp_status();
        $carp_detected_problems = PfEnv::get_single_sysctl("net.inet.carp.demotion");

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
                $if_status = PfEnv::get_carp_interface_status("_vip{$carp['uniqid']}");

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

    // System Information
    public static function system($section)
    {
        if ($section === "packages_update") {
            echo self::get_outdated_packages();
            return;
        }

        $system_pkg_version = PfEnv::get_system_pkg_version();
        $version = $system_pkg_version["version"];
        $installed_version = $system_pkg_version["installed_version"];

        if ($section === "new_version_available") {
            echo Util::b2int($version != $installed_version);
            return;
        }

        if (array_key_exists($section, $system_pkg_version)) {
            echo $system_pkg_version[$section];
        }
    }

    public static function ipsec_ph1($ike_id, $value_key)
    {
        // Get Value from IPsec Phase 1 Configuration
        // If Getting "disabled" value only check item presence in config array
        require_once("ipsec.inc");
        $config = PfEnv::cfg();
        PfEnv::init_config_arr(array('ipsec', 'phase1'));
        $a_phase1 = &$config['ipsec']['phase1'];

        if ($value_key == "status") {
            echo PfzCommands::get_ipsec_status($ike_id);
            return;
        }

        if ($value_key == "disabled") {
            echo "0";
            return;
        }

        $maybe_ike_match = Util::array_first($a_phase1, fn($d) => $d["ikeid"] == $ike_id);
        if (empty($maybe_ike_match)) {
            echo "";
            return;
        }

        if (!array_key_exists($value_key, $maybe_ike_match)) {
            echo "";
            return;
        }

        echo self::get_value_mapping("ipsec." . $value_key, $maybe_ike_match[$value_key]);
    }

    public static function ipsec_ph2($uniqid, $value_key)
    {
        require_once("ipsec.inc");
        $config = PfEnv::cfg();
        PfEnv::init_config_arr(array('ipsec', 'phase2'));
        $a_phase2 = &$config['ipsec']['phase2'];

        $valuecfr = explode(".", $value_key);

        switch ($valuecfr[0]) {
            case 'status':
                $idarr = explode(".", $uniqid);
                $statuskey = "state";
                if (isset($valuecfr[1])) $statuskey = $valuecfr[1];
                $value = self::get_ipsec_status($idarr[0], $idarr[1], $statuskey);
                break;
            case 'disabled':
                $value = "0";
        }

        foreach ($a_phase2 as $data) {
            if ($data['uniqid'] == $uniqid) {
                if (array_key_exists($value_key, $data)) {
                    if ($value_key == 'disabled')
                        $value = "1";
                    else
                        $value = self::get_value_mapping("ipsec_ph2." . $value_key, $data[$value_key], $data[$value_key]);
                    break;
                }
            }
        }
        echo $value;
    }

    public static function dhcp($section)
    {
        if ($section != "failover") {
            return;
        }

        echo PfzCommands::check_dhcp_failover();
    }

    // File is present
    public static function file_exists($filename)
    {
        echo Util::b2int(file_exists($filename));
    }

    public static function speedtest_cron()
    {
        require_once("services.inc");
        $ifdescrs = PfEnv::get_configured_interface_with_descr(true);
        $ifaces = PfEnv::get_interface_arr();
        $pf_interface_name = '';
        $subvalue = false;

        $ifcs = PfzDiscoveries::interface_discovery(true, true);

        foreach ($ifcs as $if_name) {

            foreach ($ifdescrs as $ifn => $ifd) {
                $if_info = PfEnv::get_interface_info($ifn);
                if ($if_info['hwif'] == $if_name) {
                    $pf_interface_name = $ifn;
                    break;
                }
            }

            PfzSpeedtest::speedtest_exec($if_name, $if_info['ipaddr']);
        }
    }

    public static function cron_cleanup()
    {
        PfzSpeedtest::speedtest_cron_install(false);
    }

    // S.M.A.R.T Status
    // Taken from /usr/local/www/widgets/widgets/smart_status.widget.php
    public static function smart_status()
    {
        foreach (PfEnv::get_smart_drive_list() as $dev) { ## for each found drive do                
            $dev_state = trim(exec("smartctl -H /dev/$dev | awk -F: '/^SMART overall-health self-assessment test result/ {print $2;exit}
/^SMART Health Status/ {print $2;exit}'")); ## get SMART state from drive
            $is_known_state = array_key_exists($dev_state, SMART_DEV_STATUS);
            if (!$is_known_state) {
                return SMART_ERROR; // ED This is probably a bug, status should be echoed
            }

            $status = SMART_DEV_STATUS[$dev_state];
            if ($status !== SMART_OK) {
                return $status; // ED This is probably a bug, status should be echoed
            }
        }

        echo SMART_OK;
    }

    public static function cert_date($value_key)
    {
        $config = PfEnv::cfg();

        $value = 0;
        foreach (array("cert", "ca") as $cert_type) {
            switch ($value_key) {
                case "validFrom.max":
                    foreach ($config[$cert_type] as $cert) {
                        $certinfo = openssl_x509_parse(base64_decode($cert[PfEnv::CRT]));
                        if ($value == 0 or $value < $certinfo['validFrom_time_t']) $value = $certinfo['validFrom_time_t'];
                    }
                    break;
                case "validTo.min":
                    foreach ($config[$cert_type] as $cert) {
                        $certinfo = openssl_x509_parse(base64_decode($cert[PfEnv::CRT]));
                        if ($value == 0 or $value > $certinfo['validTo_time_t']) $value = $certinfo['validTo_time_t'];
                    }
                    break;
            }
        }
        echo $value;
    }

    // Testing function, for template creating purpose
    public static function test()
    {
        $line = "-------------------\n";

        $ovpn_servers = PfzOpenVpn::get_all_openvpn_servers();
        echo "OPENVPN Servers:\n";
        print_r($ovpn_servers);
        echo $line;

        $ovpn_clients = PfEnv::openvpn_get_active_clients();
        echo "OPENVPN Clients:\n";
        print_r($ovpn_clients);
        echo $line;

        $ifdescrs = PfEnv::get_configured_interface_with_descr(true);
        $ifaces = array();
        foreach ($ifdescrs as $ifdescr => $ifname) {
            $ifinfo = PfEnv::get_interface_info($ifdescr);
            $ifaces[$ifname] = $ifinfo;
        }
        echo "Network Interfaces:\n";
        print_r($ifaces);
        print_r(PfEnv::get_interface_arr());
        print_r(PfEnv::get_configured_interface_list());
        echo $line;

        $services = PfEnv::get_services();
        echo "Services: \n";
        print_r($services);
        echo $line;

        echo "IPsec: \n";

        require_once("ipsec.inc");
        $config = PfEnv::cfg();
        PfEnv::init_config_arr(array('ipsec', 'phase1'));
        PfEnv::init_config_arr(array('ipsec', 'phase2'));
        $a_phase2 = &$config['ipsec']['phase2'];
        $status = PfEnv::ipsec_list_sa();
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
        $installed_packages = PfEnv::get_pkg_info('all', false, true);
        print_r($installed_packages);
    }

    private static function get_openvpn_server_uservalue_($unique_id, $value_key, $default = "")
    {
        $unique_id = Util::replace_special_chars($unique_id, true);
        $atpos = strpos($unique_id, '+');
        $server_id = substr($unique_id, 0, $atpos);
        $user_id = substr($unique_id, $atpos + 1);

        $servers = PfzOpenVpn::get_all_openvpn_servers();
        foreach ($servers as $server) {
            if ($server['vpnid'] == $server_id) {
                foreach ($server['conns'] as $conn) {
                    if ($conn['common_name'] == $user_id) {
                        $value = $conn[$value_key];
                    }
                }
            }
        }

        return ($value == "") ? $default : $value;
    }

    private static function get_server_value($maybe_server, $value_key)
    {
        if (empty($maybe_server)) {
            return null;
        }

        $raw_value = $maybe_server[$value_key];

        if (in_array($maybe_server["mode"], ["server_user", "server_tls_user", "server_tls"])) {
            return $raw_value == "" ? "server_user_listening" : $raw_value;
        }

        if ($maybe_server["mode"] == "p2p_tls") {
            // For p2p_tls, ensure we have one client, and return up if it's the case
            if ($raw_value == "") {
                $has_at_least_one_connection =
                    is_array($maybe_server["conns"]) && count($maybe_server["conns"]) > 0;

                return $has_at_least_one_connection ? "up" : "down";
            }
        }

        return $raw_value;
    }

    private static function get_ipsec_status($ike_id, $req_id = -1, $value_key = 'state')
    {

        require_once("ipsec.inc");
        $config = PfEnv::cfg();
        PfEnv::init_config_arr(array('ipsec', 'phase1'));

        $a_phase1 = &$config['ipsec']['phase1'];
        $conmap = array();
        foreach ($a_phase1 as $ph1ent) {
            if (function_exists('get_ipsecifnum')) {
                if (PfEnv::get_ipsecifnum($ph1ent['ikeid'], 0)) {
                    $cname = "con" . PfEnv::get_ipsecifnum($ph1ent['ikeid'], 0);
                } else {
                    $cname = "con{$ph1ent['ikeid']}00000";
                }
            } else {
                $cname = ipsec_conid($ph1ent);
            }
            $conmap[$cname] = $ph1ent['ikeid'];
        }

        $status = PfEnv::ipsec_list_sa();
        $ipsecconnected = array();

        $carp_status = self::carp_status(false);

        //Phase-Status match borrowed from status_ipsec.php	
        if (is_array($status)) {
            foreach ($status as $l_ikeid => $ikesa) {

                if (isset($ikesa['con-id'])) {
                    $con_id = substr($ikesa['con-id'], 3);
                } else {
                    $con_id = filter_var($ike_id, FILTER_SANITIZE_NUMBER_INT);
                }
                $con_name = "con" . $con_id;
                if ($ikesa['version'] == 1) {
                    $ph1idx = $conmap[$con_name];
                    $ipsecconnected[$ph1idx] = $ph1idx;
                } else {
                    if (!PfEnv::ipsec_ikeid_used($con_id)) {
                        // probably a v2 with split connection then
                        $ph1idx = $conmap[$con_name];
                        $ipsecconnected[$ph1idx] = $ph1idx;
                    } else {
                        $ipsecconnected[$con_id] = $ph1idx = $con_id;
                    }
                }
                if ($ph1idx == $ike_id) {
                    if ($req_id != -1) {
                        // Asking for Phase2 Status Value
                        foreach ($ikesa['child-sas'] as $childsas) {
                            if ($childsas['reqid'] == $req_id) {
                                if (strtolower($childsas['state']) == 'rekeyed') {
                                    //if state is rekeyed go on
                                    $tmp_value = $childsas[$value_key];
                                } else {
                                    $tmp_value = $childsas[$value_key];
                                    break;
                                }
                            }
                        }
                    } else {
                        $tmp_value = $ikesa[$value_key];
                    }

                    break;
                }
            }
        }

        if ($value_key == "state") {
            $v = self::get_value_mapping('ipsec.state', strtolower($tmp_value));

            return ($carp_status != 0) ? $v + (10 * ($carp_status - 1)) : $v;
        }

        return $tmp_value;
    }

    // DHCP Checks (copy of status_dhcp_leases.php, waiting for pfsense 2.5)
    private static function remove_duplicates($array, $field): array
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
    private static function get_dhcp($value_key)
    {


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
                        $pools[$p]['name'] = "{$pools[$p]['name']} (" . PfEnv::convert_friendly_interface_to_friendly_descr(substr($pools[$p]['name'], 5)) . ")";
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
            $leases = self::remove_duplicates($leases, "ip");
        }

        if (count($pools) > 0) {
            $pools = self::remove_duplicates($pools, "name");
            asort($pools);
        }

        switch ($value_key) {
            case "pools":
                return $pools;
                break;
            case "failover":
                return $failover;
                break;
            case "leases":
            default:
                return $leases;
        }

    }

    private static function check_dhcp_failover()
    {
        // Check DHCP Failover Status
        // Returns number of failover pools which state is not normal or
        // different than peer state
        $failover = self::get_dhcp("failover");

        return count(array_filter($failover, fn($f) => ($f["mystate"] != "normal") || ($f["mystate"] != $f["peerstate"])));
    }

    private static function get_outdated_packages()
    {
        require_once("pkg-utils.inc");
        $installed_packages = PfEnv::get_pkg_info("all", false, true);


        return count(array_filter(
            $installed_packages,
            fn($p) => $p["version"] != $p["installed_version"]));
    }

    // Value mappings
    // Each value map is represented by an associative array
    private static function get_value_mapping($value_name, $value, $default_value = "0")
    {
        $is_known_value_name = array_key_exists($value_name, VALUE_MAPPINGS);
        if (!$is_known_value_name) {
            return $default_value;
        }

        $value_mapping = VALUE_MAPPINGS[$value_name];
        if (!is_array($value_mapping)) {
            return $default_value;
        }

        $value = strtolower($value);
        $is_value_with_known_mapping = array_key_exists($value, $value_mapping);

        return $is_value_with_known_mapping ? $value_mapping[$value] : $default_value;
    }
}

function build_method_lookup(string $clazz): array
{
    try {
        $reflector = new ReflectionClass($clazz);

        $all_methods = $reflector->getMethods();

        $commands = array_filter($all_methods, fn($method) => $method->isStatic() && $method->isPublic());

        return array_map(fn(ReflectionMethod $method) => $method->getName(), $commands);
    } catch (Exception $e) {
        return [];
    }
}

function main($arguments)
{
    $command = strtolower($arguments[1]);
    $parameters = array_slice($arguments, 2);


    if ($command == "help") {
        print_r(COMMAND_HANDLERS);
        exit;
    }

    $is_known_command = in_array($command, COMMAND_HANDLERS);

    if (!$is_known_command) {
        PfzCommands::test();
        exit;
    }

    PfzCommands::{$command}(...$parameters);
}

main($argv);
