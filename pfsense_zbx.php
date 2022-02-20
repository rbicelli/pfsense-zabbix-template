<?php
/**
 * pfsense_zbx.php - pfSense Zabbix Interface
 * Version 1.1.1 - 2021-10-24
 *
 * Written by Riccardo Bicelli <r.bicelli@gmail.com>
 * This program is licensed under Apache 2.0 License
 */

namespace RBicelli\Pfz;

require_once("config.inc");
require_once("functions.inc");
require_once("globals.inc");
require_once("interfaces.inc");
require_once("ipsec.inc");
require_once("openvpn.inc");
require_once("pkg-utils.inc");
require_once("service-utils.inc");
require_once("services.inc");
require_once("system.inc");
require_once("util.inc");

define("COMMAND_HANDLERS", build_method_lookup(PfzCommands::class));

define('DISCOVERY_SECTION_HANDLERS', build_method_lookup(PfzDiscoveries::class));

define('SERVICES_VALUES', build_method_lookup(PfzServices::class));

define("TEXT_ACTIVE", gettext("active"));
define("TEXT_DYNAMIC", gettext("dynamic"));
define("TEXT_EXPIRED", gettext("expired"));
define("TEXT_NEVER", gettext("Never"));
define("TEXT_OFFLINE", gettext("offline"));
define("TEXT_ONLINE", gettext("online"));
define("TEXT_RESERVED", gettext("reserved"));

const SPEEDTEST_INTERVAL_HOURS = 8;
const SPEEDTEST_INTERVAL_SECONDS = SPEEDTEST_INTERVAL_HOURS * 3600;

const VALUE_MAPPINGS = [
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
        "rekeyed" => 2]];

const CERT_VK_TO_FIELD = [
    "validFrom.max" => "validFrom_time_t",
    "validTo.min" => "validTo_time_t",
];

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

const CARP_INCONSISTENT = "INCONSISTENT";
const CARP_MASTER = "MASTER";

const CARP_STATUS_DISABLED = 0;
const CARP_STATUS_OK = 1;
const CARP_STATUS_UNKNOWN = 2;
const CARP_STATUS_INCONSISTENT = 3;
const CARP_STATUS_PROBLEM = 4;

const CARP_RES = [
    CARP_INCONSISTENT => CARP_STATUS_INCONSISTENT,
    CARP_MASTER => CARP_STATUS_OK
];

class PfzServices
{
    public static function enabled($service, $name, $short_name): int
    {
        return Util::b2int(PfEnv::is_service_enabled($short_name));
    }

    public static function name($service, string $name)
    {
        echo $name;
    }

    public static function status(string $service): int
    {
        $status = PfEnv::get_service_status($service);

        return ($status == "") ? 0 : $status;

    }

    public static function run_on_carp_slave($service, $name, $short_name, $carpcfr, $stopped_on_carp_slave): int
    {
        return Util::b2int(in_array($carpcfr, $stopped_on_carp_slave));
    }
}

// Abstract undefined symbols and globals from code
class PfEnv
{
    public const CRT = crt;

    public static function cfg()
    {
        global $config;

        return $config;
    }

    public static function g()
    {
        global $g;

        return $g;
    }

    private static function call_pfsense_method_with_same_name_and_arguments()
    {
        $caller_function_name = debug_backtrace()[1]['function'];

        return call_user_func_array($caller_function_name, ...func_get_args());
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
    public static function array_first(array $haystack, \Closure $match)
    {
        foreach ($haystack as $needle) {
            if ($match($needle)) {
                return $needle;
            }
        }

        return null;
    }

    public static function array_flatten(array $multi_dimensional_array): array
    {
        return array_merge(...$multi_dimensional_array);
    }

    public static function array_zip(array $keys, array $values): array
    {
        return array_map(null, $keys, $values);
    }

    public static function b2int(bool $b): int
    {
        return (int)$b;
    }

    public static function result($result, bool $echo_result = false)
    {
        if ($echo_result) {
            echo $echo_result;
        }

        return $result;
    }
}

class PfzInterfaces
{
    public static function retrieve_wan_interfaces(): array
    {
        $if_descriptions = PfEnv::get_configured_interface_with_descr(true);

        $interfaces = array_map(function ($interface) {
            list ($if_name, $description) = $interface;

            return array_merge(
                PfEnv::get_interface_info($if_name),
                ["description" => $description],
            );
        }, Util::array_zip(array_keys($if_descriptions), array_values($if_descriptions)));

        return array_filter($interfaces, function ($iface_info_ext) {
            $has_gw = array_key_exists("gateway", $iface_info_ext);
            //	Issue #81 - https://stackoverflow.com/a/13818647/15093007
            $has_public_ip =
                filter_var(
                    $iface_info_ext["ipaddr"],
                    FILTER_VALIDATE_IP,
                    FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
            $is_vpn = strpos($iface_info_ext["if"], "ovpn") !== false;

            return ($has_gw || $has_public_ip) && !$is_vpn;
        });
    }
}

class PfzDiscoveries
{
    public static function gw()
    {
        $gws = PfEnv::return_gateways_status(true);

        self::print_json(array_map(fn($gw) => ["{#GATEWAY}" => $gw["name"]], $gws));
    }

    public static function wan()
    {
        self::discover_interface(true);
    }

    private static function sanitize_server_name(string $raw_name): string
    {
        return trim(preg_replace('/\w{3}(\d)?\:\d{4,5}/i', '', $raw_name));
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

    public static function openvpn_server()
    {
        $servers = PfzOpenVpn::get_all_openvpn_servers();

        self::print_json(array_map(fn($server) => [
            "{#SERVER}" => $server["vpnid"],
            "{#NAME}" => self::sanitize_name($server["name"])],
            $servers));
    }

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

        self::print_json(Util::array_flatten(array_map(fn($s) => self::map_server($s), $servers_with_conns)));
    }

    public static function openvpn_client()
    {
        self::print_json(array_map(fn($client) => [
            "{#CLIENT}" => $client['vpnid'],
            "{#NAME}", self::sanitize_name($client["name"]),
        ], PfEnv::openvpn_get_active_clients()));
    }

    public static function services()
    {
        $named_services = array_filter(PfEnv::get_services(), fn($service) => !empty($service['name']));

        self::print_json(array_map(function ($service) {
            $maybe_id = Util::array_first(array_keys($service), fn($key) => in_array($key, ["id", "zone"]));
            $id = is_null($maybe_id) ? "" : $service[$maybe_id];

            return [
                "{#SERVICE}" => str_replace(" ", "__", $service['name']) . $id,
                "{#DESCRIPTION}" => $service['description'],
            ];
        }, $named_services));
    }

    public static function interfaces()
    {
        self::discover_interface();
    }

    public static function ipsec_ph1()
    {
        $config = PfEnv::cfg();
        PfEnv::init_config_arr(array('ipsec', 'phase1'));
        $a_phase1 = &$config['ipsec']['phase1'];

        self::print_json(array_map(fn($data) => [
            "{#IKEID}" => $data['ikeid'],
            "{#NAME}" => $data['descr'],
        ], $a_phase1));
    }

    public static function ipsec_ph2()
    {
        $config = PfEnv::cfg();
        PfEnv::init_config_arr(array('ipsec', 'phase2'));
        $a_phase2 = &$config['ipsec']['phase2'];

        self::print_json(array_map(fn($data) => [
            "{#IKEID}" => $data['ikeid'],
            "{#NAME}" => $data['descr'],
            "{#UNIQID}" => $data['uniqid'],
            "{#REQID}" => $data['reqid'],
            "{#EXTID}" => $data['ikeid'] . '.' . $data['reqid'],
        ], $a_phase2));
    }

    public static function dhcpfailover()
    {
        // System public static functions regarding DHCP Leases will be available in the upcoming release of pfSense, so let's wait
        $leases = PfEnv::system_get_dhcpleases();

        self::print_json(array_map(fn($data) => [
            "{#FAILOVER_GROUP}" => str_replace(" ", "__", $data['name']),
        ], $leases["failover"]));

    }

    private static function print_json(array $json)
    {
        echo json_encode([
            "data" => $json
        ]);
    }

    private static function sanitize_name(string $raw_name): string
    {
        return trim(preg_replace('/\w{3}(\d)?:\d{4,5}/i', '', $raw_name));
    }

    private static function map_conn(string $server_name, string $vpn_id, array $conn): array
    {
        return [
            "{#SERVERID}" => $vpn_id,
            "{#SERVERNAME}" => $server_name,
            "{#UNIQUEID}" => sprintf("%s+%s", $vpn_id, $conn["common_name"]),
            "{#USERID}" => $conn["common_name"],
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
            self::sanitize_name($server["name"]),
            $server["vpnid"],
            $server["conns"]);
    }

    private static function discover_interface($is_wan = false)
    {
        if (!$is_wan) {
            self::print_json([]);
            return;
        }

        self::print_json(array_map(function ($hwif) {
            return [
                "{#IFNAME}" => $hwif['hwif'],
                "{#IFDESCR}" => $hwif["description"],
            ];
        }, PfzInterfaces::retrieve_wan_interfaces()));
    }
}

class PfzSpeedtest
{
    public static function interface_value($if_name, $value)
    {
        list($tv0, $tv1) = explode(".", $value);

        $filename = self::if_filename($if_name);
        if (!file_exists($filename)) {
            return;
        }

        $speedtest_data = json_decode(file_get_contents($filename), true);
        if (array_key_exists($value, $speedtest_data)) {
            return;
        }

        echo empty($tv1) ? $speedtest_data[$value] : $speedtest_data[$tv0][$tv1];
    }

    public static function cron_install($enable = true)
    {
        $command = "/usr/local/bin/php " . __FILE__ . " speedtest_cron";
        PfEnv::install_cron_job($command, $enable, "*/15", "*", "*", "*", "*", "root", true);
    }

    public static function exec($if_name, $ip_address)
    {
        $output_file_path = self::if_filename($if_name);
        $tmp_file_path = tempnam(sys_get_temp_dir(), "");

        // Issue #82
        // Sleep random delay in order to avoid problem when 2 pfSense on the same Internet line
        sleep(rand(1, 90));

        $is_output_file_older_than_interval =
            file_exists($output_file_path) &&
            (time() - filemtime($output_file_path) > SPEEDTEST_INTERVAL_SECONDS);
        if (!$is_output_file_older_than_interval) {
            return;
        }

        $st_command = "/usr/local/bin/speedtest --source $ip_address --json > $tmp_file_path";
        exec($st_command);
        rename($tmp_file_path, $output_file_path);
    }

    private static function if_filename($if_name): string
    {
        return implode(DIRECTORY_SEPARATOR, [sys_get_temp_dir(), "speedtest-$if_name"]);
    }
}

class PfzOpenVpn
{
    public static function get_all_openvpn_servers(): array
    {
        $servers = PfEnv::openvpn_get_active_servers();
        $sk_servers = PfEnv::openvpn_get_active_servers("p2p");

        return array_merge($servers, $sk_servers);
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

        $is_known_gw = array_key_exists($gw, $gws);
        if (!$is_known_gw) {
            return;
        }

        $value = $gws[$gw][$value_key];
        if ($value_key != "status") {
            echo $value;
            return;
        }

        // Issue #70: Gateway Forced Down
        $v = ($gws[$gw]["substatus"] != "none") ? $gws[$gw]["substatus"] : $value;

        echo self::get_value_mapping("gateway.status", $v);
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
        PfzSpeedtest::cron_install();
        PfzSpeedtest::interface_value($if_name, $value);
    }

    public static function openvpn_servervalue(int $server_id, $value_key)
    {
        $servers = PfzOpenVpn::get_all_openvpn_servers();

        $maybe_server = Util::array_first($servers, fn($s) => $s["vpnid"] == $server_id);

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

    public static function carp_status($echo_result = true): int
    {
        $config = PfEnv::cfg();
        $carp_status = PfEnv::get_carp_status();
        $carp_detected_problems = PfEnv::get_single_sysctl("net.inet.carp.demotion");

        $is_carp_enabled = $carp_status != 0;
        if (!$is_carp_enabled) { // CARP is disabled
            return Util::result(CARP_STATUS_DISABLED, $echo_result);
        }

        if ($carp_detected_problems != 0) {
            // There's some Major Problems with CARP
            return Util::result(CARP_STATUS_PROBLEM, $echo_result);
        }

        $virtual_ips = $config['virtualip']['vip'];
        $just_carps = array_filter($virtual_ips, fn($virtual_ip) => $virtual_ip['mode'] != "carp");
        $status_str = array_reduce($just_carps, function ($status, $carp) {
            $if_status = PfEnv::get_carp_interface_status("_vip{$carp['uniqid']}");

            $state_differs_from_previous_interface = ($status != $if_status) && (!empty($if_status));
            if (!$state_differs_from_previous_interface) {
                return $status;
            }

            if ($status != "") {
                return CARP_INCONSISTENT;
            }

            return $if_status;
        }, "");

        $is_known_carp_status = array_key_exists($status_str, CARP_RES);

        $result = $is_known_carp_status ? CARP_RES[$status_str] : CARP_STATUS_UNKNOWN;

        return Util::result($result, $echo_result);
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
        $config = PfEnv::cfg();
        PfEnv::init_config_arr(['ipsec', 'phase1']);
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
        $config = PfEnv::cfg();
        PfEnv::init_config_arr(array('ipsec', 'phase2'));
        $a_phase2 = &$config['ipsec']['phase2'];

        $valuecfr = explode(".", $value_key);

        $value = "0";
        if ($valuecfr[0] == 'status') {
            $ids = explode(".", $uniqid);
            $status_key = (isset($valuecfr[1])) ? $valuecfr[1] : "state";
            $value = self::get_ipsec_status($ids[0], $ids[1], $status_key);
        }

        $maybe_data = Util::array_first($a_phase2, fn($data) => $data['uniqid'] == $uniqid);
        if (is_null($maybe_data) || !array_key_exists($value_key, $maybe_data)) {
            return Util::result($value, true);
        }

        $result = ($value_key != 'disabled') ?
            self::get_value_mapping("ipsec_ph2." . $value_key, $maybe_data[$value_key]) :
            "1";

        return Util::result($result, true);
    }

    public static function dhcp($section)
    {
        if ($section != "failover") {
            return;
        }

        echo self::check_dhcp_failover();
    }

    // File is present
    public static function file_exists($filename)
    {
        echo Util::b2int(file_exists($filename));
    }

    public static function speedtest_cron()
    {
        foreach (PfzInterfaces::retrieve_wan_interfaces() as $if_info) {
            PfzSpeedtest::exec($if_info["hwif"], $if_info["ipaddr"]);
        }
    }

    public static function cron_cleanup()
    {
        PfzSpeedtest::cron_install(false);
    }

    // S.M.A.R.T Status
    // Taken from /usr/local/www/widgets/widgets/smart_status.widget.php
    public static function smart_status()
    {
        $dev_states = array_map(
            fn($dev) => trim(exec("smartctl -H /dev/$dev | awk -F: '/^SMART overall-health self-assessment test result/ {print $2;exit}
/^SMART Health Status/ {print $2;exit}'")),
            PfEnv::get_smart_drive_list());

        $maybe_not_ok = Util::array_first($dev_states, function ($dev_state) {
            $is_ok =
                array_key_exists($dev_state, SMART_DEV_STATUS) &&
                SMART_DEV_STATUS[$dev_state] == SMART_OK;

            return !$is_ok;
        });

        return Util::result($maybe_not_ok ?: SMART_OK, true);
    }

    public static function cert_date($value_key)
    {
        if (!array_key_exists($value_key, CERT_VK_TO_FIELD)) {
            return Util::result(0, true);
        }

        $field = CERT_VK_TO_FIELD[$value_key];
        $config = PfEnv::cfg();
        $all_certs = Util::array_flatten(array_map(fn($cert_type) => $config[$cert_type], ["cert", "ca"]));

        return Util::result(array_reduce($all_certs, function ($value, $certificate) use ($field) {
            $cert_info = openssl_x509_parse(base64_decode($certificate[PfEnv::CRT]));

            return ($value == 0 || $value < $cert_info[$field]) ? $cert_info[$field] : $value;
        }, 0));
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
        $ifaces = [];
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

        $config = PfEnv::cfg();
        PfEnv::init_config_arr(array('ipsec', 'phase1'));
        PfEnv::init_config_arr(array('ipsec', 'phase2'));
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
        $installed_packages = PfEnv::get_pkg_info('all', false, true);
        print_r($installed_packages);
    }

    private static function get_openvpn_server_uservalue_($unique_id, $value_key, $default = "")
    {
        $unique_id = Util::replace_special_chars($unique_id, true);

        list($server_id, $user_id) = explode("+", $unique_id);

        $servers = PfzOpenVpn::get_all_openvpn_servers();
        $maybe_server = Util::array_first($servers, fn($server) => $server['vpnid'] == $server_id);

        if (!$maybe_server) {
            return $default;
        }

        $maybe_conn = Util::array_first($maybe_server["conns"], fn($conn) => ($conn['common_name'] == $user_id));

        return $maybe_conn[$value_key] ?: $default;
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

        // For p2p_tls, ensure we have one client, and return up if it's the case
        if ($maybe_server["mode"] == "p2p_tls" && $raw_value == "") {
            $has_at_least_one_connection =
                is_array($maybe_server["conns"]) && count($maybe_server["conns"]) > 0;

            return $has_at_least_one_connection ? "up" : "down";
        }

        return $raw_value;
    }

    private static function get_ipsec_status($ike_id, $req_id = -1, $value_key = "state")
    {
        PfEnv::init_config_arr(array("ipsec", "phase1"));

        $result = "";

        $process_result = function ($vk, $r) {
            if ($vk != "state") {
                return $r;
            }

            $v = self::get_value_mapping("ipsec.state", strtolower($r));

            $carp_status = self::carp_status(false);

            return ($carp_status != 0) ? $v + (10 * ($carp_status - 1)) : $v;
        };

        $ipsec_list_sa = PfEnv::ipsec_list_sa();
        if (!is_array($ipsec_list_sa)) {
            return $process_result($value_key, $result);
        }

        $config = PfEnv::cfg();

        $connection_map = array_reduce($config["ipsec"]["phase1"], function ($p, $ph1ent) {
            $ike_id = $ph1ent["ikeid"];

            if (function_exists('get_ipsecifnum')) {
                $id_name = (PfEnv::get_ipsecifnum($ike_id, 0));

                $cname = $id_name ? "con$id_name" : "con{$ike_id}00000";
            } else {
                $cname = ipsec_conid($ph1ent);
            }

            return [
                ...$p,
                $cname => $ph1ent[$ike_id],
            ];
        }, []);

        // Phase-Status match borrowed from status_ipsec.php	
        $maybe_ike_sa = Util::array_first($ipsec_list_sa, function ($ike_sa) use ($ike_id, $connection_map) {
            $con_id = isset($ike_sa["con-id"]) ?
                substr($ike_sa["con-id"], 3) :
                filter_var($ike_id, FILTER_SANITIZE_NUMBER_INT);

            $con_name = "con$con_id";

            $is_version_1 = $ike_sa['version'] == 1;
            $is_split_connection = !$is_version_1 && !PfEnv::ipsec_ikeid_used($con_id);

            $ph1idx = ($is_version_1 || $is_split_connection) ? $connection_map[$con_name] : $con_id;

            return $ph1idx == $ike_id;
        });

        if (!$maybe_ike_sa) {
            return $process_result($value_key, $result);
        }

        $just_matching_child_sas =
            array_filter($maybe_ike_sa["child-sas"], fn($child_sa) => ($child_sa["reqid"] == $req_id));

        // Asking for Phase2 Status Value
        foreach ($just_matching_child_sas as $child_sa) {
            $result = $child_sa[$value_key];

            // If state is rekeyed go on
            if (strtolower($child_sa["state"]) == "rekeyed") {
                break;
            }
        }

        return $process_result($value_key, $result);
    }

    // DHCP Checks (copy of status_dhcp_leases.php, waiting for pfsense 2.5)
    private static function remove_duplicates($array, $field): array
    {
        $cmp = [];
        $new = [];

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
        $g = PfEnv::g();

        $leases_file = "{$g['dhcpd_chroot_path']}/var/db/dhcpd.leases";

        $awk = "/usr/bin/awk";
        /* this pattern sticks comments into a single array item */
        $clean_pattern = "'{ gsub(\"#.*\", \"\");} { gsub(\";\", \"\"); print;}'";
        /* We then split the leases file by } */
        $split_pattern = "'BEGIN { RS=\"}\";} {for (i=1; i<=NF; i++) printf \"%s \", \$i; printf \"}\\n\";}'";

        /* stuff the leases file in a proper format into a array by line */
        @exec("/bin/cat {$leases_file} 2>/dev/null| {$awk} {$clean_pattern} | {$awk} {$split_pattern}", $leases_content);
        $leases_count = count($leases_content);
        @exec("/usr/sbin/arp -an", $rawdata);

        $failover = [];
        $leases = [];
        $pools = [];
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
                        $leases[$l]['type'] = TEXT_DYNAMIC;
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
                            $leases[$l]['end'] = TEXT_NEVER;
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
                                $leases[$l]['act'] = TEXT_ACTIVE;
                                break;
                            case "free":
                                $leases[$l]['act'] = TEXT_EXPIRED;
                                $leases[$l]['online'] = TEXT_OFFLINE;
                                break;
                            case "backup":
                                $leases[$l]['act'] = TEXT_RESERVED;
                                $leases[$l]['online'] = TEXT_OFFLINE;
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
                        $arpdata_ip = [];
                        /* check if it's online and the lease is active */
                        $leases[$l]['online'] =
                            (in_array($leases[$l]['ip'], $arpdata_ip)) ? TEXT_ONLINE : TEXT_OFFLINE;
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

        $rs = compact("pools", "failover", "leases");
        $is_known_value_key = array_key_exists($value_key, $rs);

        return ($is_known_value_key) ? $rs[$value_key] : $leases;
    }

    private static function check_dhcp_failover(): int
    {
        // Check DHCP Failover Status
        // Returns number of failover pools which state is not normal or
        // different than peer state
        $failover = self::get_dhcp("failover");

        return count(array_filter($failover, fn($f) => ($f["mystate"] != "normal") || ($f["mystate"] != $f["peerstate"])));
    }

    private static function get_outdated_packages(): int
    {
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
        $reflector = new \ReflectionClass($clazz);

        $all_methods = $reflector->getMethods();

        $commands = array_filter($all_methods, fn($method) => $method->isStatic() && $method->isPublic());

        return array_map(fn(\ReflectionMethod $method) => $method->getName(), $commands);
    } catch (\Exception $e) {
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
