<?php
/**
 * pfsense_zbx.php - pfSense Zabbix Interface
 * Version 1.1.1 - 2021-10-24
 *
 * Written by Riccardo Bicelli <r.bicelli@gmail.com>
 * This program is licensed under Apache 2.0 License
 */

namespace RBicelli\Pfz;

use Closure;
use Exception;
use ReflectionClass;
use ReflectionMethod;

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

define("COMMAND_HANDLERS", build_method_lookup(Command::class));
define("DISCOVERY_SECTION_HANDLERS", build_method_lookup(Discovery::class));
define("SERVICES_VALUE_HANDLERS", build_method_lookup(Service::class));

define("TEXT_ACTIVE", gettext("active"));
define("TEXT_DYNAMIC", gettext("dynamic"));
define("TEXT_EXPIRED", gettext("expired"));
define("TEXT_NEVER", gettext("Never"));
define("TEXT_OFFLINE", gettext("offline"));
define("TEXT_ONLINE", gettext("online"));
define("TEXT_RESERVED", gettext("reserved"));

const SPEED_TEST_INTERVAL_HOURS = 8;
const SPEED_TEST_INTERVAL_SECONDS = SPEED_TEST_INTERVAL_HOURS * 3600;
const SPEED_TEST_RANDOM_DELAY_MIN_SECONDS = 1;
const SPEED_TEST_RANDOM_DELAY_MAX_SECONDS = 90;

const FALLBACK_VALUE = 0;

const LINE = "-------------------\n";

const VALUE_MAPPINGS = [
    "openvpn.server.status" => [
        "down" => 0,
        "up" => 1,
        "none" => 2,
        "reconnecting; ping-restart" => 3,
        "waiting" => 4,
        "server_user_listening" => 5],
    "openvpn.client.status" => [
        "connected" => 1,
        "up" => 1,
        "down" => 0,
        "none" => 0,
        "reconnecting; ping-restart" => 2],
    "openvpn.server.mode" => [
        "p2p_tls" => 1,
        "p2p_shared_key" => 2,
        "server_tls" => 3,
        "server_user" => 4,
        "server_tls_user" => 5],
    "gateway.status" => [
        "online" => 0,
        "none" => 0,
        "loss" => 1,
        "highdelay" => 2,
        "highloss" => 3,
        "force_down" => 4,
        "down" => 5],
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

// Abstract undefined symbols and globals from code
class PfEnv
{
    public const CRT = crt;

    public static function cfg()
    {
        global $config;

        return $config;
    }

    public static function g($key)
    {
        global $g;

        return $g[$key];
    }

    private static function call_pfsense_method_with_same_name_and_arguments()
    {
        $caller_function_name = debug_backtrace()[1]["function"];

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
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args()) ?: [];
    }

    public static function get_smart_drive_list()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args()) ?: [];
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
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args()) ?: [];
    }

    public static function is_service_enabled()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args());
    }

    public static function openvpn_get_active_clients()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args()) ?: [];
    }

    public static function openvpn_get_active_servers()
    {
        return self::call_pfsense_method_with_same_name_and_arguments(func_get_args()) ?: [];
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
    public static function array_first(Closure $match, array $haystack)
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
        return array_merge(...$multi_dimensional_array) ?: [];
    }

    public static function b2int(bool $b): int
    {
        return (int)$b;
    }

    public static function result($result, bool $echo_result = true)
    {
        if ($echo_result) {
            echo $result;
        }

        return $result;
    }

    public static function space_to_underscore($value)
    {
        return str_replace(" ", "__", $value);
    }

    public static function underscore_to_space($value)
    {
        return str_replace("__", " ", $value);
    }
}

class NetworkInterface
{
    public static function retrieve_wan_interfaces(): array
    {
        $interfaces = [];

        foreach (PfEnv::get_configured_interface_with_descr(true) as $if_name => $description) {
            $interfaces[] = array_merge(
                PfEnv::get_interface_info($if_name),
                ["description" => $description],
            );
        }

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

class Shell
{
    const ARP = "/usr/sbin/arp";
    const AWK = "/usr/bin/awk";
    const CAT = "/bin/cat";
    const SMART_CTL = "/usr/local/sbin/smartctl";
    const SPEED_TEST = "/usr/local/bin/speedtest";

    public static function run_speed_test(string $source_ip_address, string $output_file_path)
    {
        $tmp_file_path = tempnam(sys_get_temp_dir(), "speedtest.");

        exec(implode(" ", [self::SPEED_TEST, "--source", $source_ip_address, "--json", ">", $tmp_file_path]));

        rename($tmp_file_path, $output_file_path);
    }

    public static function read_smart_status(string $device_name): string
    {
        return trim(exec(
            implode(" ",
                [
                    self::SMART_CTL, "-H", "/dev/$device_name", "|",
                    self::AWK, "-F:", "'/^SMART overall-health self-assessment test result/ {print $2;exit} /
                    ^SMART Health Status/ {print $2;exit}'"])));
    }

    public static function read_dhcpd_records(string $leases_file_path): array
    {
        // Remove all content up to the first lease record
        $clean_pattern = "'/lease.*{\$/,0'";

        // Split file into records by '}'
        $split_pattern = "'BEGIN { RS=ORS=\"}\" } { gsub(\"\\n\", \"\"); print; printf \"\\n\"}'";

        // Stuff the leases file in a proper format into an array by line
        exec(
            implode(" ",
                [
                    self::CAT, $leases_file_path, "2>/dev/null", "|",
                    self::AWK, $clean_pattern, "|",
                    self::AWK, $split_pattern]), $raw_lease_records);

        return array_filter($raw_lease_records, fn($r) => preg_match("/^lease.*|^failover.*/", $r));
    }

    public static function read_arp_ips(): array
    {
        exec(implode(" ", [
            self::ARP, "-an", "|",
            self::AWK, "'{ gsub(/[()]/,\"\") } {print $2}'"]), $arp_data);

        return $arp_data;
    }
}

class Service
{
    public static function enabled(array $service, $name, $short_name): int
    {
        return Util::b2int(PfEnv::is_service_enabled($short_name));
    }

    public static function name(array $service, string $name): string
    {
        return $name;
    }

    public static function status(array $service): int
    {
        $status = PfEnv::get_service_status($service);

        if (!empty($status)) {
            return $status;
        }

        return FALLBACK_VALUE;
    }

    public static function run_on_carp_slave(array $service, $name, $short_name, $carpcfr, $stopped_on_carp_slave): int
    {
        return Util::b2int(in_array($carpcfr, $stopped_on_carp_slave));
    }
}

class Discovery
{
    public static function gw()
    {
        $gateway_discoveries = [];
        foreach (PfEnv::return_gateways_status(true) as $gateway) {
            $gateway_discoveries[] = ["{#GATEWAY}" => $gateway["name"]];
        }

        self::print_json($gateway_discoveries);
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
        $active_openvpn_server_discoveries = [];
        foreach (OpenVpn::get_active_servers() as $server) {
            $active_openvpn_server_discoveries[] = [
                "{#SERVER}" => $server["vpnid"],
                "{#NAME}" => self::sanitize_name($server["name"]),
            ];
        }

        self::print_json($active_openvpn_server_discoveries);
    }

    public static function openvpn_server_user()
    {
        $servers_with_relevant_mode =
            array_filter(
                OpenVpn::get_active_servers(),
                fn($server) => in_array($server["mode"], ["server_user", "server_tls_user", "server_tls"]));

        $servers_with_conns = array_filter(
            $servers_with_relevant_mode,
            fn($server) => is_array($server["conns"]));

        $server_discoveries = [];
        foreach ($servers_with_conns as $server) {
            $server_discoveries[] = self::map_server($server);
        }

        self::print_json(Util::array_flatten($server_discoveries));
    }

    public static function openvpn_client()
    {
        $client_discoveries = [];
        foreach (PfEnv::openvpn_get_active_clients() as $client) {
            $client_discoveries[] = [
                "{#CLIENT}" => $client["vpnid"],
                "{#NAME}" => self::sanitize_name($client["name"]),
            ];
        }

        self::print_json($client_discoveries);
    }

    public static function services()
    {
        $named_services = array_filter(PfEnv::get_services(), fn($service) => !empty($service["name"]));

        $service_discoveries = [];
        foreach ($named_services as $service) {
            $maybe_id = Util::array_first(fn($key) => in_array($key, ["id", "zone"]), array_keys($service));

            $id = "";
            if (!is_null($maybe_id)) {
                $id = $service[$maybe_id];
            }

            $service_discoveries[] = [
                "{#SERVICE}" => sprintf("%s%s", Util::space_to_underscore($service["name"]), $id),
                "{#DESCRIPTION}" => $service["description"],
            ];
        }

        self::print_json($service_discoveries);
    }

    public static function interfaces()
    {
        self::discover_interface();
    }

    public static function ipsec_ph1()
    {
        PfEnv::init_config_arr(array("ipsec", "phase1"));

        $config = PfEnv::cfg();

        $ipsec_ph1_discoveries = [];
        foreach ($config["ipsec"]["phase1"] as $data) {
            $ipsec_ph1_discoveries[] = [
                "{#IKEID}" => $data["ikeid"],
                "{#NAME}" => $data["descr"],
            ];
        }

        self::print_json($ipsec_ph1_discoveries);
    }

    public static function ipsec_ph2()
    {
        PfEnv::init_config_arr(array("ipsec", "phase2"));

        $config = PfEnv::cfg();

        $ipsec_ph2_discoveries = [];
        foreach ($config["ipsec"]["phase2"] as $data) {
            $ipsec_ph2_discoveries[] = [
                "{#IKEID}" => $data["ikeid"],
                "{#NAME}" => $data["descr"],
                "{#UNIQID}" => $data["uniqid"],
                "{#REQID}" => $data["reqid"],
                "{#EXTID}" => sprintf("%s.%s", $data["ikeid"], $data["reqid"]),
            ];
        }

        self::print_json($ipsec_ph2_discoveries);
    }

    public static function dhcpfailover()
    {
        // System public static functions regarding DHCP Leases will be available in the upcoming release of pfSense, so let's wait
        $leases = PfEnv::system_get_dhcpleases();

        $dhcp_failover_discoveries = [];
        foreach ($leases["failover"] as $data) {
            $dhcp_failover_discoveries[] = [
                "{#FAILOVER_GROUP}" => Util::space_to_underscore($data["name"]),
            ];
        }

        self::print_json($dhcp_failover_discoveries);
    }

    private static function print_json(array $json)
    {
        echo json_encode([
            "data" => $json
        ]);
    }

    private static function sanitize_name(string $raw_name): string
    {
        return trim(preg_replace("/\w{3}(\d)?:\d{4,5}/i", "", $raw_name));
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
        $conn_discoveries = [];
        foreach ($conns as $conn) {
            $conn_discoveries[] = self::map_conn($server_name, $vpn_id, $conn);

        }

        return $conn_discoveries;
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

        $wan_interface_discoveries = [];
        foreach (NetworkInterface::retrieve_wan_interfaces() as $hwif) {
            $wan_interface_discoveries[] = [
                "{#IFNAME}" => $hwif["hwif"],
                "{#IFDESCR}" => $hwif["description"],
            ];
        }

        self::print_json($wan_interface_discoveries);
    }
}

class SpeedTest
{
    public static function interface_value($if_name, $value)
    {
        list($tv0, $tv1) = explode(".", $value);

        $filename = self::if_filename($if_name);
        if (!file_exists($filename)) {
            return Util::result("");
        }

        $speed_test_data = json_decode(file_get_contents($filename), true);
        if (!array_key_exists($value, $speed_test_data)) {
            return Util::result("");
        }

        if (empty($tv1)) {
            return Util::result($speed_test_data[$tv0]);
        }

        return Util::result($speed_test_data[$tv0][$tv1]);
    }

    public static function cron_install($enable = true)
    {
        PfEnv::install_cron_job(
            implode(" ", ["/usr/local/bin/php", __FILE__, "speedtest_cron"]),
            $enable,
            "*/15", "*", "*", "*", "*",
            "root",
            true);
    }

    public static function run($if_name, $ip_address)
    {
        $output_file_path = self::if_filename($if_name);

        $is_output_file_older_than_interval =
            !file_exists($output_file_path) ||
            (time() - filemtime($output_file_path) > SPEED_TEST_INTERVAL_SECONDS);
        if (!$is_output_file_older_than_interval) {
            return;
        }

        self::run_exclusively(function () use ($ip_address, $output_file_path) {
            // Issue #82
            // Sleep random delay in order to avoid problem when 2 pfSense on the same Internet line
            sleep(rand(SPEED_TEST_RANDOM_DELAY_MIN_SECONDS, SPEED_TEST_RANDOM_DELAY_MAX_SECONDS));

            Shell::run_speed_test($ip_address, $output_file_path);
        });
    }

    private static function run_exclusively(Closure $fn)
    {
        $fp = fopen(implode("", [sys_get_temp_dir(), "pfz-speedtest.lock"]), "w");

        $is_other_test_currently_running = !flock($fp, LOCK_EX | LOCK_NB);
        if ($is_other_test_currently_running) {
            fclose($fp);
            return;
        }

        $fn();

        flock($fp, LOCK_UN);

        fclose($fp);
    }

    private static function if_filename($if_name): string
    {
        return implode(DIRECTORY_SEPARATOR, [sys_get_temp_dir(), "speedtest-$if_name"]);
    }
}

class OpenVpn
{
    public static function get_active_servers(): array
    {
        $servers = PfEnv::openvpn_get_active_servers();
        $sk_servers = PfEnv::openvpn_get_active_servers("p2p");

        return array_merge($servers, $sk_servers);
    }
}

class Command
{
    private const BINDING_STATES = [
        "active" => [
            "act" => TEXT_ACTIVE,
        ],
        "free" => [
            "act" => TEXT_EXPIRED,
            "online" => TEXT_OFFLINE,
        ],
        "backup" => [
            "act" => TEXT_RESERVED,
            "online" => TEXT_OFFLINE,
        ],
    ];

    public static function discovery($section)
    {
        $is_known_section = in_array(strtolower($section), DISCOVERY_SECTION_HANDLERS);
        if (!$is_known_section) {
            return;
        }

        Discovery::{$section}();
    }

    public static function gw_value($gw, $value_key)
    {
        $gws = PfEnv::return_gateways_status(true);
        if (!array_key_exists($gw, $gws)) {
            return Util::result("");
        }

        $gw_data = $gws[$gw];

        $value = $gw_data[$value_key];
        if ($value_key != "status") {
            return Util::result($value);
        }

        $substatus = $gw_data["substatus"];
        $has_relevant_substatus = $substatus != "none"; // Issue #70: Gateway Forced Down

        return Util::result(self::get_value_mapping(
            "gateway.status",
            $has_relevant_substatus ? $substatus : $value));
    }

    public static function gw_status()
    {
        $gw_statuses = [];
        foreach (PfEnv::return_gateways_status(true) as $gw) {
            $gw_statuses[] = sprintf("%s.%s", $gw["name"], $gw["status"]);
        }

        return Util::result(implode(",", $gw_statuses));
    }

    public static function if_speedtest_value($if_name, $value)
    {
        SpeedTest::cron_install();
        SpeedTest::interface_value($if_name, $value);
    }

    public static function openvpn_servervalue(int $server_id, $value_key)
    {
        $maybe_server = Util::array_first(fn($s) => $s["vpnid"] == $server_id, OpenVpn::get_active_servers());
        if (empty($maybe_server)) {
            return Util::result(FALLBACK_VALUE);
        }

        $server_value = self::get_server_value($maybe_server, $value_key);

        if ($value_key == "conns") {
            return Util::result(is_array($server_value) ? count($server_value) : FALLBACK_VALUE);
        }

        if (in_array($value_key, ["status", "mode"])) {
            return Util::result(self::get_value_mapping("openvpn.server.status", $server_value));
        }

        return Util::result($server_value);
    }

    public static function openvpn_server_uservalue($unique_id, $value_key)
    {
        return self::get_openvpn_server_uservalue_($unique_id, $value_key);
    }

    public static function openvpn_server_uservalue_numeric($unique_id, $value_key)
    {
        return self::get_openvpn_server_uservalue_($unique_id, $value_key, FALLBACK_VALUE);
    }

    public static function openvpn_clientvalue($client_id, $value_key, $fallback_value = FALLBACK_VALUE)
    {
        $maybe_client = Util::array_first(
            fn($client) => $client["vpnid"] == $client_id,
            PfEnv::openvpn_get_active_clients());
        if (empty($maybe_client)) {
            return Util::result($fallback_value);
        }

        $value = ($value_key == "status") ?
            self::sanitize_openvpn_clientvalue_status($maybe_client) :
            $maybe_client[$value_key];

        if ($value == "") {
            return Util::result($fallback_value);
        }

        return Util::result($value);
    }

    public static function service_value(string $name, string $value)
    {
        $sanitized_name = Util::underscore_to_space($name);

        // List of service which are stopped on CARP Slave.
        // For now this is the best way I found for filtering out the triggers
        // Waiting for a way in Zabbix to use Global Regexp in triggers with items discovery
        $stopped_on_carp_slave = array("haproxy", "radvd", "openvpn.", "openvpn", "avahi");

        $maybe_service = Util::array_first(function ($service) use ($sanitized_name) {
            foreach (["id", "zone"] as $key) {
                if (array_key_exists($key, $service)) {
                    return sprintf("%s%s", $service["name"], $service[$key]) == $sanitized_name;
                }
            }

            return $service["name"] == $sanitized_name;
        }, PfEnv::get_services());

        if (empty($maybe_service)) {
            return Util::result(FALLBACK_VALUE);
        }

        $short_name = $maybe_service["name"];
        $carp_cfr = "$short_name.";

        $is_known_service_value = in_array($value, SERVICES_VALUE_HANDLERS);
        if (!$is_known_service_value) {
            return Util::result($maybe_service[$value]);
        }

        return Util::result(
            Service::{$value}(
                $maybe_service,
                $sanitized_name,
                $short_name,
                $carp_cfr,
                $stopped_on_carp_slave));
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

    public static function carp_status(): int
    {
        return Util::result(self::get_carp_status());
    }

    // System Information
    public static function system($section)
    {
        if ($section === "packages_update") {
            return Util::result(self::get_outdated_packages());
        }

        $system_pkg_version = PfEnv::get_system_pkg_version();
        if ($section === "new_version_available") {
            return Util::result(
                Util::b2int($system_pkg_version["version"] != $system_pkg_version["installed_version"]));
        }

        $is_known_section = array_key_exists($section, $system_pkg_version);

        if ($is_known_section) {
            return Util::result($$system_pkg_version[$section]);
        }

        return Util::result("");
    }

    public static function ipsec_ph1($ike_id, $value_key)
    {
        // Get Value from IPsec Phase 1 Configuration
        // If Getting "disabled" value only check item presence in config array
        $config = PfEnv::cfg();
        PfEnv::init_config_arr(["ipsec", "phase1"]);
        $a_phase2 = $config["ipsec"]["phase1"] ?: [];

        if ($value_key == "status") {
            return Util::result(Command::get_ipsec_status($ike_id));
        }

        if ($value_key == "disabled") {
            return Util::result(FALLBACK_VALUE);
        }

        $maybe_ike_match = Util::array_first(fn($d) => $d["ikeid"] == $ike_id, $a_phase2);
        if (empty($maybe_ike_match)) {
            return Util::result(FALLBACK_VALUE);
        }

        if (!array_key_exists($value_key, $maybe_ike_match)) {
            return Util::result(FALLBACK_VALUE);
        }

        return Util::result(self::get_value_mapping("ipsec.$value_key", $maybe_ike_match[$value_key]));
    }

    public static function ipsec_ph2($uniqid, $value_key)
    {
        $config = PfEnv::cfg();
        PfEnv::init_config_arr(array("ipsec", "phase2"));
        $a_phase2 = $config["ipsec"]["phase2"] ?: [];

        $valuecfr = explode(".", $value_key);

        $value = FALLBACK_VALUE;
        if ($valuecfr[0] == "status") {
            $ids = explode(".", $uniqid);
            $status_key = (isset($valuecfr[1])) ? $valuecfr[1] : "state";
            $value = self::get_ipsec_status($ids[0], $ids[1], $status_key);
        }

        $maybe_data = Util::array_first(fn($data) => $data["uniqid"] == $uniqid, $a_phase2);
        if (is_null($maybe_data) || !array_key_exists($value_key, $maybe_data)) {
            return Util::result($value);
        }

        if ($value_key != "disabled") {
            return Util::result(self::get_value_mapping("ipsec_ph2." . $value_key, $maybe_data[$value_key]));
        }

        return Util::result(1);
    }

    public static function dhcp($section)
    {
        if ($section === "failover") {
            return Util::result(self::check_dhcp_failover());

        }

        return Util::result(self::check_dhcp_offline_leases());
    }

    // File is present
    public static function file_exists($filename)
    {
        return Util::result(Util::b2int(file_exists($filename)));
    }

    public static function speedtest_cron()
    {
        foreach (NetworkInterface::retrieve_wan_interfaces() as $if_info) {
            SpeedTest::run($if_info["hwif"], $if_info["ipaddr"]);
        }
    }

    public static function cron_cleanup()
    {
        SpeedTest::cron_install(false);
    }

    // S.M.A.R.T Status
    // Taken from /usr/local/www/widgets/widgets/smart_status.widget.php
    public static function smart_status()
    {
        $dev_states = [];
        foreach (PfEnv::get_smart_drive_list() as $device_name) {
            $dev_states[] = Shell::read_smart_status($device_name);
        }

        $smart_states = [];
        foreach ($dev_states as $dev_state) {
            $smart_states[] = array_key_exists($dev_state, SMART_DEV_STATUS) ?
                SMART_DEV_STATUS[$dev_state] :
                SMART_ERROR;
        }

        $maybe_not_ok = Util::array_first(function ($smart_state) {
            return $smart_state != SMART_OK;
        }, $smart_states);

        return Util::result($maybe_not_ok ?: SMART_OK);
    }

    public static function cert_date($value_key)
    {
        if (!array_key_exists($value_key, CERT_VK_TO_FIELD)) {
            return Util::result(FALLBACK_VALUE);
        }

        $field = CERT_VK_TO_FIELD[$value_key];
        $config = PfEnv::cfg();

        $certs_and_cas = [];
        foreach (["cert", "ca"] as $cert_type) {
            $certs_and_cas[] = $config[$cert_type] ?: [];
        }
        $all_certs = Util::array_flatten($certs_and_cas);

        return Util::result(array_reduce($all_certs, function ($value, $certificate) use ($field) {
            $cert_info = openssl_x509_parse(base64_decode($certificate[PfEnv::CRT]));

            if ($value == 0 || $value < $cert_info[$field]) {
                return $cert_info[$field];
            }

            return $value;
        }, FALLBACK_VALUE));
    }

    // Testing function, for template creating purpose
    public static function test()
    {
        $config = PfEnv::cfg();

        echo "OPENVPN Servers:\n";
        print_r(OpenVpn::get_active_servers());
        echo LINE;

        echo "OPENVPN Clients:\n";
        print_r(PfEnv::openvpn_get_active_clients());
        echo LINE;

        $ifdescrs = PfEnv::get_configured_interface_with_descr(true);
        $ifaces = [];
        foreach ($ifdescrs as $ifdescr => $ifname) {
            $ifaces[$ifname] = PfEnv::get_interface_info($ifdescr);
        }
        echo "Network Interfaces:\n";
        print_r($ifaces);
        print_r(PfEnv::get_interface_arr());
        print_r(PfEnv::get_configured_interface_list());
        echo LINE;

        echo "Services: \n";
        print_r(PfEnv::get_services());
        echo LINE;

        echo "IPsec: \n";
        PfEnv::init_config_arr(array("ipsec", "phase1"));
        PfEnv::init_config_arr(array("ipsec", "phase2"));
        echo "IPsec Status: \n";
        print_r(PfEnv::ipsec_list_sa());

        echo "IPsec Config Phase 1: \n";
        print_r($config["ipsec"]["phase1"]);

        echo "IPsec Config Phase 2: \n";
        print_r($config["ipsec"]["phase2"]);

        echo LINE;

        echo "Packages: \n";
        print_r(PfEnv::get_pkg_info("all", false, true));
    }

    private static function sanitize_openvpn_clientvalue_status($client_data)
    {
        $is_pre_version_22_05 = in_array($client_data["status"], array_keys(VALUE_MAPPINGS["openvpn.client.status"]));

        $raw_value = $is_pre_version_22_05 ?
            $client_data["status"] : $client_data["state"];

        return self::get_value_mapping("openvpn.client.status", $raw_value);
    }

    private static function get_carp_status(): int
    {
        $is_carp_enabled = PfEnv::get_carp_status() != 0;
        if (!$is_carp_enabled) {
            return CARP_STATUS_DISABLED;
        }

        $is_carp_demotion_status_ok = PfEnv::get_single_sysctl("net.inet.carp.demotion") == 0;
        if (!$is_carp_demotion_status_ok) {
            return CARP_STATUS_PROBLEM;
        }

        $config = PfEnv::cfg();

        $just_carps = array_filter($config["virtualip"]["vip"], fn($virtual_ip) => $virtual_ip["mode"] != "carp");
        $status_str = array_reduce($just_carps, function ($status, $carp) {
            $if_status = PfEnv::get_carp_interface_status("_vip{$carp["uniqid"]}");

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

        return $is_known_carp_status ? CARP_RES[$status_str] : CARP_STATUS_UNKNOWN;
    }

    private static function get_openvpn_server_uservalue_($unique_id, $value_key, $default = "")
    {
        list($server_id, $user_id) = explode("+", $unique_id);

        $servers = OpenVpn::get_active_servers();

        $maybe_server = Util::array_first(fn($server) => $server["vpnid"] == $server_id, $servers);
        if (!$maybe_server) {
            return $default;
        }

        $maybe_conn = Util::array_first(fn($conn) => ($conn["common_name"] == $user_id), $maybe_server["conns"] ?: []);

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

            $carp_status = self::get_carp_status();

            if ($carp_status != 0) {
                return $v + (10 * ($carp_status - 1));
            }

            return $v;
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

            return array_merge(
                $p,
                [$cname => $ph1ent[$ike_id]],
            );
        }, []);

        // Phase-Status match borrowed from status_ipsec.php	
        $maybe_ike_sa = Util::array_first(function ($ike_sa) use ($ike_id, $connection_map) {
            $con_id = isset($ike_sa["con-id"]) ?
                substr($ike_sa["con-id"], 3) :
                filter_var($ike_id, FILTER_SANITIZE_NUMBER_INT);

            $con_name = "con$con_id";

            $is_version_1 = $ike_sa["version"] == 1;
            $is_split_connection = !$is_version_1 && !PfEnv::ipsec_ikeid_used($con_id);

            $ph1idx = ($is_version_1 || $is_split_connection) ? $connection_map[$con_name] : $con_id;

            return $ph1idx == $ike_id;
        }, $ipsec_list_sa);

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

    private static function remove_duplicates(array $haystack, $field): array
    {
        return array_values(array_reduce($haystack, fn($lookup_table, $item) => array_merge(
            $lookup_table, [$item[$field] => $item]
        ), []));
    }

    private static function parse_raw_record(string $raw_lease_data): array
    {
        $raw_lease_data_lines = [];
        foreach (explode(";", $raw_lease_data) as $raw_line) {
            $raw_lease_data_lines[] = trim($raw_line);
        }

        $lease_data_lines = array_filter($raw_lease_data_lines);

        return array_reduce(
            $lease_data_lines,
            function ($p, $lease_data_line) {
                list($k, $v) = array_pad(explode(" ", $lease_data_line, 2), 2, true);

                return array_merge($p, [$k => $v]);
            },
            []);
    }

    private static function parse_failover_record(array $data): array
    {
        $sanitized_data = [];
        foreach ($data as $line) {
            $sanitized_data[] = trim($line);
        }

        list($name, $raw_lease_data) = $sanitized_data;

        return [
            "type" => "failover",
            "data" => array_merge(
                ["name" => $name],
                self::parse_raw_record($raw_lease_data))];
    }

    private static function parse_lease_record(array $data): array
    {
        $sanitized_data = [];
        foreach ($data as $line) {
            $sanitized_data[] = trim($line);
        }

        list($lease_address, $raw_lease_data) = $sanitized_data;

        return [
            "type" => "lease",
            "data" => array_merge(
                ["ip" => $lease_address],
                self::parse_raw_record($raw_lease_data))];
    }

    private static function parse_dhcp_record(string $record): ?array
    {
        $is_lease_record = preg_match("/^lease\s+(.*)\s+{(.+)}$/", $record, $lease_record_match);
        $is_failover_record = preg_match("/^failover.*\"(.*)\"\s+state\s+{(.+)}$/", $record, $failover_record_match);

        $is_known_record_type = $is_lease_record || $is_failover_record;
        if (!$is_known_record_type) {
            return null;
        }

        if ($is_lease_record) {
            return self::parse_lease_record(array_slice($lease_record_match, 1));
        }

        return self::parse_failover_record(array_slice($failover_record_match, 1));
    }

    private static function read_dhcp_records_from_file(string $leases_file_path): array
    {
        $dhcp_records = [];
        foreach (Shell::read_dhcpd_records($leases_file_path) as $raw_dhcp_record) {
            $dhcp_records[] = self::parse_dhcp_record($raw_dhcp_record);

        }

        return $dhcp_records;
    }

    private static function binding_to_state($binding): array
    {
        $is_known_binding = array_key_exists($binding, self::BINDING_STATES);
        if (!$is_known_binding) {
            return [
                "act" => "",
            ];
        }

        return self::BINDING_STATES[$binding];
    }

    private static function raw_lease_record_to_lease(array $raw_lease_record, array $arpdata_ip): array
    {
        $data = $raw_lease_record["data"];

        $ip = $data["ip"];
        $maybe_client_hostname =
            array_key_exists("client-hostname", $data) ?
                str_replace("\"", "", $data["client-hostname"]) :
                null;

        list(, $binding) = explode(" ", $data["binding"]);
        list(, $mac) = explode(" ", $data["hardware"]);
        list(, $start_date, $start_time) = explode(" ", $data["starts"]);

        $hostname =
            !empty($maybe_client_hostname) ?
                preg_replace('/"/', "", $maybe_client_hostname) :
                gethostbyaddr($data["ip"]);

        $online = in_array($data["ip"], $arpdata_ip) ? TEXT_ONLINE : TEXT_OFFLINE;

        $binding_state = self::binding_to_state($binding);

        $start = implode(" ", [$start_date, $start_time]);
        list(, $end_date, $end_time) = array_pad(explode(" ", $data["ends"]), 3, null);

        $end = ($end_date == "never") ? TEXT_NEVER : implode(" ", [$end_date, $end_time]);

        return array_merge(compact("end", "hostname", "ip", "mac", "online", "start"), $binding_state);
    }

    private static function raw_failover_record_to_pool(array $raw_failover_record): array
    {
        $data = $raw_failover_record["data"];

        $n0 = $data["name"];

        $friendly_description = PfEnv::convert_friendly_interface_to_friendly_descr(substr($n0, 5));
        $name = "$n0 ($friendly_description)";

        list($my_state_str, $my_time_str) = explode(" at ", $data["my"]);
        list($partner_state_str, $partner_time_str) = explode(" at ", $data["partner"]);

        list(, $mystate) = explode(" ", $my_state_str);
        list(, $peerstate) = explode(" ", $partner_state_str);
        list(, $my_date, $my_time) = explode(" ", $my_time_str);
        list(, $partner_date, $partner_time) = explode(" ", $partner_time_str);

        $mydate = implode(" ", [$my_date, $my_time]);
        $peerdate = implode(" ", [$partner_date, $partner_time]);

        return compact("name", "mystate", "peerstate", "mydate", "peerdate");
    }

    // Get DHCP Arrays (copied from status_dhcp_leases.php, waiting for pfsense 2.5, in order to use system_get_dhcpleases();)
    private static function get_dhcp($value_key): array
    {
        $leases_file = implode(
            DIRECTORY_SEPARATOR,
            [PfEnv::g("dhcpd_chroot_path"), "var", "db", "dhcpd.leases"]);

        $dhcp_records = self::read_dhcp_records_from_file($leases_file);

        $failover = [];
        if ($value_key === "failover") {
            return $failover;
        }

        if ($value_key === "pools") {
            $failover_records = array_filter($dhcp_records, fn($r) => $r["type"] == "failover");

            $pools = [];
            foreach ($failover_records as $failover_record) {
                $pools[] = self::raw_failover_record_to_pool($failover_record);
            }

            return self::remove_duplicates($pools, "name");
        }

        $arp_ips = Shell::read_arp_ips();

        $leases = [];
        foreach (array_filter($dhcp_records, fn($r) => $r["type"] == "lease") as $lease_record) {
            $leases[] = self::raw_lease_record_to_lease($lease_record, $arp_ips);
        }

        return self::remove_duplicates($leases, "mac");
    }

    private static function check_dhcp_offline_leases(): int
    {
        return count(array_filter(
            self::get_dhcp("leases"),
            fn($f) => $f["online"] != TEXT_ONLINE));
    }

    private static function check_dhcp_failover(): int
    {
        // Check DHCP Failover Status
        // Returns number of failover pools which state is not normal or
        // different from peer state
        $failover_pools = self::get_dhcp("pools");

        return count(array_filter(
            $failover_pools,
            fn($f) => ($f["mystate"] != "normal") || ($f["mystate"] != $f["peerstate"])));
    }

    private static function get_outdated_packages(): int
    {
        return count(array_filter(
            PfEnv::get_pkg_info("all", false, true),
            fn($p) => $p["version"] != $p["installed_version"]));
    }

    // Value mappings
    // Each value map is represented by an associative array
    private static function get_value_mapping($value_name, $value)
    {
        $is_known_value_name = array_key_exists($value_name, VALUE_MAPPINGS);
        if (!$is_known_value_name) {
            return FALLBACK_VALUE;
        }

        $value_mapping = VALUE_MAPPINGS[$value_name];
        if (!is_array($value_mapping)) {
            return FALLBACK_VALUE;
        }

        $sanitized_value = strtolower($value);
        $is_value_with_known_mapping = array_key_exists($sanitized_value, $value_mapping);

        if ($is_value_with_known_mapping) {
            return $value_mapping[$sanitized_value];
        }

        return FALLBACK_VALUE;
    }
}

function build_method_lookup(string $clazz): array
{
    try {
        $reflector = new ReflectionClass($clazz);

        $all_methods = $reflector->getMethods();

        $commands = array_filter($all_methods, fn($method) => $method->isStatic() && $method->isPublic());

        $available_methods = [];
        foreach ($commands as $method) {
            $available_methods[] = $method->getName();
        }

        return $available_methods;
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
        Command::test();
        exit;
    }

    Command::{$command}(...$parameters);
}

main($argv);
