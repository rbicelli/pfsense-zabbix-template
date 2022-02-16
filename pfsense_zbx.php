<?php
/*** 
pfsense_zbx.php - pfSense Zabbix Interface
Version 1.1.1 - 2021-10-24

Written by Riccardo Bicelli <r.bicelli@gmail.com>
This program is licensed under Apache 2.0 License
*/

$exec_0 = fn(callable $f) => $f;
$exec_1 = fn(callable $f) => fn($parameters) => $f($parameters[0]);
$exec_2 = fn(callable $f) => fn($parameters) => $f($parameters[0], $parameters[1]);

//Some Useful defines
define('SPEEDTEST_INTERVAL', 8); //Speedtest Interval (in hours)

// Argument parsers for Discovery
define('DISCOVERY_SECTION_HANDLERS', [
    "gw" => $exec_0(fn() => pfz_gw_discovery()),
    "wan" => $exec_0(fn() => pfz_interface_discovery(true)),
    "openvpn_server" => $exec_0(fn() => pfz_openvpn_serverdiscovery()),
    "openvpn_server_user" => $exec_0(fn() => pfz_openvpn_server_userdiscovery()),
    "openvpn_client" => $exec_0(fn() => pfz_openvpn_clientdiscovery()),
    "services" => $exec_0(fn() => pfz_services_discovery()),
    "interfaces" => $exec_0(fn() => pfz_interface_discovery()),
    "ipsec_ph1" => $exec_0(fn() => pfz_ipsec_discovery_ph1()),
    "ipsec_ph2" => $exec_0(fn() => pfz_ipsec_discovery_ph2()),
    "dhcpfailover" => $exec_0(fn() => pfz_dhcpfailover_discovery()),
    "temperature_sensors" => $exec_0(fn() => pfz_temperature_sensors_discovery()),
]);

define('COMMAND_HANDLERS', [
    "carp_status" => $exec_0(fn() => pfz_carp_status()),
    "cert_date" => $exec_1(fn($p0) => pfz_get_cert_date($p0)),
    "cron_cleanup" => $exec_0(fn() => pfz_speedtest_cron_install(false)),
    "dhcp" => $exec_2(fn($p0, $p1) => pfz_dhcp($p0, $p1)),
    "discovery" => $exec_1(fn($p0) => pfz_discovery($p0)),
    "file_exists" => $exec_1(fn($p0) => pfz_file_exists($p0)),
    "gw_status" => $exec_0(fn() => pfz_gw_rawstatus()),
    "gw_value" => $exec_2(fn($p0, $p1) => pfz_gw_value($p0, $p1)),
    "if_name" => $exec_1(fn($p0) => pfz_get_if_name($p0)),
    "if_speedtest_value" => $exec_2(function ($p0, $p1) {
        pfz_speedtest_cron_install();
        pfz_interface_speedtest_value($p0, $p1);
    }),
    "ipsec_ph1" => $exec_2(fn($p0, $p1) => pfz_ipsec_ph1($p0, $p1)),
    "ipsec_ph2" => $exec_2(fn($p0, $p1) => pfz_ipsec_ph2($p0, $p1)),
    "openvpn_clientvalue" => $exec_2(fn($p0, $p1) => pfz_openvpn_client_value($p0, $p1)),
    "openvpn_server_uservalue" => $exec_2(fn($p0, $p1) => pfz_openvpn_server_uservalue($p0, $p1)),
    "openvpn_server_uservalue_numeric" => $exec_2(fn($p0, $p1) => pfz_openvpn_server_uservalue($p0, $p1, "0")),
    "openvpn_servervalue" => $exec_2(fn($p0, $p1) => pfz_openvpn_server_value($p0, $p1)),
    "service_value" => $exec_2(fn($p0, $p1) => pfz_service_value($p0, $p1)),
    "speedtest_cron" => $exec_0(function () {
        pfz_speedtest_cron_install();
        pfz_speedtest_cron();
    }),
    "smart_status" => $exec_0(fn() => pfz_get_smart_status()),
    "system" => $exec_1(fn($p0) => pfz_get_system_value($p0)),
    "temperature" => $exec_1(fn($p0) => pfz_get_temperature($p0)),
]);

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

define('SMART_DEV_STATUS', [
    SMART_DEV_PASSED => SMART_OK,
    SMART_DEV_OK => SMART_OK,
    SMART_DEV_UNKNOWN => SMART_UNKNOWN
]);

define("DHCP_SECTIONS", [
    "failover" => function () {
        echo pfz_dhcp_check_failover();
    },
]);

define("OPENVPN_SERVER_VALUES", [
    // Client Connections: is an array so it is sufficient to count elements                    
    "conns" => fn($server_value) => is_array($server_value) ? count($server_value) : 0,
    "status" => fn($server_value) => pfz_value_mapping("openvpn.server.status", $server_value),
    "mode" => fn($server_value) => pfz_value_mapping("openvpn.server.mode", $server_value)
]);

define("IPSEC_PH1_VALUES", [
    'status' => fn($ike_id) => pfz_ipsec_status($ike_id),
    'disabled' => fn() => "0",
]);

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

// Utilities
function array_first(array $haystack, Callback $match)
{
    foreach ($haystack as $needle) {
        if ($match($needle)) {
            return $needle;
        }
    }

    return null;
}

function pfz_cfg() { // Abstract global variable from code
    global $config;

    return $config;
}

//Testing function, for template creating purpose
function pfz_test(){
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
        $ifaces=array();
        foreach ($ifdescrs as $ifdescr => $ifname){	     
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
		$config = pfz_cfg();
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
function pfz_interface_discovery($is_wan=false,$is_cron=false) {
    $ifdescrs = get_configured_interface_with_descr(true);
    $ifaces = get_interface_arr();
    $ifcs=array();
    $if_ret=array();
 
    $json_string = '{"data":[';
                   
    foreach ($ifdescrs as $ifname => $ifdescr){
          $ifinfo = get_interface_info($ifname);
          $ifinfo["description"] = $ifdescr;
	      $ifcs[$ifname] = $ifinfo;	      
    }    

    foreach ($ifaces as $hwif) {
        
        $ifdescr = $hwif;
        $has_gw = false;
        $is_vpn = false;
        $has_public_ip = false;
        
        foreach($ifcs as $ifc=>$ifinfo){
                if ($ifinfo["hwif"] == $hwif){
                        $ifdescr = $ifinfo["description"];
                        if (array_key_exists("gateway",$ifinfo)) $has_gw=true;
                        //	Issue #81 - https://stackoverflow.com/a/13818647/15093007
                        if (filter_var($ifinfo["ipaddr"], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) $has_public_ip=true;
                        if (strpos($ifinfo["if"],"ovpn")!==false) $is_vpn=true;
                        break;
                }
        }
		
		if ( ($is_wan==false) ||  (($is_wan==true) && (($has_gw==true) || ($has_public_ip==true)) && ($is_vpn==false)) ) { 
		    $if_ret[]=$hwif;
		    $json_string .= '{"{#IFNAME}":"' . $hwif . '"';
		    $json_string .= ',"{#IFDESCR}":"' . $ifdescr . '"';
		    $json_string .= '},';
        }
    
    }
    $json_string = rtrim($json_string,",");
    $json_string .= "]}";

	if ($is_cron) return $if_ret;
	
    echo $json_string;
}


//Interface Speedtest
function pfz_interface_speedtest_value($ifname, $value){	
    $tvalue = explode(".", $value);    
    
    if (count($tvalue)>1) {
    	$value = $tvalue[0];
    	$subvalue = $tvalue[1];
    }        
    
	//If the interface has a gateway is considered WAN, so let's do the speedtest
	$filename = "/tmp/speedtest-$ifname";
	
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

// This is supposed to run via cron job
function pfz_speedtest_cron(){
	require_once("services.inc");
	$ifdescrs = get_configured_interface_with_descr(true);
    $ifaces = get_interface_arr();
    $pf_interface_name='';
    $subvalue=false;    
		                       
    $ifcs = pfz_interface_discovery(true, true);    
    
    foreach ($ifcs as $ifname) {    	  
          
          foreach ($ifdescrs as $ifn => $ifd){
		      $ifinfo = get_interface_info($ifn);
		      if($ifinfo['hwif']==$ifname) {
		      	$pf_interface_name = $ifn;
		      	break;
		      }
    	  }
          			
		  pfz_speedtest_exec($ifname, $ifinfo['ipaddr']);
		    	
    }
}

//installs a cron job for speedtests
function pfz_speedtest_cron_install($enable=true){
	//Install Cron Job
	$command = "/usr/local/bin/php " . __FILE__ . " speedtest_cron";
	install_cron_job($command, $enable, $minute = "*/15", "*", "*", "*", "*", "root", true);
}        	


function pfz_speedtest_exec ($ifname, $ipaddr){
	
	$filename = "/tmp/speedtest-$ifname";
	$filetemp = "$filename.tmp";
	$filerun = "/tmp/speedtest-run"; 
	
	// Issue #82
	// Sleep random delay in order to avoid problem when 2 pfSense on the same Internet line
	sleep (rand ( 1, 90));
	
	if ( (time()-filemtime($filename) > SPEEDTEST_INTERVAL * 3600) || (file_exists($filename)==false) ) {
	  	// file is older than SPEEDTEST_INTERVAL
	  	if ( (time()-filemtime($filerun) > 180 ) ) @unlink($filerun);

		if (file_exists($filerun)==false) {	  			  		
	  		touch($filerun);
	  		$st_command = "/usr/local/bin/speedtest --source $ipaddr --json > $filetemp";
			exec ($st_command);
			rename($filetemp,$filename);
			@unlink($filerun);
		}
	}	
	
	return true;
}


// OpenVPN Server Discovery
function pfz_openvpn_get_all_servers(){
     $servers = openvpn_get_active_servers();
     $sk_servers = openvpn_get_active_servers("p2p");
     $servers = array_merge($servers,$sk_servers);
     return ($servers);
}


function pfz_openvpn_serverdiscovery() {
     $servers = pfz_openvpn_get_all_servers();

     $json_string = '{"data":[';

     foreach ($servers as $server){
          $name = trim(preg_replace('/\w{3}(\d)?\:\d{4,5}/i', '', $server['name']));
          $json_string .= '{"{#SERVER}":"' . $server['vpnid'] . '"';
          $json_string .= ',"{#NAME}":"' . $name . '"';  
          $json_string .= '},';
     }

     $json_string = rtrim($json_string,",");
     $json_string .= "]}";

     echo $json_string;
}

function pfz_retrieve_server_value($maybe_server, $value_key)
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

// Get OpenVPN Server Value
function pfz_openvpn_server_value($server_id, $value_key)
{
    $servers = pfz_openvpn_get_all_servers();

    $maybe_server = array_first($servers, fn($s) => $s['vpnid'] == $server_id);

    $server_value = pfz_retrieve_server_value($maybe_server, $value_key);

    $is_known_value_key = array_key_exists($value_key, OPENVPN_SERVER_VALUES);
    if ($is_known_value_key) {
        echo OPENVPN_SERVER_VALUES[$value_key]($server_value);
        return;
    }

    echo $server_value;
}

//OpenVPN Server/User-Auth Discovery
function pfz_openvpn_server_userdiscovery(){
     $servers = pfz_openvpn_get_all_servers();

     $json_string = '{"data":[';

     foreach ($servers as $server){
          if ( ($server['mode']=='server_user') || ($server['mode']=='server_tls_user') || ($server['mode']=='server_tls') ) {
               if (is_array($server['conns'])) {               
                    $name = trim(preg_replace('/\w{3}(\d)?\:\d{4,5}/i', '', $server['name']));
                    
                    foreach($server['conns'] as $conn) {
                    	
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

     $json_string = rtrim($json_string,",");
     $json_string .= "]}";

     echo $json_string;
}

// Get OpenVPN User Connected Value
function pfz_openvpn_server_uservalue($unique_id, $valuekey, $default=""){

	 $unique_id = pfz_replacespecialchars($unique_id,true);
     $atpos=strpos($unique_id,'+');
     $server_id = substr($unique_id,0,$atpos);
     $user_id = substr($unique_id,$atpos+1);
     
     $servers = pfz_openvpn_get_all_servers();
     foreach($servers as $server) {
          if($server['vpnid']==$server_id) {
               foreach($server['conns'] as $conn) {               
                    if ($conn['common_name']==$user_id){
                         $value = $conn[$valuekey];
                    }
               }               
          }
     }
     if ($value=="") $value = $default;
     echo $value;
}
// OpenVPN Client Discovery
function pfz_openvpn_clientdiscovery() {
     $clients = openvpn_get_active_clients();

     $json_string = '{"data":[';

     foreach ($clients as $client){
          $name = trim(preg_replace('/\w{3}(\d)?\:\d{4,5}/i', '', $client['name']));
          $json_string .= '{"{#CLIENT}":"' . $client['vpnid'] . '"';
          $json_string .= ',"{#NAME}":"' . $name . '"';
          $json_string .= '},';
     }

     $json_string = rtrim($json_string,",");
     $json_string .= "]}";

     echo $json_string;
}

function pfz_replacespecialchars($inputstr,$reverse=false){
	 $specialchars = ",',\",`,*,?,[,],{,},~,$,!,&,;,(,),<,>,|,#,@,0x0a";
	 $specialchars = explode(",",$specialchars);	 
	 $resultstr = $inputstr;
	 
	 for ($n=0;$n<count($specialchars);$n++){
	 	if ($reverse==false)
	 		$resultstr = str_replace($specialchars[$n],'%%' . $n . '%',$resultstr);
	 	else
	 		$resultstr = str_replace('%%' . $n . '%',$specialchars[$n],$resultstr);
	 }	 
	 
	 return ($resultstr);
}

function pfz_openvpn_client_value($client_id, $value_key, $fallback_value = "none")
{
    $clients = openvpn_get_active_clients();

    $client = array_first($clients, fn($client) => $client['vpnid'] == $client_id);

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

// Services Discovery
// 2020-03-27: Added space replace with __ for issue #12
function pfz_services_discovery(){
     $services = get_services();

     $json_string = '{"data":[';

     foreach ($services as $service){
          if (!empty($service['name'])) {
               
               $status = get_service_status($service);
               if ($status="") $status = 0;

               $id="";               
               //id for OpenVPN               
               if (!empty($service['id'])) $id = "." . $service["id"];
               //zone for Captive Portal
               if (!empty($service['zone'])) $id = "." . $service["zone"];
                              
               $json_string .= '{"{#SERVICE}":"' . str_replace(" ", "__", $service['name']) . $id . '"';          
               $json_string .= ',"{#DESCRIPTION}":"' . $service['description'] . '"';
               $json_string .= '},';
          }
     }     
     $json_string = rtrim($json_string,",");
     $json_string .= "]}";
     
     echo $json_string;

}

// Get service value
// 2020-03-27: Added space replace in service name for issue #12
// 2020-09-28: Corrected Space Replace
function pfz_service_value($name,$value){
     $services = get_services();     
     $name = str_replace("__"," ",$name);
           
     //List of service which are stopped on CARP Slave.
     //For now this is the best way i found for filtering out the triggers
     //Waiting for a way in Zabbix to use Global Regexp in triggers with items discovery
     $stopped_on_carp_slave = array("haproxy","radvd","openvpn.","openvpn","avahi");
     
     foreach ($services as $service){
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

          if ($namecfr == $name){
               switch ($value) {
               
                    case "status":
                         $status = get_service_status($service);
                         if ($status=="") $status = 0;
                         echo $status;
                         break;               

                    case "name":
                         echo $namecfr;
                         break;

                    case "enabled":
                         if (is_service_enabled($service['name']))
                              echo 1;
                         else
                              echo 0;
                         break;

                    case "run_on_carp_slave":
                         if (in_array($carpcfr,$stopped_on_carp_slave))
                              echo 0;
                         else
                              echo 1;
                         break;
                    default:               
                         echo $service[$value];
                         break;
               }
          }                                              
    }
}


//Gateway Discovery
function pfz_gw_rawstatus() {
     // Return a Raw Gateway Status, useful for action Scripts (e.g. Update Cloudflare DNS config)
     $gws = return_gateways_status(true);
     $gw_string="";
     foreach ($gws as $gw){
          $gw_string .= ($gw['name'] . '.' . $gw['status'] .",");
     }
     echo rtrim($gw_string,",");
}


function pfz_gw_discovery() {
     $gws = return_gateways_status(true);

     $json_string = '{"data":[';
     foreach ($gws as $gw){          
          $json_string .= '{"{#GATEWAY}":"' . $gw['name'] . '"';          
          $json_string .= '},';
     }     
     $json_string = rtrim($json_string,",");
     $json_string .= "]}";
     
     echo $json_string;
}


function pfz_gw_value($gw, $valuekey) {
     $gws = return_gateways_status(true);
     if(array_key_exists($gw,$gws)) {
          $value = $gws[$gw][$valuekey];
          if ($valuekey=="status") { 
               //Issue #70: Gateway Forced Down
               if ($gws[$gw]["substatus"]<>"none") 
                    $value = $gws[$gw]["substatus"];
               
               $value = pfz_value_mapping("gateway.status", $value);
          }     
          echo $value;         
     }
}


// IPSEC Discovery
function pfz_ipsec_discovery_ph1(){
	
	require_once("ipsec.inc");	
	$config = pfz_cfg();
	init_config_arr(array('ipsec', 'phase1'));
	$a_phase1 = &$config['ipsec']['phase1'];
	
	$json_string = '{"data":[';
	
	foreach ($a_phase1 as $data) {
		$json_string .= '{"{#IKEID}":"' . $data['ikeid'] . '"';
		$json_string .= ',"{#NAME}":"' . $data['descr'] . '"';
		$json_string .= '},';
	}	

	$json_string = rtrim($json_string,",");
    $json_string .= "]}";     	
    
    echo $json_string;
	
}

function pfz_ipsec_ph1($ike_id, $value_key)
{
    // Get Value from IPsec Phase 1 Configuration
    // If Getting "disabled" value only check item presence in config array
    require_once("ipsec.inc");
    $config = pfz_cfg();
    init_config_arr(array('ipsec', 'phase1'));
    $a_phase1 = &$config['ipsec']['phase1'];

    $is_known_ipsec_key = array_key_exists($value_key, IPSEC_PH1_VALUES);
    if ($is_known_ipsec_key) {
        echo IPSEC_PH1_VALUES[$value_key]($ike_id);
        return;
    }

    $maybe_ike_match = array_first($a_phase1, fn($d) => $d["ikeid"] == $ike_id);
    if (empty($maybe_ike_match)) {
        echo "";
        return;
    }

    if (!array_key_exists($value_key, $maybe_ike_match)) {
        echo "";
        return;
    }

    if ($value_key == 'disabled') {
        echo "1";
        return;
    }

    echo pfz_value_mapping("ipsec." . $value_key, $maybe_ike_match[$value_key]);
}

function pfz_ipsec_discovery_ph2(){
	
	require_once("ipsec.inc");
	
	$config = pfz_cfg();
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

	$json_string = rtrim($json_string,",");
    $json_string .= "]}";     	
    
    echo $json_string;
	
}

function pfz_ipsec_ph2($uniqid, $valuekey){
	require_once("ipsec.inc");
	$config = pfz_cfg();
	init_config_arr(array('ipsec', 'phase2'));
	$a_phase2 = &$config['ipsec']['phase2'];	
	
	$valuecfr = explode(".",$valuekey);
		
	switch ($valuecfr[0]) {
		case 'status':
			$idarr = explode(".", $uniqid);
			$statuskey = "state";
			if (isset($valuecfr[1])) $statuskey = $valuecfr[1]; 
			$value = pfz_ipsec_status($idarr[0],$idarr[1],$statuskey);
			break;
		case 'disabled':
			$value = "0";
	}							
	
	foreach ($a_phase2 as $data) {
		if ($data['uniqid'] == $uniqid) {
			if(array_key_exists($valuekey,$data)) {
			if ($valuekey=='disabled')
				$value = "1";
			else
				$value = pfz_value_mapping("ipsec_ph2." . $valuekey, $data[$valuekey], $data[$valuekey]);
			break;
			}
		}
	}
	echo $value;
}

function pfz_ipsec_status($ikeid,$reqid=-1,$valuekey='state'){
		
	require_once("ipsec.inc");
	$config = pfz_cfg();
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
        } else{
            $cname = ipsec_conid($ph1ent);
        }
        
        $conmap[$cname] = $ph1ent['ikeid'];
    }

	$status = ipsec_list_sa();
	$ipsecconnected = array();
	
	$carp_status = pfz_carp_status(false);
	
	//Phase-Status match borrowed from status_ipsec.php	
	if (is_array($status)) {		
		foreach ($status as $l_ikeid=>$ikesa) {
			
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
			if ($ph1idx == $ikeid){
				if ($reqid!=-1) {
					// Asking for Phase2 Status Value
					foreach ($ikesa['child-sas'] as $childsas) {
						if ($childsas['reqid']==$reqid) {
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
	
	switch($valuekey) {
					case 'state':
						$value = pfz_value_mapping('ipsec.state', strtolower($tmp_value));
						if ($carp_status!=0) $value = $value + (10 * ($carp_status-1));						
						break;
					default:
						$value = $tmp_value;
						break;
	}
	
	return $value;
}

// Temperature sensors Discovery
function pfz_temperature_sensors_discovery(){


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

	$json_string = rtrim($json_string,",");
    $json_string .= "]}";

    echo $json_string;

}

// Temperature sensor get value
function pfz_get_temperature($sensorid){

	exec("sysctl '$sensorid' | cut -d ':' -f 2", $value, $code);
	if ($code != 0 or count($value)!=1) {
	    echo "";
	    return;
	} else {
	    echo trim($value[0]);
    }

}


function pfz_carp_status($echo = true){
     //Detect CARP Status
     $config = pfz_cfg();
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

               if ( ($prev_status != $if_status) && (empty($if_status)==false) ) { //Some glitches with GUI
                    if ($prev_status!="") $status_changed = true;
                    $prev_status = $if_status;
               }
          }          
          if ($status_changed) {
               //CARP Status is inconsistent across interfaces
               $ret=3;
               echo 3;          
          } else {
               if ($prev_status=="MASTER")
                    $ret = 1;                    
               else
					$ret = 2;
          }      
     }
     
     if ($echo == true) echo $ret;   
     return $ret;
     
}

// DHCP Checks (copy of status_dhcp_leases.php, waiting for pfsense 2.5)
function pfz_remove_duplicate($array, $field) {
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
function pfz_dhcp_get($valuekey) {

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
					$pools[$p]['name'] = trim($data[$f+2], '"');
					$pools[$p]['name'] = "{$pools[$p]['name']} (" . convert_friendly_interface_to_friendly_descr(substr($pools[$p]['name'], 5)) . ")";
					$pools[$p]['mystate'] = $data[$f+7];
					$pools[$p]['peerstate'] = $data[$f+14];
					$pools[$p]['mydate'] = $data[$f+10];
					$pools[$p]['mydate'] .= " " . $data[$f+11];
					$pools[$p]['peerdate'] = $data[$f+17];
					$pools[$p]['peerdate'] .= " " . $data[$f+18];
					$p++;
					$i++;
					continue 3;
				case "lease":
					$leases[$l]['ip'] = $data[$f+1];
					$leases[$l]['type'] = $dynamic_string;
					$f = $f+2;
					break;
				case "starts":
					$leases[$l]['start'] = $data[$f+2];
					$leases[$l]['start'] .= " " . $data[$f+3];
					$f = $f+3;
					break;
				case "ends":
					if ($data[$f+1] == "never") {
						// Quote from dhcpd.leases(5) man page:
						// If a lease will never expire, date is never instead of an actual date.
						$leases[$l]['end'] = gettext("Never");
						$f = $f+1;
					} else {
						$leases[$l]['end'] = $data[$f+2];
						$leases[$l]['end'] .= " " . $data[$f+3];
						$f = $f+3;
					}
					break;
				case "tstp":
					$f = $f+3;
					break;
				case "tsfp":
					$f = $f+3;
					break;
				case "atsfp":
					$f = $f+3;
					break;
				case "cltt":
					$f = $f+3;
					break;
				case "binding":
					switch ($data[$f+2]) {
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
					$f = $f+1;
					break;
				case "next":
					/* skip the next binding statement */
					$f = $f+3;
					break;
				case "rewind":
					/* skip the rewind binding statement */
					$f = $f+3;
					break;
				case "hardware":
					$leases[$l]['mac'] = $data[$f+2];
					/* check if it's online and the lease is active */
					if (in_array($leases[$l]['ip'], $arpdata_ip)) {
						$leases[$l]['online'] = $online_string;
					} else {
						$leases[$l]['online'] = $offline_string;
					}
					$f = $f+2;
					break;
				case "client-hostname":
					if ($data[$f+1] <> "") {
						$leases[$l]['hostname'] = preg_replace('/"/', '', $data[$f+1]);
					} else {
						$hostname = gethostbyaddr($leases[$l]['ip']);
						if ($hostname <> "") {
							$leases[$l]['hostname'] = $hostname;
						}
					}
					$f = $f+1;
					break;
				case "uid":
					$f = $f+1;
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

	switch ($valuekey){
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

function pfz_dhcpfailover_discovery(){
	//System functions regarding DHCP Leases will be available in the upcoming release of pfSense, so let's wait
	require_once("system.inc");
	$leases = system_get_dhcpleases();
	
	$json_string = '{"data":[';
	
	if (count($leases['failover']) > 0){
		foreach ($leases['failover'] as $data){
			   $json_string .= '{"{#FAILOVER_GROUP}":"' . str_replace(" ", "__", $data['name']) . '"';          
		}
	}

	$json_string = rtrim($json_string,",");
    $json_string .= "]}";     	
    
    echo $json_string;
}

function pfz_dhcp_check_failover()
{
    // Check DHCP Failover Status
    // Returns number of failover pools which state is not normal or
    // different than peer state
    $failover = pfz_dhcp_get("failover");

    return count(array_filter($failover, fn($f) => ($f["mystate"] != "normal") || ($f["mystate"] != $f["peerstate"])));
}

function pfz_dhcp($section, $valuekey = "")
{
    $is_known_section = array_key_exists($section, DHCP_SECTIONS);
    if (!$is_known_section) {
        return;
    }

    DHCP_SECTIONS[$section]();
}

// Packages
function pfz_packages_uptodate()
{
    require_once("pkg-utils.inc");
    $installed_packages = get_pkg_info("all", false, true);

    return count(array_filter(
        $installed_packages,
        fn($p) => $p["version"] != $p["installed_version"]));
}

// System Information
function pfz_get_system_value($section)
{
    if ($section === "packages_update") {
        echo pfz_packages_uptodate();
        return;
    }

    $system_pkg_version = get_system_pkg_version();
    $version = $system_pkg_version["version"];
    $installed_version = $system_pkg_version["installed_version"];

    if ($section === "new_version_available") {
        echo pfz_bint($version, $installed_version);
        return;
    }

    if (array_key_exists($section, $system_pkg_version)) {
        echo $system_pkg_version[$section];
    }
}

//S.M.A.R.T Status
// Taken from /usr/local/www/widgets/widgets/smart_status.widget.php
function pfz_get_smart_status()
{
    foreach (get_smart_drive_list() as $dev) { ## for each found drive do                
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

// Certificats validity date
function pfz_get_cert_date($valuekey){
    $config = pfz_cfg();
    
    $value = 0;
	foreach (array("cert", "ca") as $cert_type) {
		switch ($valuekey){
		case "validFrom.max":
			foreach ($config[$cert_type] as $cert) {
				$certinfo = openssl_x509_parse(base64_decode($cert[crt]));
				if ($value == 0 or $value < $certinfo['validFrom_time_t']) $value = $certinfo['validFrom_time_t'];
            }
			break;
		case "validTo.min":
			foreach ($config[$cert_type] as $cert) {
				$certinfo = openssl_x509_parse(base64_decode($cert[crt]));
				if ($value == 0 or $value > $certinfo['validTo_time_t']) $value = $certinfo['validTo_time_t'];
			}
			break;
		}
	}
	echo $value;
}

// File is present
function pfz_file_exists($filename) {
    echo pfz_bint(file_exists($filename));
}

// Value mappings
// Each value map is represented by an associative array
function pfz_value_mapping($value_name, $value, $default_value = "0")
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

function pfz_discovery($section)
{
    $is_known_section = array_key_exists(strtolower($section), DISCOVERY_SECTION_HANDLERS);
    if (!$is_known_section) {
        return;
    }

    DISCOVERY_SECTION_HANDLERS[$section]();
}

function main($arguments)
{
    $command = strtolower($arguments[1]);
    $parameters = array_slice($arguments, 2);

    $is_known_command = array_key_exists($command, COMMAND_HANDLERS);

    if (!$is_known_command) {
        pfz_test();
        return;
    }

    COMMAND_HANDLERS[$command]($parameters);
}

main($argv);
