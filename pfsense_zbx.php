<?php
/*** 
pfsense_zbx.php - pfSense Zabbix Interface
Version 0.9.3 - 2020-04-26 

Written by Riccardo Bicelli <r.bicelli@gmail.com>
This program is licensed under Apache 2.0 License
*/

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

}


// Interface Discovery
// Improved performance
function pfz_interface_discovery($skip_disabled = true, $skip_unconfigured = true) {
    $ifdescrs = get_configured_interface_with_descr(true);
    $all_hw_ifs = get_interface_arr();
    $merged_ifs=array();

    $output = ['data' => []];

    foreach ($ifdescrs as $pfsense_if_name => $user_if_name ) {
          $ifinfo = get_interface_info($pfsense_if_name);
          $ifinfo["description"] = $user_if_name;
          $ifinfo["pfsense_name"] = $pfsense_if_name;
          $hwname = $ifinfo['hwif'];
          $merged_ifs[$hwname] = $ifinfo;
    }

	foreach ($all_hw_ifs as $hwif) {
	    $record = [];

	    $record['{#IFNAME}'] = $hwif;

	    // needed when using interface names in dependent items via jsonpath
	    $record['{#IFNAMEJ}'] = str_replace('.','_',$hwif);

	    if (!empty($merged_ifs[ $hwif ])) {
	    	if(true === $skip_disabled && isset($merged_ifs[ $hwif ]['enabled'])) {
	    		if($merged_ifs[ $hwif ]['enabled'] != 1) {
	    			continue;
			    }
		    }
		    $record['{#IFDESCR}'] = $merged_ifs[ $hwif ]['description'];
	    } else {
	    	if(true === $skip_unconfigured) {
		        continue;
		    }
	    	else {
			    $record['{#IFDESCR}'] = $hwif;
		    }
	    }

	    $output['data'][] = $record;

    }
    echo json_encode($output);
}

function pfz_interface_discovery_all() {
	pfz_interface_discovery(false, false);
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


// Get OpenVPN Server Value
function pfz_openvpn_servervalue($server_id,$valuekey){
     $servers = pfz_openvpn_get_all_servers();     
     
     foreach($servers as $server) {
          if($server['vpnid']==$server_id){
               $value = $server[$valuekey];
               if ($valuekey=="status") {
                    if ( ($server['mode']=="server_user") || ($server['mode']=="server_tls_user") || ($server['mode']=="server_tls") ){
                         if ($value=="") $value="server_user_listening";                    
                    }                    
               }
          }
     }
     
     switch ($valuekey){     
          
          case "conns":
               //Client Connections: is an array so it is sufficient to count elements                    
               if (is_array($value))
                    $value = count($value);
               else
                    $value = "0";
               break;     
               
          case "status":
               
               $value = pfz_valuemap("openvpn.server.status", $value);
               break;

          case "mode":
               $value = pfz_valuemap("openvpn.server.mode", $value);
               break;
     }
     
     //if ($value=="") $value="none";
     echo $value;
}

//OpenVPN Server/User-Auth Discovery
function pfz_openvpn_server_userdiscovery(){
     $servers = pfz_openvpn_get_all_servers();

     $json_string = '{"data":[';

     foreach ($servers as $server){
          if ( ($server['mode']=='server_user') || ($server['mode']=='server_tls_user') ) {
               if (is_array($server['conns'])) {               
                    $name = trim(preg_replace('/\w{3}(\d)?\:\d{4,5}/i', '', $server['name']));
                    
                    foreach($server['conns'] as $conn) {               
                         $json_string .= '{"{#SERVERID}":"' . $server['vpnid'] . '"';
                         $json_string .= ',"{#SERVERNAME}":"' . $name . '"';
                         $json_string .= ',"{#UNIQUEID}":"' . $server['vpnid'] . '+' . $conn['common_name'] . '"';                         
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
function pfz_openvpn_server_uservalue($unique_id, $valuekey){

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


function pfz_openvpn_clientvalue($client_id, $valuekey){
     $clients = openvpn_get_active_clients();     
     foreach($clients as $client) {
          if($client['vpnid']==$client_id)
               $value = $client[$valuekey];
     }

     switch ($valuekey){        
               
          case "status":
               $value = pfz_valuemap("openvpn.client.status", $value);
               break;

     }

     if ($value=="") $value="none";
     echo $value;
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
function pfz_service_value($name,$value){
     $services = get_services();     
     
     //List of service which are stopped on CARP Slave.
     //For now this is the best way i found for filtering out the triggers
     //Waiting for a way in Zabbix to use Global Regexp in triggers with items discovery
     $stopped_on_carp_slave = array("haproxy","openvpn.","openvpn");
     
     foreach ($services as $service){
          $namecfr=str_replace("__"," ",$service["name"]);
          $carpcfr=str_replace("__"," ",$service["name"]);          

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
     if(array_key_exists($gw,$gws))
          echo $gws[$gw][$valuekey];
}


function pfz_carp_status(){
     //Detect CARP Status
     global $config;
     $status_return = 0;
     $status = get_carp_status();
     $carp_detected_problems = get_single_sysctl("net.inet.carp.demotion");

     if ($status != 0) { //CARP is enabled

          if ($carp_detected_problems != 0) {                              
               echo 4;   //There's some Major Problems with CARP
               return true;
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
               echo 3;          
          } else {
               if ($prev_status=="MASTER")
                    echo 1;
               else
                    echo 2;
          }      
     } else {
          //CARP is Disabled
          echo 0;     
     }
}


//System Information
function pfz_get_system_value($section){
     switch ($section){
          case "version":
               echo( get_system_pkg_version()['version']);
               break;
          case "installed_version":
               echo( get_system_pkg_version()['installed_version']);
               break;
          case "new_version_available":
               $pkgver = get_system_pkg_version();
               if ($pkgver['version']==$pkgver['installed_version'])
                    echo "0";
               else
                    echo "1";
               break;
     }
}


// Value mappings
// Each value map is represented by an associative array
function pfz_valuemap($valuename, $value){

     switch ($valuename){     

          case "openvpn.server.status":          
                    $valuemap = array(
                         "down" => "0",
                         "up" => "1",
                         "none" => "2",
                         "reconnecting; ping-restart" => "3",
                         "waiting" => "4",
                         "server_user_listening" => "5");          
          break;
          
          case "openvpn.client.status":          
                    $valuemap = array(
                         "up" => "1",
                         "down" => "0",
                         "none" => "0",
                         "reconnecting; ping-restart" => "2");          
          break;

          case "openvpn.server.mode":
                    $valuemap = array(
                         "p2p_tls" => "1",
                         "p2p_shared_key" => "2",
                         "server_tls" => "3",
                         "server_user" => "4",
                         "server_tls_user" => "5");          
          break;     
     }

     if (array_key_exists($value, $valuemap))
          return $valuemap[$value];
     
     return "0";
}

//Argument parsers for Discovery
function pfz_discovery($section){
     switch (strtolower($section)){     
          case "gw":
               pfz_gw_discovery();
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
          case "interfaces_all":
               pfz_interface_discovery_all();
               break;
     }         
}

//Main Code
switch (strtolower($argv[1])){     
     case "discovery":
          pfz_discovery($argv[2]);
          break;
     case "gw_value":
          pfz_gw_value($argv[2],$argv[3]);
          break;     
     case "gw_status":
          pfz_gw_rawstatus();
          break;
     case "openvpn_servervalue":
          pfz_openvpn_servervalue($argv[2],$argv[3]);
          break;
     case "openvpn_server_uservalue":
          pfz_openvpn_server_uservalue($argv[2],$argv[3]);
          break;
     case "openvpn_clientvalue":
          pfz_openvpn_clientvalue($argv[2],$argv[3]);
          break;
     case "service_value":
          pfz_service_value($argv[2],$argv[3]);
          break;
     case "carp_status":
          pfz_carp_status();
          break;
     case "if_name":
          pfz_get_if_name($argv[2]);
          break;
     case "system":
          pfz_get_system_value($argv[2]);
          break;
     default:
          pfz_test();
}
