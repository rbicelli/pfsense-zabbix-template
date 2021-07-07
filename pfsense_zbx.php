<?php
/*** 
pfsense_zbx.php - pfSense Zabbix Interface
Version 1.0.5 - 2021-07-05

Written by Riccardo Bicelli <r.bicelli@gmail.com>
This program is licensed under Apache 2.0 License
*/

//Some Useful defines

define('SPEEDTEST_INTERVAL', 8); //Speedtest Interval (in hours)

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
        
        foreach($ifcs as $ifc=>$ifinfo){
                if ($ifinfo["hwif"] == $hwif){
                        $ifdescr = $ifinfo["description"];
                        if (array_key_exists("gateway",$ifinfo)) $has_gw=true;
                        if (strpos($ifinfo["if"],"ovpn")!==false) $is_vpn=true;
                        break;
                }
        }
		
		if ( ($is_wan==false) ||  (($is_wan==true) && ($has_gw==true) && ($is_vpn==false)) ) { 
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
          
          //If the interface has a gateway is considered WAN, so let's do the speedtest
          if (array_key_exists("gateway", $ifinfo)) {				
		  	$ipaddr = $ifinfo['ipaddr'];		
			pfz_speedtest_exec($ifname, $ipaddr);		
		  }
				          	
    }
}

//installs a cron job for speedtests
function pfz_speedtest_cron_install($enable=true){
	//Install Cron Job
	$command = "/usr/local/bin/php " . __FILE__ . " speedtest_cron"; 
	install_cron_job($command, $enable, $minute = "*/15", "*", "*", "*", "*", "root", false);
}        	


function pfz_speedtest_exec ($ifname, $ipaddr){
	
	$filename = "/tmp/speedtest-$ifname";
	$filerun = "/tmp/speedtest-run"; 
	
	if ( (time()-filemtime($filename) > SPEEDTEST_INTERVAL * 3600) || (file_exists($filename)==false) ) {
	  	// file is older than SPEEDTEST_INTERVAL
	  	if ( (time()-filemtime($filerun) > 180 ) ) @unlink($filerun);

		if (file_exists($filerun)==false) {
	  		touch($filerun);
	  		$st_command = "/usr/local/bin/speedtest --source $ipaddr --json > $filename";
			exec ($st_command);
			@unlik($filerun);
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


// Get OpenVPN Server Value
function pfz_openvpn_servervalue($server_id,$valuekey){
     $servers = pfz_openvpn_get_all_servers();     
     
     foreach($servers as $server) {
          if($server['vpnid']==$server_id){
               $value = $server[$valuekey];
               if ($valuekey=="status") {
                    if ( ($server['mode']=="server_user") || ($server['mode']=="server_tls_user") || ($server['mode']=="server_tls") ){
                         if ($value=="") $value="server_user_listening";                    
                    } else if ($server['mode']=="p2p_tls"){
                        // For p2p_tls, ensure we have one client, and return up if it's the case
                        if ($value=="")
                            $value=(is_array($server["conns"]) && count($server["conns"]) > 0) ? "up" : "down";
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

function pfz_openvpn_clientvalue($client_id, $valuekey, $default="none"){
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

     if ($value=="") $value=$default;
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
// 2020-09-28: Corrected Space Replace
function pfz_service_value($name,$value){
     $services = get_services();     
     $name = str_replace("__"," ",$name);
           
     //List of service which are stopped on CARP Slave.
     //For now this is the best way i found for filtering out the triggers
     //Waiting for a way in Zabbix to use Global Regexp in triggers with items discovery
     $stopped_on_carp_slave = array("haproxy","radvd","openvpn.","openvpn");
     
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
          if ($valuekey=="status")
               $value = pfz_valuemap("gateway.status", $value);     
          echo $value;         
     }
}


// IPSEC Discovery
function pfz_ipsec_discovery_ph1(){
	
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

	$json_string = rtrim($json_string,",");
    $json_string .= "]}";     	
    
    echo $json_string;
	
}


function pfz_ipsec_ph1($ikeid,$valuekey){	
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
					if(array_key_exists($valuekey,$data)) {
					if ($valuekey=='disabled')
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

function pfz_ipsec_discovery_ph2(){
	
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

	$json_string = rtrim($json_string,",");
    $json_string .= "]}";     	
    
    echo $json_string;
	
}

function pfz_ipsec_ph2($uniqid, $valuekey){
	require_once("ipsec.inc");
	global $config;
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
				$value = pfz_valuemap("ipsec_ph2." . $valuekey, $data[$valuekey], $data[$valuekey]);
			break;
			}
		}
	}
	echo $value;
}

function pfz_ipsec_status($ikeid,$reqid=-1,$valuekey='state'){
		
	require_once("ipsec.inc");
	global $config;
	init_config_arr(array('ipsec', 'phase1'));
	$a_phase1 = &$config['ipsec']['phase1'];
	$status = ipsec_list_sa();
	$ipsecconnected = array();	
	
	$carp_status = pfz_carp_status(false);
	
	//Phase-Status match borrowed from status_ipsec.php	
	if (is_array($status)) {		
		foreach ($status as $l_ikeid=>$ikesa) {			
			
			if(isset($ikesa['con-id'])){
				$con_id = substr($ikesa['con-id'], 3);
			}else{
				$con_id = filter_var($l_ikeid, FILTER_SANITIZE_NUMBER_INT);
			}
			if ($ikesa['version'] == 1) {
				$ph1idx = $con_id/1000;
				$ipsecconnected[$ph1idx] = $ph1idx;
			} else {
				if (!ipsec_ikeid_used($con_id)) {
					// probably a v2 with split connection then
					$ph1idx = $con_id/1000;
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
						$value = pfz_valuemap('ipsec.state', strtolower($tmp_value));
						if ($carp_status!=0) $value = $value + (10 * ($carp_status-1));						
						break;
					default:
						$value = $tmp_value;
						break;
	}
	
	return $value;
}



function pfz_carp_status($echo = true){
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

function pfz_dhcp_check_failover(){
	// Check DHCP Failover Status
	// Returns number of failover pools which state is not normal or
	// different than peer state
	$failover = pfz_dhcp_get("failover");
	$ret = 0;
	foreach ($failover as $f){
		if ( ($f["mystate"]!="normal") || ($f["mystate"]!=$f["peerstate"])) {
			$ret++;
		}
	}		
	return $ret;	
}

function pfz_dhcp($section, $valuekey=""){
	switch ($section){
		case "failover":
			echo pfz_dhcp_check_failover();
			break;
		default:		
	}
}

//Packages
function pfz_packages_uptodate(){
	require_once("pkg-utils.inc");
	$installed_packages = get_pkg_info('all', false, true);
		
	$ret = 0;

	foreach ($installed_packages as $package){
		if ($package['version']!=$package['installed_version']){
			$ret ++;
		}
	}
	
	return $ret;
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
          case "packages_update":
          		echo pfz_packages_uptodate();
          		break;	
     }
}

// File is present
function pfz_file_exists($filename) {
	if (file_exists($filename))
		echo "1";
	else
		echo "0";
}

// Value mappings
// Each value map is represented by an associative array
function pfz_valuemap($valuename, $value, $default="0"){
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
          
          case "gateway.status":
                    $valuemap = array(
                         "online" => "0",
                         "none" => "0",
                         "loss" => "1",
                         "highdelay" => "2",
                         "highloss" => "3",
                         "force_down" => "4",
                         "down" => "5");          
          break;    
          
          case "ipsec.iketype":
          			$valuemap = array (
          				"auto" => 0,
          				"ikev1" => 1,
          				"ikev2" => 2);
          break;
          
          case "ipsec.mode":
          			$valuemap = array (
          				"main" => 0,
          				"aggressive" => 1);
          break;
          
          case "ipsec.protocol":
          			$valuemap = array (
          				"both" => 0,
          				"inet" => 1,
          				"inet6" => 2);
          break;
          
          case "ipsec_ph2.mode":
          			$valuemap = array (
          				"transport" => 0,
          				"tunnel" => 1,
          				"tunnel6" => 2);
          break;
          
          case "ipsec_ph2.protocol":
          			$valuemap = array (
          				"esp" => 1,
          				"ah" => 2);
          break;

		  case "ipsec.state":
          			$valuemap = array (
          				"established" => 1,
          				"connecting" => 2,
          				"installed" => 1,
          				"rekeyed" => 2);
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
function pfz_discovery($section){
     switch (strtolower($section)){     
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
	 case "if_speedtest_value":
	      pfz_speedtest_cron_install();
	 	  pfz_interface_speedtest_value($argv[2],$argv[3]);
	 	  break;
     case "openvpn_servervalue":
          pfz_openvpn_servervalue($argv[2],$argv[3]);
          break;
     case "openvpn_server_uservalue":
          pfz_openvpn_server_uservalue($argv[2],$argv[3]);
          break;
     case "openvpn_server_uservalue_numeric":
          pfz_openvpn_server_uservalue($argv[2],$argv[3],"0");
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
     case "ipsec_ph1":
          pfz_ipsec_ph1($argv[2],$argv[3]);
          break;
     case "ipsec_ph2":
          pfz_ipsec_ph2($argv[2],$argv[3]);
          break;
     case "dhcp":
     	  pfz_dhcp($argv[2],$argv[3]);
          break;
     case "file_exists":
     	  pfz_file_exists($argv[2]);
     	  break;
     case "speedtest_cron":
     	  pfz_speedtest_cron_install();
     	  pfz_speedtest_cron();
     	  break;
     case "cron_cleanup":
     	  pfz_speedtest_cron_install(false);
     	  break;     	  
     default:
          pfz_test();
}
