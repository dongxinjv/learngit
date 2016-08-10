#!/usr/bin/expect --


package require LOAD
package require SWARM
package require ARUBA
package require IAP
lappend auto_path $env(PATA_ROOT)/tests/INSTANTAP/lib/tcl
source $env(PATA_ROOT)/tests/INSTANTAP/WLAN/SpectrumMonitor/SM_procs.tst
source $env(PATA_ROOT)/tests/INSTANTAP/lib/tcl/iap_expect_lib.lib
STARTSCRIPT

SYNOPSIS "The case is used to test wifi Uplink"

DESCRIPTION "The test cases will use to test wifi Uplink"

proc GetBSSID {handle ssid band} {
	IAP::getToCLIMode $handle
	set output [COMMAND $handle "show ap bss-table"]
	set bssid 0
	if [regexp "(\[\\\da-f\]+:\[\\\da-f\]+:\[\\\da-f\]+:\[\\\da-f\]+:\[\\\da-f\]+:\[\\\da-f\]+)\[\\\s\]+$ssid\[\\\s\]+\\\?\/\\\?\[\\\s\]+\[\\\d\\\.\]+\[\\\s\]+$band" $output - mac] {
		set bssid $mac
	}
	return $bssid
}
proc GetMasterRole {handlelist} {
	#handlelist:
        #example:
        #{IAP1 IAP2 IAP3}
        #You should use braces
        set master_count 0
        foreach handle $handlelist {
                set output ""
                set output [COMMAND $handle "show summary"]
                set master_ip 0
                if [regexp {Master( IP Address)?[\s]+\*\:([\d\.]+)} $output match - ip] {
                        set master_ip $ip
                        set master_handle $handle
                        incr master_count
                }
        }
        if {$master_count != 1} {
                return -1
        }
        return $master_handle
}
proc GetMasterIP {handlelist} {
	#handlelist:
        #example:
        #{IAP1 IAP2 IAP3}
        #You should use braces
        set master_count 0
        foreach handle $handlelist {
                set output ""
                set output [COMMAND $handle "show summary"]
                set master_ip 0
                if [regexp {Master( IP Address)?[\s]+\*\:([\d\.]+)} $output match - ip] {
                        set master_ip $ip
                        incr master_count
                }
        }
        if {$master_count != 1} {
                return -1
        }
        return $master_ip
}
proc IsEthUplink {handle} {
        IAP::getToCLIMode $handle
        set ret [COMMAND $handle "show uplink status"]
        if [regexp {Ethernet[\s]+UP[\s]+[\d][\s]+Yes} $ret] {
                return 1
        }
        return 0
}
proc IsWifiUplink {handle} {
	IAP::getToCLIMode $handle
	set ret [COMMAND $handle "show uplink status"]
	if [regexp {Wifi-sta[\s]+UP[\s]+[\d][\s]+Yes} $ret] {
		return 1
	}
	return 0
}
proc IsEthUplinkDown {handle} {
        IAP::getToCLIMode $handle
        set ret [COMMAND $handle "show uplink status"]
        if [regexp {Ethernet[\s]+DOWN[\s]+[\d][\s]+No} $ret] {
                return 1
        }
        return 0
}
proc IsVPNConnected {handle} {
	IAP::getToCLIMode $handle
	set ret [COMMAND $handle "show vpn status"]
	if [regexp {vpn[\s]+status[\s]+\:up} $ret] {
		return 1
	}
	return 0
}
proc GetIAPBr0IP {handle} {
	IAP::getToCLIMode $handle
	set output [COMMAND $handle "show ip interface"]
	set ip 0
	if [regexp {br0[\s]+([\d\.]+)} $output match br0] {
		set ip $br0
	}
	return $ip
}
proc GetIAPppp0IP {handle} {
	IAP::getToCLIMode $handle
	set output [COMMAND $handle "show ip interface"]
	set ip 0
	if [regexp {ppp0[\s]+([\d\.]+)} $output match ppp0] {
		set ip $ppp0
	}
	return $ip
}
proc GetIAPUPtime {handle} {
	IAP::getToCLIMode $handle
	set info_version [COMMAND $handle "show version"]
	if [regexp {AP uptime is ([^\r^\n]+)} $info_version - t] {puts $t} 
	if [regexp {([\d]+) (year|years)} $t match y] {puts $y}
	if [regexp {([\d]+) (day|days)} $t match d] {puts $d}
	if [regexp {([\d]+) (hour|hours)} $t match h] {puts $h}
	if [regexp {([\d]+) (minute|minutes)} $t match m] {puts $m}
	if [regexp {([\d]+) (second|seconds)} $t match s] {puts $s}
	
	set time 0
	if [info exists y] {set time [expr $y*365]}
	if [info exists d] {set time [expr ($d+$time)*24]}
	if [info exists h] {set time [expr ($h+$time)*60]}
	if [info exists m] {set time [expr ($m+$time)*60]}
	if [info exists s] {set time [expr $s+$time]}
	
	return $time
}
proc IsTheTwoIPBelongToSameNetwork {first_ip second_ip prefix_length} {
	set first_ip_binary [IPaddressToBinary $first_ip]
	set second_ip_binary [IPaddressToBinary $second_ip]
	set first_ip_binary_prefix [string range $first_ip_binary 0 [expr $prefix_length-1]]
	set second_ip_binary_prefix [string range $second_ip_binary 0 [expr $prefix_length-1]]
	
	if {$first_ip_binary_prefix ne "$second_ip_binary_prefix"} {return 0}
	return 1
}
proc IPaddressToBinary {ip} {
	if {![regexp {([\d]+)\.([\d]+)\.([\d]+)\.([\d]+)} $ip match a b c d]} {
		error "The format of ip is incorrect"
	}
	if {![binary scan [format %c $a] "B8" segment1]} {error "transform segment1 to binary failed"}
	if {![binary scan [format %c $b] "B8" segment2]} {error "transform segment2 to binary failed"}
	if {![binary scan [format %c $c] "B8" segment3]} {error "transform segment3 to binary failed"}
	if {![binary scan [format %c $d] "B8" segment4]} {error "transform segment4 to binary failed"}
	
	append ip_binary $segment1 $segment2 $segment3 $segment4
	
	return $ip_binary
}
proc IsPrivateIP {ip} {
	if {![regexp {([\d]+).([\d]+).([\d]+).([\d]+)} $ip match a b c d]} {
		error "IsPrivateIP $ip:The format of ip is incorrect"
	}
	foreach temp "$a $b $c $d" {
		if {$temp < 0 || $temp > 254} {
			error "IsPrivateIP $ip:The format of ip is incorrect"
		}
	}
	if [regexp {169\.254} $ip] {
		return 1
	}
	return 0
}
proc IsPingSuccessful {handle ip {times 3}} {
	IAP::getToCLIMode $handle
	set flag 0
	while {$times != 0} {
		set temp [COMMAND $handle "ping $ip"]
		if {[regexp {5 packets transmitted, 5 packets received, 0% packet loss} $temp]} {
			set flag 1
			break
		}
		incr times -1
	}
	
	return $flag
}
proc GetIP {handle interface} {
	set got_ip_from_dhcp [COMMAND $handle "netsh interface ipv4 set address \"$interface\" dhcp"]
	INFO "-----------------ipconfig /release----------------"
	set releaseip [COMMAND $handle {ipconfig /release}]
	INFO "-----------------ipconfig /renew------------------"
	set ret [COMMAND $handle {ipconfig /renew &}]
	regexp {\[1\] ([\d]+)} $ret match renewippid
	UTIL::Wait 30
	set tasklistrenew [COMMAND $handle "tasklist /fi \"pid eq $renewippid\""]
	if [regexp {ipconfig.exe} $tasklistrenew] {
		UTIL::Wait 30
		set tasklistrenew [COMMAND $handle "tasklist /fi \"pid eq $renewippid\""]
		if [regexp {ipconfig.exe} $tasklistrenew] {
			COMMAND $handle "taskkill /pid $renewippid /f"
		}
	}
	INFO "-----------------ipconfig /all--------------------"
	set ipconfig [COMMAND $handle {ipconfig /all}]
	set lines [split $ipconfig "\n"]
	set p 0
	set q 0
	foreach line $lines {
		if [regexp {^[^\s]} $line] {
		set head $p
		set q 0
		set adapter($head,$q) $line
		incr p
		incr q
		} else {
			if {$q != 0} {
				set adapter($head,$q) $line
				incr q
				set adapter($head,counter) $q
			}
		}
	}
	for {set i 0} {$i != $p} {incr i} {
		if [regexp "$interface\:" $adapter($i,0)] {
			for {set j 1} {$j != $adapter($i,counter)} {incr j} {
				if [regexp {IPv4 Address.*\: ([\d\.]+)} $adapter($i,$j) match ip] {
				return $ip
				}
			}
		}
	}
	return 0
}
proc GetLaptopMAC {handle interface} {
	INFO "-----------------ipconfig /all--------------------"
	set ipconfig [COMMAND $handle {ipconfig /all}]
	set lines [split $ipconfig "\n"]
	set p 0
	set q 0
	foreach line $lines {
		if [regexp {^[^\s]} $line] {
		set head $p
		set q 0
		set adapter($head,$q) $line
		incr p
		incr q
		} else {
			if {$q != 0} {
				set adapter($head,$q) $line
				incr q
				set adapter($head,counter) $q
			}
		}
	}
	for {set i 0} {$i != $p} {incr i} {
		if [regexp "$interface\:" $adapter($i,0)] {
			for {set j 1} {$j != $adapter($i,counter)} {incr j} {
				if [regexp {Physical Address.*\: ([\w\-]+)} $adapter($i,$j) match mac] {
				regsub -all -- "-" $mac ":" mac
				return $mac
				}
			}
		}
	}
	return 0
}
proc ClientGetIP {handle} {
	set IP($handle) [GetIP $handle "Wireless Network Connection"]
	return $IP($handle)
}
proc ResetConsoleServer {} {
		spawn telnet 10.64.18.49
		send \r
		expect -re "Key in your selection:"
		send "s\r"
		expect -re "Key in your selection:"
		send "y\r"
		after 5000
}
proc SendControlC {client_list {info 0}} {
############################################################################################################################
# Name: SendControlC
# Args: client_list
# Sends ctrl-C ( used for stopping iperf on win client)
# Eg.: SendControlC "CLIENT1 CLIENT2"
# Diany Emmanuel
# modified: prateek: Added stats reporting e.g. SendControlC "CLIENT1 CLIENT2" -withStats
############################################################################################################################
    array set buffers ""
    set buffer ""
    set ctlc [CONM::ctlChar c]
    foreach handle $client_list {
        if {[isDevice $handle]} {
            set buffer [CONM::sndRcv $handle "$ctlc" [getVar $handle PROMPT] -timeout 20]
            INFO {$buffer}
            if {0 == $buffer} {
                DISCONNECT $handle
                CONNECT $handle
                set res [CONM::sndRcv $handle "killall -9 iperf\r" [getVar $handle PROMPT] -timeout 60]
                if {$res == 0} {
                    DISCONNECT $handle
                    CONNECT $handle
                }
                return ""
            }
            if {$info == "-withStats"} {
                set buffers($handle) [parseIperfClientData $buffer]
            }
        }
    }
    if {$info == "-withStats"} {
        return [array get buffers]
    }
}
proc ClientConnectPingTest {args} {
############################################################################################################################
# Name: ClientConnectPingTest
# Args: handle:CLIENT ;band:ABAND or GBAND ;IAP:Connect to 
# Client connect to IAP and ping server
# 
# YJ: Added
############################################################################################################################
	STEP "Traffic test!"
	set opts(-handle) "CLIENT1"
	set opts(-BAND) "a"
	set opts(-IAP) "SWARM(MASTER)"
	set opts(-ssid) ""
	set opts(-opmode) ""
	set opts(-passPhrase) ""
	set opts(-server_ip) "192.168.203.1"
	array set opts $args
	PrintArray opts [array get opts]
	
	set output_show_ap_bss_table [COMMAND $opts(-IAP) "show ap bss-table"]
	if {[regexp "Dell AP BSS Table" $output_show_ap_bss_table]} {
		set title "Dell_AP_BSS_Table"
	} elseif {[regexp "Alcatel-Lucent AP BSS Table" $output_show_ap_bss_table]} {
		set title "Alcatel-Lucent_AP_BSS_Table"
	} else {
		set title "Aruba_AP_BSS_Table"
	}	
	set output [ARUBA::parse $output_show_ap_bss_table]
	array set temp $output
	set ABAND $temp($title,phy,0)
	set GBAND $temp($title,phy,1)
	INFO "a-band is $ABAND!"
	INFO "g-band is $GBAND!"
	if {[regexp "g" $ABAND]} {
		set ABAND $temp($title,phy,1)
		set GBAND $temp($title,phy,0)
	}
	STEP "Configure CLient profile"
	createXML2 $opts(-handle) $opts(-ssid) $opts(-opmode) $opts(-passPhrase)
	set client_tool "[getVar $opts(-handle) SOFTWARE.CLIENT.PATH]/[getVar $opts(-handle) SOFTWARE.CLIENT.EXE]"
	array set win_wireless_interface [ getClientInterfaceInfo $opts(-handle) [ getVar $opts(-handle) INTERFACE.WIRELESS.ADAPTER] ]
	
	STEP "Client connect!"
	if {$opts(-BAND) == "a"} {
		set BAND $ABAND
	} else {
		set BAND $GBAND
	}
	set master_bssid [ regsub -all {:} [ getBSSID $opts(-IAP) $opts(-ssid) $BAND ] ""]
	array set BSSIDs "$opts(-IAP)$opts(-ssid)$BAND $master_bssid"
	RETRY {
		connectWinClient $opts(-handle) $BSSIDs($opts(-IAP)$opts(-ssid)$BAND) $opts(-ssid)
		sleep 20
		set result [getInfoClientTable $opts(-IAP) $win_wireless_interface(Physical Address) BSSID]
		regsub -all {:} $result "" result
	} -condition { $result == $BSSIDs($opts(-IAP)$opts(-ssid)$BAND)
	} -onFail {
		FAIL "FAIL: client not on expected $opts(-IAP) BSSID"
	} -count 5 -onPass {
		PASS "client connected"
	} -wait 5
	COMMAND $opts(-IAP) "show client"

	STEP "Client ping external PC server"
	set ret [WIN::pingIp $opts(-handle) $opts(-server_ip) -count 10 -passPer 60 -timeout 40]
	if {$ret != 1} {
		FAIL "CLIENT ping $opts(-server_ip) failed"
	}
	
	STEP "client disconnects from IAP"
	sleep 5
	RETRY {
		COMMAND $opts(-handle) "$client_tool dc"
		STEP "Check the connecting result"
		sleep 5
		set cmd_gs [COMMAND $opts(-handle) "$client_tool gs"] 
	} -condition {
		[regexp {"disconnected"} $cmd_gs]
	} -count 5 -onPass {
		PASS "Client disconnected"
	} -onFail {
		FAIL "Client disconnected failed"
	} -wait 10		
}
#2.4G band
set channel_1 2.412
set channel_6 2.437
set channel_11 2.462
#5G band
set channel_149 5.745
set channel_153 5.765
set	channel_157 5.785
set	channel_161 5.805
set channel_165 5.825


CASE SETUP {Configure the test bed. 2IAP should be in master role} {
	set server_ip "192.168.72.1"
	STEP "Enable the Ethernet ports of the Service IAP and WiFi uplink client IAP, and shutdown the others."
	CONNECT IAP1
	CONNECT IAP2
	CONNECT LAPTOP1
	CONNECT LAPTOP2

	set rand [expr {int(rand()*1000)}]
	set client_ap_ssid "client_ap_ssid$rand"
	set eth0_port_serIAP [getVar IAP1 INTERFACE.ETH0.SWITCH.PORT]
	set eth0_port_cltIAP [getVar IAP2 INTERFACE.ETH0.SWITCH.PORT]
	CONNECT SWITCH
	COMMAND SWITCH {
		configure terminal
		interface $eth0_port_serIAP
		no shutdown
		exit
		interface $eth0_port_cltIAP
		no shutdown
		exit
		interface-profile poe-profile g2
		no enable
		exit
		interface-profile poe-profile g3
		no enable
		exit
		interface-profile poe-profile g12
		no enable
		exit
		interface-profile poe-profile g13
		no enable
		exit
		}
	DISCONNECT SWITCH

	STEP "Convert IAP2 to standalone mode"

    if [regexp -nocase "standalone" [showSwarm IAP2 mode]] {
        PASS "IAP2 already in standalone mode"
    } else {
		COMMAND IAP2 "config t"
		COMMAND IAP2 "no extended-ssid"
		COMMAND IAP2 "end"
		COMMAND IAP2 "swarm standalone"
		sleep 2
		IAP::Reload IAP2
	}
	sleep 10
	CONNECT IAP2
	if [regexp -nocase "standalone" [showSwarm IAP2 mode]] {
		PASS "IAP2 convcerted to standalone mode"
	} else {
		FAIL "IAP2 conversion to standalone mode failed" -ABORT SCRIPT
	}	
	STEP "Check the role of the service IAP, it should be master."
	RETRY {
		set IAP1masterIP [GetMasterIP {IAP1}]
		set IAP1br0IP [GetIAPBr0IP {IAP1}]
	} -condition {
		[regexp -nocase $IAP1masterIP $IAP1br0IP]
	} -count 2 -onPass {
		PASS "The service IAP in this test bed is master role."
	} -onFail {
		FAIL "The service IAP is not in master role!" -ABORT SCRIPT
	} -wait 3
	
	STEP "Check the role of the client IAP, it should be master."
	RETRY {
		set IAP2masterIP [GetMasterIP {IAP2}]
		set IAP2br0IP [GetIAPBr0IP {IAP2}]
	} -condition {
		[regexp -nocase $IAP2masterIP $IAP2br0IP]
	} -count 2 -onPass {
		PASS "The client IAP in this test bed is master role."
	} -onFail {
		FAIL "The client IAP is not in master role!" -ABORT SCRIPT
	} -wait 3
	ADD_TO_CLEANUP {
		CONNECT IAP1
		CONNECT IAP2
		IAP::FactoryReset IAP1 -reset 1
		IAP::FactoryReset IAP2 -reset 1
		DISCONNECT IAP1
		DISCONNECT IAP2
		DISCONNECT LAPTOP1
		DISCONNECT LAPTOP2
	} -type script
} 
CASE RN-4014 {WiFi-uplink use 2.4GHz, authentication use OPEN,Verify the WiFi-uplink functionality.} {
	CONNECT IAP1
	CONNECT IAP2
	CONNECT LAPTOP1
	STEP "Configure the SSID on service IAP. And configure the service IAP 2.4G channel as channel 6."

	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	
	set config {
		wlan ssid-profile auto-uplinktest
		essid auto-uplinktest
		type employee
		opmode opensystem
		exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "Config ssid-profile failed !$results" -ABORT CASE
		}
	
	set config {
		wlan access-rule auto-uplinktest
		rule any any match any any any permit
		exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$Config access-rule failed !$results" -ABORT CASE
		}

	set config {
		g-channel 6 20
	}
	set results [swarm::Action $master_ip $sid $config -ip $master_ip]
		if {$results != 1} {
			FAIL "Config static 2.4g channel failed! $results" -ABORT CASE
		}
	
	STEP "Check RUNNING-CONFIGURATION on service IAP."
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running"]
	} -condition {
		[regexp -nocase "essid auto-uplinktest" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The SSID configuration of the service IAP was configured successfully."
	} -onFail {
		FAIL "The SSID was configured failed" -ABORT CASE
	} -wait 10

	STEP "Configure the WiFi-uplink on WiFi-uplink IAP."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
	    no extended-ssid
		wlan ssid-profile wifi_uplink_client_ap
		 essid wifi_uplink_client_ap
		 type employee
		 opmode opensystem
		 vlan guest
		 exit
		 wlan access-rule wifi_uplink_client_ap
		 rule any any match any any any permit
		 exit
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite clear
		 no wpa-passphrase
		 uplink-band dot11g
		 exit
		uplink
		 no preemption
		 enforce wifi
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  sleep 10
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba101" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10
	
	STEP "Check the actual RF band which the wifi-uplink functionality use on client IAP."
	RETRY {
		IAP::getFullAccess IAP2
		set out_iwconfig [COMMAND IAP2 "iwconfig\n"]
		COMMAND IAP2 "exit\n"
	} -condition {
		[regexp -nocase "aruba101\[\\s\]+IEEE 802.11ng\[\\s\]+ESSID:\"auto-uplinktest\"" $out_iwconfig ]
	} -count 10 -onPass {
		PASS "The client IAP establish WiFi uplink on NG 2.4 band actually."
	} -onFail {
		FAIL "The client IAP work on the wrong band." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND a -IAP IAP1 -ssid "auto-uplinktest" -opmode opensystem
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP2 -BAND a -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode opensystem
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-6813 {WiFi-uplink use 2.4GHz, authentication use OPEN. Change the 2.4G channel on the service IAP. Verify the client IAP can change the 2.4G tunnel to follow the service and connect to the service IAP.} {
	CONNECT IAP1
	CONNECT IAP2
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba101" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10
	
	STEP "Change the channel on 2.4G band from channel 6 to channel 11 on service IAP, then check the WiFi-uplink status on client IAP after a few seconds."
	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	set config {
		g-channel 11 20
	}
	set results [swarm::Action $master_ip $sid $config -ip $master_ip]
	if {$results != 1} {
		FAIL "Channe change failed! $results" -ABORT CASE
	}
	sleep 10
	STEP "After channel changed,Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba101" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10	
	STEP "Check the actual RF band on client IAP and service IAP, they must be same, then we can verify that the client IAP followed the change of channel on service IAP."
	RETRY {
		IAP::getFullAccess IAP1
		IAP::getFullAccess IAP2
		set out_iwconfig_iap1 [COMMAND IAP1 "iwconfig\n"]
		set out_iwconfig_iap2 [COMMAND IAP2 "iwconfig\n"]
		COMMAND IAP1 "exit\n"
		COMMAND IAP2 "exit\n"
	} -condition {
		[regexp -nocase "aruba101\[\\s\]+IEEE 802.11ng\[\\s\]+ESSID:\"auto-uplinktest\"" $out_iwconfig_iap2 ] && [regexp -nocase $channel_11 $out_iwconfig_iap2 ] && [regexp -nocase $channel_11 $out_iwconfig_iap1 ]
	} -count 10 -onPass {
		PASS "The client IAP followed the change of channel on the service IAP."
	} -onFail {
		FAIL "The client IAP may have some trouble on scaning." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND g -IAP IAP1 -ssid "auto-uplinktest" -opmode opensystem
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP2 -BAND g -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode opensystem
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-20090 {WiFi-uplink use 2.4GHz, authentication use WPA-TKIP-PSK. Verify the WiFi-uplink functionality.} {

	CONNECT IAP1
	CONNECT IAP2
	STEP "Configure the SSID on service IAP."
	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	
	set config {
		wlan ssid-profile auto-uplinktest
		 essid auto-uplinktest
		 type employee
		 opmode wpa-psk-tkip
		 wpa-passphrase 12345678
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	set config {
		wlan access-rule auto-uplinktest
		 rule any any match any any any permit
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	STEP "Check RUNNING-CONFIGURATION on service IAP."
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running"]
	} -condition {
		[regexp -nocase "essid auto-uplinktest" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The SSID configuration of the service IAP was configured successfully."
	} -onFail {
		FAIL "The SSID was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Configure the WiFi-uplink on WiFi-uplink IAP."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
	    no extended-ssid
		wlan ssid-profile wifi_uplink_client_ap
		 essid wifi_uplink_client_ap
		 type employee
		 opmode wpa-psk-tkip
		 wpa-passphrase 12345678
		 vlan guest
		 exit
		 wlan access-rule wifi_uplink_client_ap
		 rule any any match any any any permit
		 exit
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite wpa-tkip-psk
		 wpa-passphrase 12345678
		 uplink-band dot11g
		 exit
		uplink
		 no preemption
		 enforce wifi
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10

	STEP "Check the WiFi-uplink configuration."	
	RETRY {
		set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
		[ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Check the WiFi-uplink status and uplink status."
	sleep 10
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba101" $wifiuplkstatus_client_IAP ] 
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10

	STEP "Check the actual RF band which the wifi-uplink functionality use on client IAP."
	RETRY {
		IAP::getFullAccess IAP2
		set out_iwconfig [COMMAND IAP2 "iwconfig\n"]
		COMMAND IAP2 "exit\n"
	} -condition {
		[regexp -nocase "aruba101\[\\s\]+IEEE 802.11ng\[\\s\]+ESSID:\"auto-uplinktest\"" $out_iwconfig ]
	} -count 10 -onPass {
		PASS "The client IAP establish WiFi uplink on NA 2.4G band actually."
	} -onFail {
		FAIL "The client IAP work on the wrong band." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND a -IAP IAP1 -ssid "auto-uplinktest" -opmode wpa-psk-tkip -passPhrase 12345678
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP2 -BAND a -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode wpa-psk-tkip -passPhrase 12345678
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-20091 {WiFi-uplink use 2.4GHz, authentication use WPA2-AES-PSK. Verify the WiFi-uplink functionality.} {
	CONNECT IAP1
	CONNECT IAP2
	STEP "Configure the SSID on service IAP."
	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
		wlan ssid-profile auto-uplinktest
		 essid auto-uplinktest
		 type employee
		 opmode wpa2-psk-aes
		 wpa-passphrase 12345678
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	set config {
		wlan access-rule auto-uplinktest
		 rule any any match any any any permit
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	STEP "Check RUNNING-CONFIGURATION on service IAP."
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running"]
	} -condition {
		[regexp -nocase "essid auto-uplinktest" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The SSID configuration of the service IAP was configured successfully."
	} -onFail {
		FAIL "The SSID was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Configure the WiFi-uplink on WiFi-uplink IAP."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
	    no extended-ssid
		wlan ssid-profile wifi_uplink_client_ap
		 essid wifi_uplink_client_ap
		 type employee
		 opmode wpa2-psk-aes
		 wpa-passphrase 12345678
		 vlan guest
		 exit
		 wlan access-rule wifi_uplink_client_ap
		 rule any any match any any any permit
		 exit
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite wpa2-ccmp-psk
		 wpa-passphrase 12345678
		 uplink-band dot11g
		 exit
		uplink
		 no preemption
		 enforce wifi
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10

	STEP "Check the WiFi-uplink configuration."	
	RETRY {
		set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
		[ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba101" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10
	STEP "Check the actual RF band which the wifi-uplink functionality use on client IAP."
	RETRY {
		IAP::getFullAccess IAP2
		set out_iwconfig [COMMAND IAP2 "iwconfig\n"]
		COMMAND IAP2 "exit\n"
	} -condition {
		[regexp -nocase "aruba101\[\\s\]+IEEE 802.11ng\[\\s\]+ESSID:\"auto-uplinktest\"" $out_iwconfig ]
	} -count 10 -onPass {
		PASS "The client IAP establish WiFi uplink on NG 2.4G band actually."
	} -onFail {
		FAIL "The client IAP work on the wrong band." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND a -IAP IAP1 -ssid "auto-uplinktest" -opmode wpa2-psk-aes -passPhrase 12345678
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP2 -BAND a -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode wpa2-psk-aes -passPhrase 12345678

	DISCONNECT IAP1
	DISCONNECT IAP2	
}
CASE RN-4320 {WiFi-uplink use 5GHz, authentication use OPEN. Verify the WiFi-uplink functionality.} {

	CONNECT IAP1
	CONNECT IAP2
	STEP "Configure the SSID on service IAP."
    set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	
	set config {
		wlan ssid-profile auto-uplinktest
		 essid auto-uplinktest
		 type employee
		 opmode opensystem
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	set config {
		wlan access-rule auto-uplinktest
		 rule any any match any any any permit
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	set config {
		a-channel 149 20
	}
	set results [swarm::Action $master_ip $sid $config -ip $master_ip]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	STEP "Check RUNNING-CONFIGURATION on service IAP."
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running"]
	} -condition {
		[regexp -nocase "essid auto-uplinktest" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The SSID configuration of the service IAP was configured successfully."
	} -onFail {
		FAIL "The SSID was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Configure the WiFi-uplink on WiFi-uplink IAP."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
	     no extended-ssid
		wlan ssid-profile wifi_uplink_client_ap
		 essid wifi_uplink_client_ap
		 type employee
		 opmode opensystem
		 vlan guest
		 exit
		 wlan access-rule wifi_uplink_client_ap
		 rule any any match any any any permit
		 exit
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite clear
		 no wpa-passphrase
		 uplink-band dot11a
		 exit
		uplink
		 no preemption
		 enforce wifi
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10

	STEP "Check the WiFi-uplink configuration."	
	RETRY {
		set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
		[ regexp -nocase "auto-uplinktest" $out_client_IAP ] && [ regexp -nocase "uplink-band dot11a" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "5, Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba001" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10
	STEP "Check the actual RF band which the wifi-uplink functionality use on client IAP."
	RETRY {
		IAP::getFullAccess IAP2
		set out_iwconfig [COMMAND IAP2 "iwconfig\n"]
		COMMAND IAP2 "exit\n"
	} -condition {
		[regexp -nocase "aruba001\[\\s\]+IEEE 802.11na\[\\s\]+ESSID:\"auto-uplinktest\"" $out_iwconfig ]
	} -count 10 -onPass {
		PASS "The client IAP establish WiFi uplink on NA 5G band actually."
	} -onFail {
		FAIL "The client IAP work on the wrong band." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND a -IAP IAP1 -ssid "auto-uplinktest" -opmode opensystem
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP2 -BAND a -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode opensystem
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-6811 {WiFi-uplink use 5GHz, authentication use OPEN. Change the 5G channel on the service IAP. Verify the client IAP can change the 5G tunnel to follow the service and connect to the service IAP.} {
	CONNECT IAP1
	CONNECT IAP2
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba101" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10
	
	STEP "Change the channel on 5G band from channel 149 to channel 153 on service IAP, then check the WiFi-uplink status on client IAP after a few seconds."
	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	set config {
		a-channel 153 20
	}
	set results [swarm::Action $master_ip $sid $config -ip $master_ip]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	sleep 10
	STEP "After channel changed,Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba101" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10		
	STEP "Check the actual RF band on client IAP and service IAP, they must be same, then we can verify that the client IAP followed the change of channel on service IAP."
	RETRY {
		IAP::getFullAccess IAP1
		IAP::getFullAccess IAP2
		set out_iwconfig_iap1 [COMMAND IAP1 "iwconfig\n"]
		set out_iwconfig_iap2 [COMMAND IAP2 "iwconfig\n"]
		COMMAND IAP1 "exit\n"
		COMMAND IAP2 "exit\n"
	} -condition {
		[regexp -nocase "aruba001\[\\s\]+IEEE 802.11na\[\\s\]+ESSID:\"auto-uplinktest\"" $out_iwconfig_iap2 ] && [regexp -nocase $channel_153 $out_iwconfig_iap2 ] && [regexp -nocase $channel_153 $out_iwconfig_iap1 ]
	} -count 10 -onPass {
		PASS "The client IAP followed the change of channel on the service IAP."
	} -onFail {
		FAIL "The client IAP may have some trouble on scaning." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND a -IAP IAP1 -ssid "auto-uplinktest" -opmode opensystem
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP2 -BAND a -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode opensystem
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-4319 {WiFi-uplink use 5GHz, authentication use WPA-TKIP-PSK. Verify the WiFi-uplink functionality.} {

	CONNECT IAP1
	CONNECT IAP2
	STEP "1, Configure the SSID on service IAP."

	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
		wlan ssid-profile auto-uplinktest
		 essid auto-uplinktest
		 type employee
		 opmode wpa-psk-tkip
		 wpa-passphrase 12345678
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	set config {
		wlan access-rule auto-uplinktest
		 rule any any match any any any permit
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	STEP "Check RUNNING-CONFIGURATION on service IAP."
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running"]
	} -condition {
		[regexp -nocase "essid auto-uplinktest" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The SSID configuration of the service IAP was configured successfully."
	} -onFail {
		FAIL "The SSID was configured failed" -ABORT CASE
	} -wait 10	
	
	STEP "Configure the WiFi-uplink on WiFi-uplink IAP."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
	     no extended-ssid
		wlan ssid-profile wifi_uplink_client_ap
		 essid wifi_uplink_client_ap
		 type employee
		 opmode wpa-psk-tkip
		 wpa-passphrase 12345678
		 vlan guest
		 exit
		 wlan access-rule wifi_uplink_client_ap
		 rule any any match any any any permit
		 exit
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite wpa-tkip-psk
		 wpa-passphrase 12345678
		 uplink-band dot11a
		 exit
		uplink
		 no preemption
		 enforce wifi
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10

	STEP "Check the WiFi-uplink configuration."	
	RETRY {
		set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
		[ regexp -nocase "auto-uplinktest" $out_client_IAP ] && [ regexp -nocase "uplink-band dot11a" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba001" $wifiuplkstatus_client_IAP ] 
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10

	STEP "Check the actual RF band which the wifi-uplink functionality use on client IAP."
	RETRY {
		IAP::getFullAccess IAP2
		set out_iwconfig [COMMAND IAP2 "iwconfig\n"]
		COMMAND IAP2 "exit\n"
	} -condition {
		[regexp -nocase "aruba001\[\\s\]+IEEE 802.11na\[\\s\]+ESSID:\"auto-uplinktest\"" $out_iwconfig ]
	} -count 10 -onPass {
		PASS "The client IAP establish WiFi uplink on NA 5G band actually."
	} -onFail {
		FAIL "The client IAP work on the wrong band." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND a -IAP IAP1 -ssid "auto-uplinktest" -opmode wpa-psk-tkip -passPhrase 12345678
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP2 -BAND a -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode wpa-psk-tkip -passPhrase 12345678
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-14705 {WiFi-uplink use 5GHz, authentication use WPA2-AES-PSK. Verify the WiFi-uplink functionality.} {
	CONNECT IAP1
	CONNECT IAP2
	STEP "Configure the SSID on service IAP."

	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	
	set config {
		wlan ssid-profile auto-uplinktest
		 essid auto-uplinktest
		 type employee
		 opmode wpa2-psk-aes
		 wpa-passphrase 12345678
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	set config {
		wlan access-rule auto-uplinktest
		 rule any any match any any any permit
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	STEP "Check RUNNING-CONFIGURATION on service IAP."
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running"]
	} -condition {
		[regexp -nocase "essid auto-uplinktest" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The SSID configuration of the service IAP was configured successfully."
	} -onFail {
		FAIL "The SSID was configured failed" -ABORT CASE
	} -wait 10

	STEP "Configure the WiFi-uplink on WiFi-uplink IAP."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
		 no extended-ssid
		wlan ssid-profile wifi_uplink_client_ap
		 essid wifi_uplink_client_ap
		 type employee
		 opmode wpa2-psk-aes
		 wpa-passphrase 12345678
		 vlan guest
		 exit
		 wlan access-rule wifi_uplink_client_ap
		 rule any any match any any any permit
		 exit
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite wpa2-ccmp-psk
		 wpa-passphrase 12345678
		 uplink-band dot11a
		 exit
		uplink
		 no preemption
		 enforce wifi
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10

	STEP "Check the WiFi-uplink configuration."	
	RETRY {
		set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
		[ regexp -nocase "auto-uplinktest" $out_client_IAP ] && [ regexp -nocase "uplink-band dot11a" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba001" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10

	STEP "Check the actual RF band which the wifi-uplink functionality use on client IAP."
	RETRY {
		IAP::getFullAccess IAP2
		set out_iwconfig [COMMAND IAP2 "iwconfig\n"]
		COMMAND IAP2 "exit\n"
	} -condition {
		[regexp -nocase "aruba001\[\\s\]+IEEE 802.11na\[\\s\]+ESSID:\"auto-uplinktest\"" $out_iwconfig ]
	} -count 10 -onPass {
		PASS "The client IAP establish WiFi uplink on NA 5G band actually."
	} -onFail {
		FAIL "The client IAP work on the wrong band." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND a -IAP IAP1 -ssid "auto-uplinktest" -opmode wpa2-psk-aes -passPhrase 12345678
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP2 -BAND a -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode wpa2-psk-aes -passPhrase 12345678
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-4321_RN-4021 {WiFi-uplink use 5GHz, authentication use WPA2-AES-PSK. Verify the WiFi-uplink IAP can be configured "enforce eth0" and this configuration can work well.} {
	CONNECT IAP1
	CONNECT IAP2
	
	STEP "Check the WiFi-uplink status and uplink status directly."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba001" $wifiuplkstatus_client_IAP ] 
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}

	STEP "Get the new br0 IP address, and configure the 'enforce ethernet' by WebUI."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
	     no extended-ssid
		wlan ssid-profile wifi_uplink_client_ap
		 essid wifi_uplink_client_ap
		 type employee
		 opmode wpa2-psk-aes
		 wpa-passphrase 12345678
		 vlan guest
		 exit
		 wlan access-rule wifi_uplink_client_ap
		 rule any any match any any any permit
		 exit
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite wpa2-ccmp-psk
		 wpa-passphrase 12345678
		 uplink-band dot11a
		 exit
		uplink
		 no preemption
		 enforce ethernet
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	STEP "Check the wifi-uplink status and the uplink the IAP use."
	RETRY {
		set out_wifi_uplink [COMMAND IAP2 "show wifi-uplink status\n"]
		set out_uplink [COMMAND IAP2 "show uplink status\n"]
	} -condition {
		[regexp -nocase "configured\[\\s\]+:YES" $out_wifi_uplink] && [regexp -nocase "enabled\[\\s\]+:NO" $out_wifi_uplink] && [regexp -nocase "eth0\[\\s\]+UP\[\\s\]+0\[\\s\]+Yes" $out_uplink ]
	} -count 10 -onPass {
		PASS "The eth0 ports is the current uplink."
	} -onFail {
		FAIL "The uplink which the IAP choose is wrong." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND g -IAP IAP1 -ssid "auto-uplinktest" -opmode wpa2-psk-aes -passPhrase 12345678
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP2 -BAND g -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode wpa2-psk-aes -passPhrase 12345678
	
	STEP "Get the new br0 IP address, and configure the 'enforce wifi' back by WebUI."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	sleep 15
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
	    no extended-ssid
		wlan ssid-profile wifi_uplink_client_ap
		 essid wifi_uplink_client_ap
		 type employee
		 opmode wpa2-psk-aes
		 wpa-passphrase 12345678
		 vlan guest
		 exit
		 wlan access-rule wifi_uplink_client_ap
		 rule any any match any any any permit
		 exit
		uplink
		 no preemption
		 enforce wifi
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	STEP "Check the wifi-uplink status and the uplink the IAP use."
	RETRY {
		set out_wifi_uplink [COMMAND IAP2 "show wifi-uplink status\n"]
		set out_uplink [COMMAND IAP2 "show uplink status\n"]
	} -condition {
		[regexp -nocase "configured\[\\s\]+:YES" $out_wifi_uplink] && [regexp -nocase "enabled\[\\s\]+:YES" $out_wifi_uplink] && [regexp -nocase "wifi-sta\[\\s\]+up" $out_uplink ]
	} -count 10 -onPass {
		PASS "The WiFi uplink was established successfully."
	} -onFail {
		FAIL "The WiFi uplink was established failed." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND g -IAP IAP1 -ssid "auto-uplinktest" -opmode wpa2-psk-aes -passPhrase 12345678
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP2 -BAND g -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode wpa2-psk-aes -passPhrase 12345678
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-4022 {WiFi-uplink use 5GHz, authentication use WPA2-AES-PSK. Verify the WiFi-uplink functionality when the eth0 status is down.} {
	CONNECT IAP1
	CONNECT IAP2
	STEP "Configure the SSID on service IAP."

	INFO "Shutdown the switch port which connect to the eth0 of the client IAP."
	CONNECT SWITCH
	COMMAND SWITCH {
		configure terminal
		interface $eth0_port_cltIAP
		shutdown
		exit
	}
	DISCONNECT SWITCH
	ADD_TO_CLEANUP {
		CONNECT SWITCH
		COMMAND SWITCH {
			configure terminal
			interface $eth0_port_cltIAP
			no shutdown
			exit
		}
		DISCONNECT SWITCH
	} -type case

	INFO "Reload the client IAP, wait 240 seconds.\n"
	IAP::Reload IAP2 -timeout 240 -getTo null
	DISCONNECT IAP2
	CONNECT IAP2

	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba001" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP] && [regexp -nocase "eth0\[\\s\]+down" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10

	STEP "Check the actual RF band which the wifi-uplink functionality use on client IAP."
	RETRY {
		IAP::getFullAccess IAP2
		set out_iwconfig [COMMAND IAP2 "iwconfig\n"]
		COMMAND IAP2 "exit\n"
	} -condition {
		[regexp -nocase "aruba001\[\\s\]+IEEE 802.11na\[\\s\]+ESSID:\"auto-uplinktest\"" $out_iwconfig ]
	} -count 10 -onPass {
		PASS "The client IAP establish WiFi uplink on NA 5G band actually."
	} -onFail {
		FAIL "The client IAP work on the wrong band." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND g -IAP IAP1 -ssid "auto-uplinktest" -opmode wpa2-psk-aes -passPhrase 12345678
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP2 -BAND g -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode wpa2-psk-aes -passPhrase 12345678
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-4013 {WiFi-uplink use 5GHz, authentication use WPA2-AES-PSK. Verify the client IAP can follow the HT mode of the service IAP.} {
	CONNECT IAP1
	CONNECT IAP2
	STEP "Configure the SSID on service IAP."

	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	
	set config {
		wlan ssid-profile auto-uplinktest
		 essid auto-uplinktest
		 type employee
		 opmode wpa2-psk-aes
		 wpa-passphrase 12345678
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}

	set config {
		wlan access-rule auto-uplinktest
		 rule any any match any any any permit
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	set config {
		arm 
		 wide-bands 5ghz
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	STEP "Check RUNNING-CONFIGURATION on service IAP."
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running | include 5ghz\n"]
	} -condition {
		[regexp -nocase "wide-bands 5ghz" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The Wide band configuration of the service IAP was configured successfully."
	} -onFail {
		FAIL "The Wide band was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Configure the WiFi-uplink on WiFi-uplink IAP."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
	     no extended-ssid
		wlan ssid-profile wifi_uplink_client_ap
		 essid wifi_uplink_client_ap
		 type employee
		 opmode opensystem
		 vlan guest
		 exit
		 wlan access-rule wifi_uplink_client_ap
		 rule any any match any any any permit
		 exit
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite wpa2-ccmp-psk
		 wpa-passphrase 12345678
		 uplink-band dot11a
		 exit
		uplink
		 no preemption
		 enforce wifi
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		COMMAND IAP1 "show running-config\n"
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba001" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}

	STEP "Check the width of the client IAP 5G band and the width of the service IAP 5G band. Both of them should be HT40 mode."
	RETRY {
		IAP::getFullAccess IAP1
		set nchannel_IAP1 [COMMAND IAP1 "cat /proc/sys/dev/wifi0/nchannel\n"]
		regexp {([\d]+)[\s~#]*$} $nchannel_IAP1 - nchannel_IAP1
		COMMAND IAP1 "exit\n"
		IAP::getFullAccess IAP2
		set nchannel_IAP2 [COMMAND IAP2 "cat /proc/sys/dev/wifi0/nchannel\n"]
		regexp {([\d]+)[\s~#]*$} $nchannel_IAP2 - nchannel_IAP2
		COMMAND IAP2 "exit\n"
	} -condition {
		[regexp $nchannel_IAP1 $nchannel_IAP2 ] && [expr { $nchannel_IAP1>256 } ] && [expr { $nchannel_IAP2>256 } ]
	} -count 10 -onPass {
		PASS "The client IAP used a wide 5G channel to connect to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP used a wide 5G channel to connect to the service IAP failed." -ABORT CASE
	} -wait 10

	STEP "Configure the HT20 mode on the 5G channel of the service IAP. Then check the configuration."
	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	set config {
		arm 
		 wide-bands none
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
		
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running | include none\n"]
	} -condition {
		[regexp -nocase "wide-bands none" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The HT20 mode configuration of the service IAP was configured successfully."
	} -onFail {
		FAIL "The HT20 mode was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba001" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10
	
	STEP "Check the width of the client IAP 5G band and the width of the service IAP 5G band. Both of them should be HT20 mode."
	RETRY {
		IAP::getFullAccess IAP1
		set nchannel_IAP1 [COMMAND IAP1 "cat /proc/sys/dev/wifi0/nchannel\n"]
		regexp {([\d]+)[\s~#]*$} $nchannel_IAP1 - nchannel_IAP1
		COMMAND IAP1 "exit\n"
		IAP::getFullAccess IAP2
		set nchannel_IAP2 [COMMAND IAP2 "cat /proc/sys/dev/wifi0/nchannel\n"]
		regexp {([\d]+)[\s~#]*$} $nchannel_IAP2 - nchannel_IAP2
		COMMAND IAP2 "exit\n"
	} -condition {
				[regexp $nchannel_IAP1 $nchannel_IAP2 ] && [expr { $nchannel_IAP1<256 } ] && [expr { $nchannel_IAP2<256 } ]
	} -count 10 -onPass {
		PASS "The client IAP used a HT20 mode 5G channel to connect to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP used a HT20 mode 5G channel to connect to the service IAP failed." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND a -IAP IAP1 -ssid "auto-uplinktest" -opmode wpa2-psk-aes -passPhrase 12345678
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP2 -BAND a -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode opensystem
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-5149 {WiFi-uplink use 5GHz, authentication use WPA2-AES-PSK. Verify the client IAP can follow the legacy configuration of the service IAP.} {
	CONNECT IAP1
	CONNECT IAP2
	STEP "1, Configure the SSID on service IAP."

	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
		wlan ssid-profile auto-uplinktest
		 essid auto-uplinktest
		 type employee
		 opmode wpa2-psk-aes
		 wpa-passphrase 12345678
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	set config {
		wlan access-rule auto-uplinktest
		 rule any any match any any any permit
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}

	STEP "2, Check RUNNING-CONFIGURATION on service IAP."
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running\n"]
	} -condition {
		![regexp -nocase "legacy-mode" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The SSID on service IAP isn't legacy mode."
	} -onFail {
		FAIL "The radio profile is wrong." -ABORT CASE
	} -wait 10
	
	STEP "Configure the WiFi-uplink on WiFi-uplink IAP."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
	    no extended-ssid
		wlan ssid-profile wifi_uplink_client_ap
		 essid wifi_uplink_client_ap
		 type employee
		 opmode opensystem
		 vlan guest
		 exit
		 wlan access-rule wifi_uplink_client_ap
		 rule any any match any any any permit
		 exit
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite wpa2-ccmp-psk
		 wpa-passphrase 12345678
		 uplink-band dot11a
		 exit
		uplink
		 no preemption
		 enforce wifi
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10

	
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba001" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10

	STEP "5, Check the uplink status of the client IAP 5G band."
	RETRY {
		IAP::getFullAccess IAP1
		set nchannel_IAP1 [COMMAND IAP1 "cat /proc/sys/dev/wifi0/nchannel\n"]
		regexp {([\d]+)[\s~#]*$} $nchannel_IAP1 - nchannel_IAP1
		COMMAND IAP1 "exit\n"
		IAP::getFullAccess IAP2
		set nchannel_IAP2 [COMMAND IAP2 "cat /proc/sys/dev/wifi0/nchannel\n"]
		regexp {([\d]+)[\s~#]*$} $nchannel_IAP2 - nchannel_IAP2
		COMMAND IAP2 "exit\n"
	} -condition {
		[regexp $nchannel_IAP1 $nchannel_IAP2 ] && [expr { $nchannel_IAP1>256 } ] && [expr { $nchannel_IAP2>256 } ]
	} -count 10 -onPass {
		PASS "The client IAP used a wide 5G channel to connect to the service IAP successfully. The channel is not legacy mode."
	} -onFail {
		FAIL "The client IAP used a wide 5G channel to connect to the service IAP failed or the channel is legacy mode." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}

	STEP "Configure the legacy mode on service IAP 5G band."
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	
	set config {
		rf dot11a-radio-profile
		 legacy-mode
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	STEP "Check RUNNING-CONFIGURATION on service IAP."
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running\n"]
	} -condition {
		[regexp -nocase "legacy-mode" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The SSID on service IAP 5G band is legacy mode."
	} -onFail {
		FAIL "The radio profile is wrong." -ABORT CASE
	} -wait 10
	sleep 30
	
	STEP "Check the uplink status of the client IAP 5G band."
	RETRY {
		set IAP2_ip [GetIAPBr0IP {IAP2} ]
		set client_info [COMMAND IAP1 "show clients\n"]
		regexp "$IAP2_ip\[\\s\]+\[\\da-z\\:\]+auto-uplinktest\[\\s\]+\[\\da-z\\:\]+\[\\s\]+\[\\d\]+\[\\s\]+(\[A-Z\]+)" $client_info - $client_info
	} -condition {
		[ regexp "A" $client_info] && ![ regexp "AN" $client_info]
	} -count 10 -onPass {
		PASS "The client IAP used a 5G channel to connect to the service IAP successfully. And the channel is legacy mode."
	} -onFail {
		FAIL "The client IAP used a 5G channel to connect to the service IAP failed or the channel isn't legacy mode." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND a -IAP IAP1 -ssid "auto-uplinktest" -opmode wpa2-psk-aes -passPhrase 12345678
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP2 -BAND a -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode opensystem
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-4026 {WiFi-uplink use 2.4GHz first, authentication use WPA2-AES-PSK. Then switch the uplink band from 2.4G to 5G.} {
	CONNECT IAP1
	CONNECT IAP2
	STEP "Configure the SSID on service IAP."

	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
		wlan ssid-profile auto-uplinktest
		 essid auto-uplinktest
		 type employee
		 opmode wpa2-psk-aes
		 wpa-passphrase 12345678
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	set config {
		wlan access-rule auto-uplinktest
		 rule any any match any any any permit
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	STEP "Check RUNNING-CONFIGURATION on service IAP."
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running"]
	} -condition {
		[regexp -nocase "essid auto-uplinktest" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The SSID configuration of the service IAP was configured successfully."
	} -onFail {
		FAIL "The SSID was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Configure the WiFi-uplink on WiFi-uplink IAP."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
	     no extended-ssid
		wlan ssid-profile wifi_uplink_client_ap
		 essid wifi_uplink_client_ap
		 type employee
		 opmode opensystem
		 vlan guest
		 exit
		 wlan access-rule wifi_uplink_client_ap
		 rule any any match any any any permit
		 exit
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite wpa2-ccmp-psk
		 wpa-passphrase 12345678
		 uplink-band dot11g
		 exit
		uplink
		 no preemption
		 enforce wifi
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10

	STEP "Check the WiFi-uplink configuration."	
	RETRY {
		set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
		[ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba101" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10

	STEP "Check the actual RF band which the wifi-uplink functionality use on client IAP."
	RETRY {
		IAP::getFullAccess IAP2
		set out_iwconfig [COMMAND IAP2 "iwconfig\n"]
		COMMAND IAP2 "exit\n"
	} -condition {
		[regexp -nocase "aruba101\[\\s\]+IEEE 802.11ng\[\\s\]+ESSID:\"auto-uplinktest\"" $out_iwconfig ]
	} -count 10 -onPass {
		PASS "The client IAP establish WiFi uplink on NG 2.4G band actually."
	} -onFail {
		FAIL "The client IAP work on the wrong band." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}

	STEP "Reconfigure the Wifi-uplink band."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
	    no extended-ssid
		wlan ssid-profile wifi_uplink_client_ap
		 essid wifi_uplink_client_ap
		 type employee
		 opmode opensystem
		 vlan guest
		 exit
		 wlan access-rule wifi_uplink_client_ap
		 rule any any match any any any permit
		 exit
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite wpa2-ccmp-psk
		 wpa-passphrase 12345678
		 uplink-band dot11a
		 exit
		uplink
		 no preemption
		 enforce wifi
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	INFO "Reload the client IAP, wait 240 seconds.\n"
	IAP::Reload IAP2 -timeout 240 -getTo null
	DISCONNECT IAP2
	CONNECT IAP2
	
	STEP "Check the WiFi-uplink configuration."	
	RETRY {
		set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
		[ regexp -nocase "auto-uplinktest" $out_client_IAP ] && [ regexp -nocase "uplink-band dot11a" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba001" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10

	STEP "Check the actual RF band which the wifi-uplink functionality use on client IAP."
	RETRY {
		IAP::getFullAccess IAP2
		set out_iwconfig [COMMAND IAP2 "iwconfig\n"]
		COMMAND IAP2 "exit\n"
	} -condition {
		[regexp -nocase "aruba001\[\\s\]+IEEE 802.11na\[\\s\]+ESSID:\"auto-uplinktest\"" $out_iwconfig ]
	} -count 10 -onPass {
		PASS "The client IAP establish WiFi uplink on NA 5G band actually."
	} -onFail {
		FAIL "The client IAP work on the wrong band." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND a -IAP IAP1 -ssid "auto-uplinktest" -opmode wpa2-psk-aes -passPhrase 12345678
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP2 -BAND a -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode opensystem
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-4019 {WiFi-uplink use 5GHz, authentication use WPA2-AES-PSK. Verify the WiFi-uplink IAP can switch uplink between wifi and ethernet automatically.} {
	CONNECT IAP1
	CONNECT IAP2
	STEP "1, Configure the SSID on service IAP."

	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	
	set config {
		wlan ssid-profile auto-uplinktest
		 essid auto-uplinktest
		 type employee
		 opmode wpa2-psk-aes
		 wpa-passphrase 12345678
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	set config {
		wlan access-rule auto-uplinktest
		 rule any any match any any any permit
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	STEP "Check RUNNING-CONFIGURATION on service IAP."
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running"]
	} -condition {
		[regexp -nocase "essid auto-uplinktest" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The SSID configuration of the service IAP was configured successfully."
	} -onFail {
		FAIL "The SSID was configured failed" -ABORT CASE
	} -wait 10

	STEP "Configure the WiFi-uplink on WiFi-uplink IAP. The priority of WiFi uplink is higher than the ethernet."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
	     no extended-ssid
		wlan ssid-profile wifi_uplink_client_ap
		 essid wifi_uplink_client_ap
		 type employee
		 opmode opensystem
		 vlan guest
		 exit
		 wlan access-rule wifi_uplink_client_ap
		 rule any any match any any any permit
		 exit
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite wpa2-ccmp-psk
		 wpa-passphrase 12345678
		 uplink-band dot11a
		 exit
		uplink
		 preemption
		 no enforce 
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 uplink-priority wifi 1
		 uplink-priority ethernet port 0 2
		 uplink-priority cellular 3
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]&&\
	 [ regexp -nocase "ethernet 2" $out_client_IAP ]&&\
	 [ regexp -nocase "wifi 1" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10

	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba001" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}

	STEP "Shutdown the service IAP ssid."
	IAP::FactoryReset IAP1
	
	STEP "Check the WiFi-uplink status and uplink status."
	sleep 20
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:NO" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+down" $uplkstatus_client_IAP] && [regexp -nocase "eth0\[\\s\]+up\[\\s\]+2\[\\s\]+yes" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}

	STEP "Recover the configuration of the service IAP."
	DISCONNECT IAP1
	CONNECT IAP1
	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	
	set config {
		wlan ssid-profile auto-uplinktest
		 essid auto-uplinktest
		 type employee
		 opmode wpa2-psk-aes
		 wpa-passphrase 12345678
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	set config {
		wlan access-rule auto-uplinktest
		 rule any any match any any any permit
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	INFO "The IAP need 600 seconds to switch uplink from eth0 to WiFi."
	sleep 600
	
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba001" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 20
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND a -IAP IAP1 -ssid "auto-uplinktest" -opmode wpa2-psk-aes -passPhrase 12345678
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP2 -BAND a -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode opensystem
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-7885 {WiFi-uplink use 5GHz, authentication use WPA2-AES-PSK. Check network-summary.} {
	CONNECT IAP1
	CONNECT IAP2
	STEP "Configure the SSID on service IAP."

    set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	
	set config {
		wlan ssid-profile auto-uplinktest
		 essid auto-uplinktest
		 type employee
		 opmode wpa2-psk-aes
		 wpa-passphrase 12345678
		 exit
		}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	set config {
		wlan access-rule auto-uplinktest
		 rule any any match any any any permit
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	STEP "Check RUNNING-CONFIGURATION on service IAP."
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running"]
	} -condition {
		[regexp -nocase "essid auto-uplinktest" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The SSID configuration of the service IAP was configured successfully."
	} -onFail {
		FAIL "The SSID was configured failed" -ABORT CASE
	} -wait 10

	STEP "Configure the WiFi-uplink on WiFi-uplink IAP."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
	     no extended-ssid
		wlan ssid-profile wifi_uplink_client_ap
		 essid wifi_uplink_client_ap
		 type employee
		 opmode opensystem
		 vlan guest
		 exit
		 wlan access-rule wifi_uplink_client_ap
		 rule any any match any any any permit
		 exit
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite wpa2-ccmp-psk
		 wpa-passphrase 12345678
		 uplink-band dot11a
		 exit
		uplink
		 no preemption
		 enforce wifi
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10

	STEP "Check the WiFi-uplink configuration."	
	RETRY {
		set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
		[ regexp -nocase "auto-uplinktest" $out_client_IAP ] && [ regexp -nocase "uplink-band dot11a" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba001" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10

	STEP "Check the network-summary."
	RETRY {
		set out_network_summary [COMMAND IAP2 "show network-summary"]
	} -condition {
		[regexp -nocase "wifi" $out_network_summary ]
	} -count 10 -onPass {
		PASS "The uplink is correct."
	} -onFail {
		FAIL "The uplink is wrong." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND a -IAP IAP1 -ssid "auto-uplinktest" -opmode wpa2-psk-aes -passPhrase 12345678
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP2 -BAND a -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode opensystem
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-4017 {WiFi-uplink use 2.4GHz, WIFI uplink use the same channel as uplink wireless AP} {
	CONNECT IAP1
	CONNECT IAP2
	CONNECT LAPTOP1
	STEP "Configure the SSID on service IAP. And configure the service IAP 2.4G channel as channel 6."

	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	
	set config {
		wlan ssid-profile auto-uplinktest
		essid auto-uplinktest
		type employee
		opmode opensystem
		exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "Config ssid-profile failed !$results" -ABORT CASE
		}
	
	set config {
		wlan access-rule auto-uplinktest
		rule any any match any any any permit
		exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$Config access-rule failed !$results" -ABORT CASE
		}

	set config {
		g-channel 6 20
	}
	set results [swarm::Action $master_ip $sid $config -ip $master_ip]
		if {$results != 1} {
			FAIL "Config static 2.4g channel failed! $results" -ABORT CASE
		}
	
	STEP "Check RUNNING-CONFIGURATION on service IAP."
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running"]
	} -condition {
		[regexp -nocase "essid auto-uplinktest" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The SSID configuration of the service IAP was configured successfully."
	} -onFail {
		FAIL "The SSID was configured failed" -ABORT CASE
	} -wait 10

	STEP "Configure the WiFi-uplink on WiFi-uplink IAP."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
	    no extended-ssid
		wlan ssid-profile wifi_uplink_client_ap
		 essid wifi_uplink_client_ap
		 type employee
		 opmode opensystem
		 vlan guest
		 exit
		 wlan access-rule wifi_uplink_client_ap
		 rule any any match any any any permit
		 exit
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite clear
		 no wpa-passphrase
		 uplink-band dot11g
		 exit
		uplink
		 no preemption
		 enforce wifi
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  sleep 10
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba101" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10
	
	STEP "Check the actual RF band which the wifi-uplink functionality use on client IAP."
	RETRY {
		IAP::getFullAccess IAP2
		set out_iwconfig [COMMAND IAP2 "iwconfig\n"]
		COMMAND IAP2 "exit\n"
	} -condition {
		[regexp -nocase "aruba101\[\\s\]+IEEE 802.11ng\[\\s\]+ESSID:\"auto-uplinktest\"" $out_iwconfig ]
	} -count 10 -onPass {
		PASS "The client IAP establish WiFi uplink on NG 2.4 band actually."
	} -onFail {
		FAIL "The client IAP work on the wrong band." -ABORT CASE
	} -wait 10
	
	set result [GetApBssChannels -IAP IAP1 -SSID "auto-uplinktest"]
	if {$result == -1} {
		FAIL "Could not get bss-table for SSID" -ABORT CASE
	}
	array set bss_tab_IAP1 $result
	if {$bss_tab_IAP1(g) == -1} {
		FAIL "could not get channel for g-band for ssid" -ABORT CASE
	}
	INFO "IAP1 channel is $bss_tab_IAP1(g)"
	unset result
	set result [GetApBssChannels -IAP IAP2 -SSID "wifi_uplink_client_ap"]
	if {$result == -1} {
		FAIL "Could not get bss-table for SSID" -ABORT CASE
	}
	array set bss_tab_IAP2 $result
	if {$bss_tab_IAP2(g) == -1} {
		FAIL "could not get channel for g-band for ssid" -ABORT CASE
	}
	INFO "IAP1 channel is $bss_tab_IAP2(g)"
	INFO "IAP1 channel ======> $bss_tab_IAP1(g)"
	INFO "IAP2 channel ======> $bss_tab_IAP2(g)"
	if {$bss_tab_IAP1(g) == $bss_tab_IAP2(g)} {
		PASS "Verify IAP & client_ap channel should be the same pass!"
	} else {
		FAIL "Verify IAP & client_ap channel should be the same failed!"
	}
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND a -IAP IAP1 -ssid "auto-uplinktest" -opmode opensystem
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP2 -BAND a -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode opensystem
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-4011 {WiFi-uplink use 5GHz, WIFI udplink use the same channel as uplink wireless AP} {
	CONNECT IAP1
	CONNECT IAP2
	CONNECT LAPTOP1
	STEP "Configure the SSID on service IAP. And configure the service IAP 2.4G channel as channel 6."

	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	
	set config {
		wlan ssid-profile auto-uplinktest
		essid auto-uplinktest
		type employee
		opmode opensystem
		exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "Config ssid-profile failed !$results" -ABORT CASE
		}
	
	set config {
		wlan access-rule auto-uplinktest
		rule any any match any any any permit
		exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$Config access-rule failed !$results" -ABORT CASE
		}

	set config {
		g-channel 6 20
	}
	set results [swarm::Action $master_ip $sid $config -ip $master_ip]
		if {$results != 1} {
			FAIL "Config static 2.4g channel failed! $results" -ABORT CASE
		}
	
	STEP "Check RUNNING-CONFIGURATION on service IAP."
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running"]
	} -condition {
		[regexp -nocase "essid auto-uplinktest" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The SSID configuration of the service IAP was configured successfully."
	} -onFail {
		FAIL "The SSID was configured failed" -ABORT CASE
	} -wait 10

	STEP "Configure the WiFi-uplink on WiFi-uplink IAP."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
	    no extended-ssid
		wlan ssid-profile wifi_uplink_client_ap
		 essid wifi_uplink_client_ap
		 type employee
		 opmode opensystem
		 vlan guest
		 exit
		 wlan access-rule wifi_uplink_client_ap
		 rule any any match any any any permit
		 exit
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite clear
		 no wpa-passphrase
		 uplink-band dot11a
		 exit
		uplink
		 no preemption
		 enforce wifi
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  sleep 10
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba101" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10
	
	set result [GetApBssChannels -IAP IAP1 -SSID "auto-uplinktest"]
	if {$result == -1} {
		FAIL "Could not get bss-table for SSID" -ABORT CASE
	}
	array set bss_tab_IAP1 $result
	if {$bss_tab_IAP1(a) == -1} {
		FAIL "could not get channel for a-band for ssid" -ABORT CASE
	}
	INFO "IAP1 channel is $bss_tab_IAP1(a)"
	unset result
	set result [GetApBssChannels -IAP IAP2 -SSID "wifi_uplink_client_ap"]
	if {$result == -1} {
		FAIL "Could not get bss-table for SSID" -ABORT CASE
	}
	array set bss_tab_IAP2 $result
	if {$bss_tab_IAP2(a) == -1} {
		FAIL "could not get channel for a-band for ssid" -ABORT CASE
	}
	INFO "IAP1 channel is $bss_tab_IAP2(a)"
	INFO "IAP1 channel ======> $bss_tab_IAP1(a)"
	INFO "IAP2 channel ======> $bss_tab_IAP2(a)"
	if {$bss_tab_IAP1(a) == $bss_tab_IAP2(a)} {
		PASS "Verify IAP & client_ap channel should be the same pass!"
	} else {
		FAIL "Verify IAP & client_ap channel should be the same failed!"
	}
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND a -IAP IAP1 -ssid "auto-uplinktest" -opmode opensystem
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP2 -BAND a -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode opensystem
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-4023 {master beacon sta-iap do not send master beacon and also ignore master beaon received via WIFI uplink} {
	CONNECT IAP1
	CONNECT IAP2
	STEP "Configure the SSID on service IAP."
    set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	
	set config {
		wlan ssid-profile auto-uplinktest
		 essid auto-uplinktest
		 type employee
		 opmode opensystem
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	set config {
		wlan access-rule auto-uplinktest
		 rule any any match any any any permit
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	set config {
		a-channel 149 20
	}
	set results [swarm::Action $master_ip $sid $config -ip $master_ip]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	STEP "Check RUNNING-CONFIGURATION on service IAP."
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running"]
	} -condition {
		[regexp -nocase "essid auto-uplinktest" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The SSID configuration of the service IAP was configured successfully."
	} -onFail {
		FAIL "The SSID was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Configure the WiFi-uplink on WiFi-uplink IAP."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
	     no extended-ssid
		wlan ssid-profile wifi_uplink_client_ap
		 essid wifi_uplink_client_ap
		 type employee
		 opmode opensystem
		 vlan guest
		 exit
		 wlan access-rule wifi_uplink_client_ap
		 rule any any match any any any permit
		 exit
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite clear
		 no wpa-passphrase
		 uplink-band dot11a
		 exit
		uplink
		 no preemption
		 enforce wifi
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10

	STEP "Check the WiFi-uplink configuration."	
	RETRY {
		set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
		[ regexp -nocase "auto-uplinktest" $out_client_IAP ] && [ regexp -nocase "uplink-band dot11a" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "interfaces\[\\s\]+:aruba001" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10
	STEP "Check sta-iap do not send master beacon"
	set debug_master_beacon [COMMAND IAP2 "debug-master-beacon"]
	if {[regexp "Sending master-beacon" $debug_master_beacon]} {
		FAIL "Verify sta-iap could not send master beacon failed!"
	} else {
		PASS "Verify sta-iap could not send master beacon pass!"
	}
	COMMAND IAP2 "no debug-master-beacon"
	STEP "Check sta-iap should ignore master beacon received via wifi-uplink"

	RETRY {
		set IAP2masterIP [GetMasterIP {IAP2}]
		set IAP2br0IP [GetIAPBr0IP {IAP2}]
	} -condition {
		[regexp -nocase $IAP2masterIP $IAP2br0IP]
	} -count 2 -onPass {
		PASS "Verify sta-iap should ignore master beacon pass."
	} -onFail {
		FAIL "Verify sta-iap should ignore master beacon failed!"
	} -wait 3
	
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND a -IAP IAP1 -ssid "auto-uplinktest" -opmode opensystem
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP2 -BAND a -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode opensystem
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-4007 {debug CLI} {
	STEP "Get to su mode on IAP2"
	IAP::getFullAccess IAP2
	COMMAND IAP2 "iwconfig"
	set bin_conf [COMMAND IAP2 "cat aruba/bin/wpa_sta_supplicant.conf"]
	if {[regexp "auto-uplinktest"] $bin_conf} {
		PASS "Verify config via su_mode pass!"
	} else {
		FAIL "Verify config via su_mode fail!"
	}
	COMMAND IAP2 {cat var/log/arubalog/SYSTEM.log | grep "wifi uplink"}
	COMMAND IAP2 {cat tmp/wpa_supplicant-debug-log | grep "States:"}
	COMMAND IAP2 {cat tmp/wpa_supplicant-debug-log | grep "Scan results"}
	sleep 10
	COMMAND IAP2 "exit\n"
	set show_wifi_uplink_config [COMMAND IAP2 "show wifi-uplink config"]
	if {[regexp "ESSID\\s+:auto-uplinktest"]} {
		PASS "Verify wifi-uplink config pass"
	} else {
		FAIL "Verify wifi-uplink config failed!"
	}
}
CASE RN-4328 {wifi-uplink use 5g with wpa2-ccmp-psk, client is Magic vlan client with CP, swich uplink} {
	CONNECT IAP1
	CONNECT IAP2
	STEP "Configure the SSID on service IAP."
	sleep 5
	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	
	set config {
		wlan ssid-profile auto-uplinktest
		 essid auto-uplinktest
		 type employee
		 opmode wpa2-psk-aes
		 wpa-passphrase 12345678
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	set config {
		wlan access-rule auto-uplinktest
		 rule any any match any any any permit
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	sleep 5
	STEP "Check RUNNING-CONFIGURATION on service IAP."
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running"]
	} -condition {
		[regexp -nocase "essid auto-uplinktest" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The SSID configuration of the service IAP was configured successfully."
	} -onFail {
		FAIL "The SSID was configured failed" -ABORT CASE
	} -wait 10

	set master_ip [GetIAPBr0IP IAP2]
	set radius_client_username "fengding"
	set radius_client_password "fengding"

	set auth_server1_port [getVar RADIUS SOFTWARE.RADIUS.PRI.AUTHPORT]
	set auth_server1_acctport [getVar RADIUS SOFTWARE.RADIUS.PRI.ACCTPORT]
	set auth_server1_key [getVar RADIUS SOFTWARE.RADIUS.PRI.SECRET]
	set auth_server1_config [getVar RADIUS SOFTWARE.RADIUS.PRI.CONFIG]
	set auth_server1 "ReachableExternalRadiusServer"
	STEP "Add Extenal Authentication Server $auth_server1"
	
	set auth_server1_ip "192.168.72.2"
	set servers "ReachableExternalRadiusServer"
	CONNECT SWARM  
	set swarm [getVar SWARM SOFTWARE.SWARM.EXE]
	# set configs [IAP_CMD_GET_DELETE_AUTH_SERVER $servers]
	# commandswarm SWARM "$swarm $master_ip Config \"$configs\"" -timeout 60
    sleep 5
	
	COMMAND IAP2 "config t"
	COMMAND IAP2 "wlan auth-server $servers"
	COMMAND IAP2 "ip $auth_server1_ip"
	COMMAND IAP2 "port $auth_server1_port"
	COMMAND IAP2 "acctport $auth_server1_acctport"
	COMMAND IAP2 "key $auth_server1_key"
	COMMAND IAP2 "end"
	COMMAND IAP2 "commit apply"
	sleep 5

	STEP "---------Creat 1 ssid------------"
	set ssid "wifi_uplink_client_ap"
	set ssid_type "guest"
	set ssid_vlan "guest"
	set ssid_opmode "opensystem"
	STEP "Create 1 ssid:"
	INFO "ssid parameters: "
	INFO "ssid: $ssid"
	INFO "type: $ssid_type"
	INFO "vlan: $ssid_vlan"
	INFO "opmode: $ssid_opmode"
	COMMAND IAP2 "config t"
	COMMAND IAP2 "wlan ssid-profile $ssid"
	COMMAND IAP2 "type $ssid_type"
	COMMAND IAP2 "essid $ssid"
	COMMAND IAP2 "opmode $ssid_opmode"
	COMMAND IAP2 "vlan $ssid_vlan"
	COMMAND IAP2 "auth-server $servers"
	COMMAND IAP2 "captive-portal internal"
	COMMAND IAP2 "end"
	COMMAND IAP2 "commit apply"	
	sleep 10
	ADD_TO_CLEANUP {
		CONNECT IAP2
		COMMAND IAP2 "config t"
		COMMAND IAP2 "no wlan ssid-profile $ssid"
		COMMAND IAP2 "no wlan sta-profile"
		COMMAND IAP2 "uplink"
		COMMAND IAP2 "no enforce"
		COMMAND IAP2 "end"
		COMMAND IAP2 "commit apply"
		sleep 10
	} -type case	
	
	sleep 10

	STEP "Configure the WiFi-uplink on WiFi-uplink IAP."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}	
	set config {
		 no extended-ssid
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite wpa2-ccmp-psk
		 wpa-passphrase 12345678
		 uplink-band dot11a
		 exit
		uplink
		 no preemption
		 enforce wifi
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Check the WiFi-uplink configuration."	
	RETRY {
		set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
		[ regexp -nocase "auto-uplinktest" $out_client_IAP ] && [ regexp -nocase "uplink-band dot11a" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	COMMAND IAP1 "show client"
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10

	UTIL::Wait 10
	STEP "Verify add auth server successful!"
	set servers [IAP_CLI_GetRadiusServerName IAP2]
	if {[lsearch -exact $servers $auth_server1] == -1} {
		FAIL "Add Extenal Authentication Server $auth_server1 failed" -ABORT CASE
	}
	PASS "Add Extenal Authentication Server $auth_server1 successfully"

	STEP "Restarting primary radius server..."
	CONNECT RADIUS
	set auth_server1_exe [getVar RADIUS SOFTWARE.RADIUS.PRI.EXE]
	COMMAND RADIUS "killall -9 $auth_server1_exe"
	COMMAND RADIUS "cd $auth_server1_config"
	COMMAND RADIUS "rm -rf users"
	COMMAND RADIUS "touch users"
	if {$radius_client_username != "" && $radius_client_password != ""} {
		COMMAND RADIUS "echo \"$radius_client_username Cleartext-Password := $radius_client_password\" > users"
	}
	COMMAND RADIUS "cat users"
	COMMAND RADIUS "rm -rf clients.conf"
	COMMAND RADIUS "touch clients.conf"
	set clients_content "client $master_ip \{\nsecret    = $auth_server1_key\nshortname       = automation_test\n\}\n"
	set vc_ip $master_ip
	if {$vc_ip != "0.0.0.0"} {
		append clients_content "client $vc_ip \{\nsecret          = $auth_server1_key\nshortname       = automation_test\n\}\n"
	}
	
	set acsii_clients_content ""
	set chars [split $clients_content {}]
	foreach char $chars {
		append acsii_clients_content {\\} [format "%o" [scan $char %c]]
	}
	COMMAND RADIUS {printf "$acsii_clients_content" > "clients.conf"}
	COMMAND RADIUS {cat clients.conf}
	COMMAND RADIUS "$auth_server1_exe -d $auth_server1_config"
	if {![regexp "$auth_server1_exe" [COMMAND RADIUS  "ps ax|grep  --color=never radius | grep -v grep"]]} {
	   FAIL "$auth_server1_exe start failed" -ABORT CASE
	}
	
	STEP "Verify ssid creat sucessful!"
	set output [IAP_CLI_GetNetworkDetails IAP2 "$ssid"]
	set lines [split $output "\n\r"]
	foreach line $lines {
		set line [string trim $line]
		if {$line == ""} {continue}
		if {[regexp {^Network Not Found$} $line]} {
			FAIL "Created SSID failed" -ABORT CASE
		}
	}

	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND a -IAP IAP1 -ssid "auto-uplinktest" -opmode wpa2-psk-aes -passPhrase 12345678
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
#	ClientConnectPingTest -handle LAPTOP2 -BAND a -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode opensystem
	STEP "Traffic test!"
	set output_show_ap_bss_table [COMMAND IAP2 "show ap bss-table"]
	if {[regexp "Dell AP BSS Table" $output_show_ap_bss_table]} {
		set title "Dell_AP_BSS_Table"
	} elseif {[regexp "Alcatel-Lucent AP BSS Table" $output_show_ap_bss_table]} {
		set title "Alcatel-Lucent_AP_BSS_Table"
	} else {
		set title "Aruba_AP_BSS_Table"
	}
	set output [ARUBA::parse $output_show_ap_bss_table]
	array set temp $output
	set ABAND $temp($title,phy,0)
	set GBAND $temp($title,phy,1)
	INFO "a-band is $ABAND!"
	INFO "g-band is $GBAND!"
	if {[regexp "g" $ABAND]} {
		set ABAND $temp($title,phy,1)
		set GBAND $temp($title,phy,0)
	}	
	STEP "Configure CLient profile"
	createXML2 LAPTOP2 $ssid opensystem
	set client_tool "[getVar LAPTOP2 SOFTWARE.CLIENT.PATH]/[getVar LAPTOP2 SOFTWARE.CLIENT.EXE]"
	array set win_wireless_interface [ getClientInterfaceInfo LAPTOP2 [ getVar LAPTOP2 INTERFACE.WIRELESS.ADAPTER] ]
	
	STEP "Connect client to 5G!"
	set master_bssid [ regsub -all {:} [ getBSSID IAP2 $ssid $ABAND ] ""]
	array set BSSIDs "IAP2$ssid$ABAND $master_bssid"
	RETRY {
		connectWinClient LAPTOP2 $BSSIDs(IAP2$ssid$ABAND) $ssid
		sleep 20
		set result [getInfoClientTable IAP2 $win_wireless_interface(Physical Address) BSSID]
		regsub -all {:} $result "" result
	} -condition { $result == $BSSIDs(IAP2$ssid$ABAND)
	} -onFail {
		FAIL "FAIL: client not on expected IAP2 BSSID"
	} -count 5 -onPass {
		PASS "client connected"
	} -wait 5
	STEP "Do cp authentication"
	set original_url "192.168.72.2"
	COMMAND LAPTOP2 {wget --secure-protocol=TLSv1 --no-check-certificate -t 1 -a ./cp.log -O ./cp2.log --post-data 'orig_url=http%3A%2F%2F$original_url%2F&opcode=cp_auth&user=$radius_client_username&password=$radius_client_password' 'https://securelogin.arubanetworks.com/swarm.cgi'} -timeout 30
    COMMAND LAPTOP2 {cat cp2.log} -timeout 30


	STEP "Client ping external PC server"
	COMMAND IAP2 "show client"
	set ret [WIN::pingIp LAPTOP2 $server_ip -count 10 -passPer 60 -timeout 40]
	if {$ret != 1} {
		FAIL "CLIENT ping $server_ip failed"
	}
	STEP "client disconnects from IAP"
	sleep 5
	RETRY {
		COMMAND LAPTOP2 "$client_tool dc"
		STEP "Check the connecting result"
		sleep 5
		set cmd_gs [COMMAND LAPTOP2 "$client_tool gs"] 
	} -condition {
		[regexp {"disconnected"} $cmd_gs]
	} -count 5 -onPass {
		PASS "Client disconnected"
	} -onFail {
		FAIL "Client disconnected failed"
	} -wait 10
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-4326 {wifi-uplink use 5g with wpa2-ccmp-psk, client is internal vlan client with CP, swich uplink} {
	CONNECT IAP1
	CONNECT IAP2
	STEP "Configure the SSID on service IAP."
	sleep 5
	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	
	set config {
		wlan ssid-profile auto-uplinktest
		 essid auto-uplinktest
		 type employee
		 opmode wpa2-psk-aes
		 wpa-passphrase 12345678
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	set config {
		wlan access-rule auto-uplinktest
		 rule any any match any any any permit
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	sleep 5
	STEP "Check RUNNING-CONFIGURATION on service IAP."
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running"]
	} -condition {
		[regexp -nocase "essid auto-uplinktest" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The SSID configuration of the service IAP was configured successfully."
	} -onFail {
		FAIL "The SSID was configured failed" -ABORT CASE
	} -wait 10

	set master_ip [GetIAPBr0IP IAP2]
	set radius_client_username "fengding"
	set radius_client_password "fengding"

	set auth_server1_port [getVar RADIUS SOFTWARE.RADIUS.PRI.AUTHPORT]
	set auth_server1_acctport [getVar RADIUS SOFTWARE.RADIUS.PRI.ACCTPORT]
	set auth_server1_key [getVar RADIUS SOFTWARE.RADIUS.PRI.SECRET]
	set auth_server1_config [getVar RADIUS SOFTWARE.RADIUS.PRI.CONFIG]
	set auth_server1 "ReachableExternalRadiusServer"
	STEP "Add Extenal Authentication Server $auth_server1"
	
	set auth_server1_ip "192.168.72.2"
	set servers "ReachableExternalRadiusServer"
	CONNECT SWARM  
	set swarm [getVar SWARM SOFTWARE.SWARM.EXE]
	# set configs [IAP_CMD_GET_DELETE_AUTH_SERVER $servers]
	# commandswarm SWARM "$swarm $master_ip Config \"$configs\"" -timeout 60
    sleep 5
	
	COMMAND IAP2 "config t"
	COMMAND IAP2 "wlan auth-server $servers"
	COMMAND IAP2 "ip $auth_server1_ip"
	COMMAND IAP2 "port $auth_server1_port"
	COMMAND IAP2 "acctport $auth_server1_acctport"
	COMMAND IAP2 "key $auth_server1_key"
	COMMAND IAP2 "end"
	COMMAND IAP2 "commit apply"
	sleep 5
	COMMAND IAP2 "ip dhcp vlan666"
	COMMAND IAP2 "server-type Local"
	COMMAND IAP2 "server-vlan 666"
	COMMAND IAP2 "subnet 66.6.6.6"
	COMMAND IAP2 "subnet-mask 255.255.255.0"
	COMMAND IAP2 "end"
	COMMAND IAP2 "commit apply"
	sleep 5

	STEP "---------Creat 1 ssid------------"
	set ssid "wifi_uplink_client_ap"
	set ssid_type "employee"
	set ssid_vlan "666"
	set ssid_opmode "opensystem"
	STEP "Create 1 ssid:"
	INFO "ssid parameters: "
	INFO "ssid: $ssid"
	INFO "type: $ssid_type"
	INFO "vlan: $ssid_vlan"
	INFO "opmode: $ssid_opmode"
	COMMAND IAP2 "config t"
	COMMAND IAP2 "wlan ssid-profile $ssid"
	COMMAND IAP2 "type $ssid_type"
	COMMAND IAP2 "essid $ssid"
	COMMAND IAP2 "opmode $ssid_opmode"
	COMMAND IAP2 "vlan $ssid_vlan"
	COMMAND IAP2 "auth-server $servers"
	COMMAND IAP2 "captive-portal internal"
	COMMAND IAP2 "end"
	COMMAND IAP2 "commit apply"	
	sleep 10
	ADD_TO_CLEANUP {
		CONNECT IAP2
		COMMAND IAP2 "config t"
		COMMAND IAP2 "no wlan ssid-profile $ssid"
		COMMAND IAP2 "no wlan sta-profile"
		COMMAND IAP2 "uplink"
		COMMAND IAP2 "no enforce"
		COMMAND IAP2 "no ip dhcp vlan666"
		COMMAND IAP2 "end"
		COMMAND IAP2 "commit apply"
		sleep 10
	} -type case	
	
	sleep 10

	STEP "Configure the WiFi-uplink on WiFi-uplink IAP."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}	
	set config {
		 no extended-ssid
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite wpa2-ccmp-psk
		 wpa-passphrase 12345678
		 uplink-band dot11a
		 exit
		uplink
		 no preemption
		 enforce wifi
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Check the WiFi-uplink configuration."	
	RETRY {
		set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
		[ regexp -nocase "auto-uplinktest" $out_client_IAP ] && [ regexp -nocase "uplink-band dot11a" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	COMMAND IAP1 "show client"
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10

	UTIL::Wait 10
	STEP "Verify add auth server successful!"
	set servers [IAP_CLI_GetRadiusServerName IAP2]
	if {[lsearch -exact $servers $auth_server1] == -1} {
		FAIL "Add Extenal Authentication Server $auth_server1 failed" -ABORT CASE
	}
	PASS "Add Extenal Authentication Server $auth_server1 successfully"

	STEP "Restarting primary radius server..."
	CONNECT RADIUS
	set auth_server1_exe [getVar RADIUS SOFTWARE.RADIUS.PRI.EXE]
	COMMAND RADIUS "killall -9 $auth_server1_exe"
	COMMAND RADIUS "cd $auth_server1_config"
	COMMAND RADIUS "rm -rf users"
	COMMAND RADIUS "touch users"
	if {$radius_client_username != "" && $radius_client_password != ""} {
		COMMAND RADIUS "echo \"$radius_client_username Cleartext-Password := $radius_client_password\" > users"
	}
	COMMAND RADIUS "cat users"
	COMMAND RADIUS "rm -rf clients.conf"
	COMMAND RADIUS "touch clients.conf"
	set clients_content "client $master_ip \{\nsecret    = $auth_server1_key\nshortname       = automation_test\n\}\n"
	set vc_ip $master_ip
	if {$vc_ip != "0.0.0.0"} {
		append clients_content "client $vc_ip \{\nsecret          = $auth_server1_key\nshortname       = automation_test\n\}\n"
	}
	
	set acsii_clients_content ""
	set chars [split $clients_content {}]
	foreach char $chars {
		append acsii_clients_content {\\} [format "%o" [scan $char %c]]
	}
	COMMAND RADIUS {printf "$acsii_clients_content" > "clients.conf"}
	COMMAND RADIUS {cat clients.conf}
	COMMAND RADIUS "$auth_server1_exe -d $auth_server1_config"
	if {![regexp "$auth_server1_exe" [COMMAND RADIUS  "ps ax|grep  --color=never radius | grep -v grep"]]} {
	   FAIL "$auth_server1_exe start failed" -ABORT CASE
	}
	
	STEP "Verify ssid creat sucessful!"
	set output [IAP_CLI_GetNetworkDetails IAP2 "$ssid"]
	set lines [split $output "\n\r"]
	foreach line $lines {
		set line [string trim $line]
		if {$line == ""} {continue}
		if {[regexp {^Network Not Found$} $line]} {
			FAIL "Created SSID failed" -ABORT CASE
		}
	}

	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND a -IAP IAP1 -ssid "auto-uplinktest" -opmode wpa2-psk-aes -passPhrase 12345678
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
#	ClientConnectPingTest -handle LAPTOP2 -BAND a -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode opensystem
	STEP "Traffic test!"
	set output_show_ap_bss_table [COMMAND IAP2 "show ap bss-table"]
	if {[regexp "Dell AP BSS Table" $output_show_ap_bss_table]} {
		set title "Dell_AP_BSS_Table"
	} elseif {[regexp "Alcatel-Lucent AP BSS Table" $output_show_ap_bss_table]} {
		set title "Alcatel-Lucent_AP_BSS_Table"
	} else {
		set title "Aruba_AP_BSS_Table"
	}
	set output [ARUBA::parse $output_show_ap_bss_table]
	array set temp $output
	set ABAND $temp($title,phy,0)
	set GBAND $temp($title,phy,1)
	INFO "a-band is $ABAND!"
	INFO "g-band is $GBAND!"
	if {[regexp "g" $ABAND]} {
		set ABAND $temp($title,phy,1)
		set GBAND $temp($title,phy,0)
	}	
	STEP "Configure CLient profile"
	createXML2 LAPTOP2 $ssid opensystem
	set client_tool "[getVar LAPTOP2 SOFTWARE.CLIENT.PATH]/[getVar LAPTOP2 SOFTWARE.CLIENT.EXE]"
	array set win_wireless_interface [ getClientInterfaceInfo LAPTOP2 [ getVar LAPTOP2 INTERFACE.WIRELESS.ADAPTER] ]
	
	STEP "Connect client to 5G!"
	set master_bssid [ regsub -all {:} [ getBSSID IAP2 $ssid $ABAND ] ""]
	array set BSSIDs "IAP2$ssid$ABAND $master_bssid"
	RETRY {
		connectWinClient LAPTOP2 $BSSIDs(IAP2$ssid$ABAND) $ssid
		sleep 20
		set result [getInfoClientTable IAP2 $win_wireless_interface(Physical Address) BSSID]
		regsub -all {:} $result "" result
	} -condition { $result == $BSSIDs(IAP2$ssid$ABAND)
	} -onFail {
		FAIL "FAIL: client not on expected IAP2 BSSID"
	} -count 5 -onPass {
		PASS "client connected"
	} -wait 5
	STEP "Do cp authentication"
	set original_url "192.168.72.2"
	COMMAND LAPTOP2 {wget --secure-protocol=TLSv1 --no-check-certificate -t 1 -a ./cp.log -O ./cp2.log --post-data 'orig_url=http%3A%2F%2F$original_url%2F&opcode=cp_auth&user=$radius_client_username&password=$radius_client_password' 'https://securelogin.arubanetworks.com/swarm.cgi'} -timeout 30
    COMMAND LAPTOP2 {cat cp2.log} -timeout 30


	STEP "Client ping external PC server"
	COMMAND IAP2 "show client"
	set ret [WIN::pingIp LAPTOP2 $server_ip -count 10 -passPer 60 -timeout 40]
	if {$ret != 1} {
		FAIL "CLIENT ping $server_ip failed"
	}
	STEP "client disconnects from IAP"
	sleep 5
	RETRY {
		COMMAND LAPTOP2 "$client_tool dc"
		STEP "Check the connecting result"
		sleep 5
		set cmd_gs [COMMAND LAPTOP2 "$client_tool gs"] 
	} -condition {
		[regexp {"disconnected"} $cmd_gs]
	} -count 5 -onPass {
		PASS "Client disconnected"
	} -onFail {
		FAIL "Client disconnected failed"
	} -wait 10
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-4327 {wifi-uplink use 5g with wpa2-ccmp-psk, client is Magic vlan client with dot1x, swich uplink} {
	CONNECT IAP1
	CONNECT IAP2
	STEP "Configure the SSID on service IAP."
	sleep 5
	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	
	set config {
		wlan ssid-profile auto-uplinktest
		 essid auto-uplinktest
		 type employee
		 opmode wpa2-psk-aes
		 wpa-passphrase 12345678
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	set config {
		wlan access-rule auto-uplinktest
		 rule any any match any any any permit
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	sleep 5
	STEP "Check RUNNING-CONFIGURATION on service IAP."
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running"]
	} -condition {
		[regexp -nocase "essid auto-uplinktest" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The SSID configuration of the service IAP was configured successfully."
	} -onFail {
		FAIL "The SSID was configured failed" -ABORT CASE
	} -wait 10

	set master_ip [GetIAPBr0IP IAP2]
	set radius_client_username "fengding"
	set radius_client_password "fengding"

	set auth_server1_port [getVar RADIUS SOFTWARE.RADIUS.PRI.AUTHPORT]
	set auth_server1_acctport [getVar RADIUS SOFTWARE.RADIUS.PRI.ACCTPORT]
	set auth_server1_key [getVar RADIUS SOFTWARE.RADIUS.PRI.SECRET]
	set auth_server1_config [getVar RADIUS SOFTWARE.RADIUS.PRI.CONFIG]
	set auth_server1 "ReachableExternalRadiusServer"
	STEP "Add Extenal Authentication Server $auth_server1"
	
	set auth_server1_ip "192.168.72.2"
	set servers "ReachableExternalRadiusServer"
	CONNECT SWARM  
	set swarm [getVar SWARM SOFTWARE.SWARM.EXE]

    sleep 5
	
	COMMAND IAP2 "config t"
	COMMAND IAP2 "wlan auth-server $servers"
	COMMAND IAP2 "ip $auth_server1_ip"
	COMMAND IAP2 "port $auth_server1_port"
	COMMAND IAP2 "acctport $auth_server1_acctport"
	COMMAND IAP2 "key $auth_server1_key"
	COMMAND IAP2 "end"
	COMMAND IAP2 "commit apply"
	sleep 5

	STEP "---------Creat 1 ssid------------"
	set ssid "wifi_uplink_client_ap"
	set ssid_type "employee"
	set ssid_vlan "guest"
	set ssid_opmode "wpa2-aes"
	STEP "Create 1 ssid:"
	INFO "ssid parameters: "
	INFO "ssid: $ssid"
	INFO "type: $ssid_type"
	INFO "vlan: $ssid_vlan"
	INFO "opmode: $ssid_opmode"
	COMMAND IAP2 "config t"
	COMMAND IAP2 "wlan ssid-profile $ssid"
	COMMAND IAP2 "type $ssid_type"
	COMMAND IAP2 "essid $ssid"
	COMMAND IAP2 "opmode $ssid_opmode"
	COMMAND IAP2 "vlan $ssid_vlan"
	COMMAND IAP2 "auth-server $servers"
	COMMAND IAP2 "captive-portal disable"
	COMMAND IAP2 "end"
	COMMAND IAP2 "commit apply"	
	sleep 10
	ADD_TO_CLEANUP {
		CONNECT IAP2
		COMMAND IAP2 "config t"
		COMMAND IAP2 "no wlan ssid-profile $ssid"
		COMMAND IAP2 "no wlan sta-profile"
		COMMAND IAP2 "uplink"
		COMMAND IAP2 "no enforce"
		COMMAND IAP2 "end"
		COMMAND IAP2 "commit apply"
		sleep 10
	} -type case	
	
	sleep 10

	STEP "Configure the WiFi-uplink on WiFi-uplink IAP."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}	
	set config {
		 no extended-ssid
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite wpa2-ccmp-psk
		 wpa-passphrase 12345678
		 uplink-band dot11a
		 exit
		uplink
		 no preemption
		 enforce wifi
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Check the WiFi-uplink configuration."	
	RETRY {
		set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
		[ regexp -nocase "auto-uplinktest" $out_client_IAP ] && [ regexp -nocase "uplink-band dot11a" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	COMMAND IAP1 "show client"
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10

	UTIL::Wait 10
	STEP "Verify add auth server successful!"
	set servers [IAP_CLI_GetRadiusServerName IAP2]
	if {[lsearch -exact $servers $auth_server1] == -1} {
		FAIL "Add Extenal Authentication Server $auth_server1 failed" -ABORT CASE
	}
	PASS "Add Extenal Authentication Server $auth_server1 successfully"

	STEP "Restarting primary radius server..."
	CONNECT RADIUS
	set auth_server1_exe [getVar RADIUS SOFTWARE.RADIUS.PRI.EXE]
	COMMAND RADIUS "killall -9 $auth_server1_exe"
	COMMAND RADIUS "cd $auth_server1_config"
	COMMAND RADIUS "rm -rf users"
	COMMAND RADIUS "touch users"
	if {$radius_client_username != "" && $radius_client_password != ""} {
		COMMAND RADIUS "echo \"$radius_client_username Cleartext-Password := $radius_client_password\" > users"
	}
	COMMAND RADIUS "cat users"
	COMMAND RADIUS "rm -rf clients.conf"
	COMMAND RADIUS "touch clients.conf"
	set clients_content "client $master_ip \{\nsecret    = $auth_server1_key\nshortname       = automation_test\n\}\n"
	set vc_ip $master_ip
	if {$vc_ip != "0.0.0.0"} {
		append clients_content "client $vc_ip \{\nsecret          = $auth_server1_key\nshortname       = automation_test\n\}\n"
	}
	
	set acsii_clients_content ""
	set chars [split $clients_content {}]
	foreach char $chars {
		append acsii_clients_content {\\} [format "%o" [scan $char %c]]
	}
	COMMAND RADIUS {printf "$acsii_clients_content" > "clients.conf"}
	COMMAND RADIUS {cat clients.conf}
	COMMAND RADIUS "$auth_server1_exe -d $auth_server1_config"
	if {![regexp "$auth_server1_exe" [COMMAND RADIUS  "ps ax|grep  --color=never radius | grep -v grep"]]} {
	   FAIL "$auth_server1_exe start failed" -ABORT CASE
	}
	
	STEP "Verify ssid creat sucessful!"
	set output [IAP_CLI_GetNetworkDetails IAP2 "$ssid"]
	set lines [split $output "\n\r"]
	foreach line $lines {
		set line [string trim $line]
		if {$line == ""} {continue}
		if {[regexp {^Network Not Found$} $line]} {
			FAIL "Created SSID failed" -ABORT CASE
		}
	}

	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND a -IAP IAP1 -ssid "auto-uplinktest" -opmode wpa2-psk-aes -passPhrase 12345678
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
#	ClientConnectPingTest -handle LAPTOP2 -BAND a -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode opensystem
	STEP "Traffic test!"
	set output_show_ap_bss_table [COMMAND IAP2 "show ap bss-table"]
	if {[regexp "Dell AP BSS Table" $output_show_ap_bss_table]} {
		set title "Dell_AP_BSS_Table"
	} elseif {[regexp "Alcatel-Lucent AP BSS Table" $output_show_ap_bss_table]} {
		set title "Alcatel-Lucent_AP_BSS_Table"
	} else {
		set title "Aruba_AP_BSS_Table"
	}
	set output [ARUBA::parse $output_show_ap_bss_table]
	array set temp $output
	set ABAND $temp($title,phy,0)
	set GBAND $temp($title,phy,1)
	INFO "a-band is $ABAND!"
	INFO "g-band is $GBAND!"
	if {[regexp "g" $ABAND]} {
		set ABAND $temp($title,phy,1)
		set GBAND $temp($title,phy,0)
	}	
	STEP "Configure CLient profile"
#	createXML2 LAPTOP2 $ssid wpa2-aes
	set client_tool "[getVar LAPTOP2 SOFTWARE.CLIENT.PATH]/[getVar LAPTOP2 SOFTWARE.CLIENT.EXE]"
	array set win_wireless_interface [ getClientInterfaceInfo LAPTOP2 [ getVar LAPTOP2 INTERFACE.WIRELESS.ADAPTER] ]
	set master_bssid [ regsub -all {:} [ getBSSID IAP2 $ssid $ABAND ] ""]
	set bssid $master_bssid
# ###########################################	
	STEP "Connect client to 5G!"
	set client_xml_file_param ""
	lappend client_xml_file_param -profilename $ssid -ssid $ssid
	lappend client_xml_file_param -authentication "wpa2_aes"
	lappend client_xml_file_param  -useOneX "true"
	lappend client_xml_file_param -eapMethod "peap_mschapv2"
	lappend client_xml_file_param -username $radius_client_username -password $radius_client_password

	eval Win_GenerateXMLFile LAPTOP2 $client_xml_file_param
	ADD_TO_CLEANUP {
		Win_DisconnectFromSSID LAPTOP2 "$ssid"
		Win_DeleteXMLFile LAPTOP2 "$ssid"
	} -type case

	set connect_result(LAPTOP2) "0"
	set connected(LAPTOP2) 0
	RETRY {
		set connect_result(LAPTOP2) [Win_AddWirelessProfileAndConnect LAPTOP2 $bssid -eapMethod "peap_mschapv2" -interface [getVar LAPTOP2 SOFTWARE.CLIENT.IFACE] -profilename $ssid -ssid $ssid]
	} -condition {
		$connect_result(LAPTOP2) == 1
	} -onPass {
		INFO "LAPTOP2 execute connection successfully"
	} -onFail {
		FAIL "LAPTOP2 execute connection failed"
	} -count 3 -wait 

	if {$connect_result(LAPTOP2) != 1} {
		FAIL "LAPTOP2 execute connection failed" -ABORT CASE
	}
	
	STEP "Verifying Client(s) connected successfully or not"
	UTIL::Wait 10

	set connected(LAPTOP2) [Win_IsClientConnected LAPTOP2]
	set i 0
	while {$connected(LAPTOP2) == 0 && $i != 3} {
		Win_AddWirelessProfileAndConnect LAPTOP2 $bssid -eapMethod "peap_mschapv2" -interface "[getVar LAPTOP2 SOFTWARE.CLIENT.IFACE]" -profilename $ssid -ssid $ssid
		UTIL::Wait 20
		set connected(LAPTOP2) [Win_IsClientConnected LAPTOP2]
		incr i
	}
		
	if {$connected(LAPTOP2) != 1} {
		FAIL "LAPTOP2 connect to $ssid---$bssid failed" -ABORT CASE
	}
	
	set client_ip_list ""
	STEP "Getting client LAPTOP2 ip address..."
	set client_ip(LAPTOP2) 0
	set client_ip(LAPTOP2) [Win_GetIPAddress LAPTOP2 -interface "[getVar LAPTOP2 SOFTWARE.CLIENT.IFACE]"]
	if {$client_ip(LAPTOP2) == 0} {
		FAIL "Got LAPTOP2 ip address failed" -ABORT CASE
	}
	if [IsPrivateIP $client_ip(LAPTOP2)] {
		FAIL "IP of LAPTOP2 is private ip, got ip address failed" -ABORT CASE
	}
	lappend client_ip_list $client_ip(LAPTOP2)
# ################################

	STEP "Client ping external PC server"
	COMMAND IAP2 "show client"
	set ret [WIN::pingIp LAPTOP2 $server_ip -count 10 -passPer 60 -timeout 40]
	if {$ret != 1} {
		FAIL "CLIENT ping $server_ip failed"
	}
	STEP "client disconnects from IAP"
	sleep 5
	RETRY {
		COMMAND LAPTOP2 "$client_tool dc"
		STEP "Check the connecting result"
		sleep 5
		set cmd_gs [COMMAND LAPTOP2 "$client_tool gs"] 
	} -condition {
		[regexp {"disconnected"} $cmd_gs]
	} -count 5 -onPass {
		PASS "Client disconnected"
	} -onFail {
		FAIL "Client disconnected failed"
	} -wait 10
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-4323 {wifi-uplink use 5g with wpa2-ccmp-psk, client is internal vlan client with dot1x, swich uplink} {
	CONNECT IAP1
	CONNECT IAP2
	STEP "Configure the SSID on service IAP."
	sleep 5
	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	
	set config {
		wlan ssid-profile auto-uplinktest
		 essid auto-uplinktest
		 type employee
		 opmode wpa2-psk-aes
		 wpa-passphrase 12345678
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	set config {
		wlan access-rule auto-uplinktest
		 rule any any match any any any permit
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	sleep 5
	STEP "Check RUNNING-CONFIGURATION on service IAP."
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running"]
	} -condition {
		[regexp -nocase "essid auto-uplinktest" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The SSID configuration of the service IAP was configured successfully."
	} -onFail {
		FAIL "The SSID was configured failed" -ABORT CASE
	} -wait 10

	set master_ip [GetIAPBr0IP IAP2]
	set radius_client_username "fengding"
	set radius_client_password "fengding"

	set auth_server1_port [getVar RADIUS SOFTWARE.RADIUS.PRI.AUTHPORT]
	set auth_server1_acctport [getVar RADIUS SOFTWARE.RADIUS.PRI.ACCTPORT]
	set auth_server1_key [getVar RADIUS SOFTWARE.RADIUS.PRI.SECRET]
	set auth_server1_config [getVar RADIUS SOFTWARE.RADIUS.PRI.CONFIG]
	set auth_server1 "ReachableExternalRadiusServer"
	STEP "Add Extenal Authentication Server $auth_server1"
	
	set auth_server1_ip "192.168.72.2"
	set servers "ReachableExternalRadiusServer"
	CONNECT SWARM  
	set swarm [getVar SWARM SOFTWARE.SWARM.EXE]

    sleep 5
	
	COMMAND IAP2 "config t"
	COMMAND IAP2 "wlan auth-server $servers"
	COMMAND IAP2 "ip $auth_server1_ip"
	COMMAND IAP2 "port $auth_server1_port"
	COMMAND IAP2 "acctport $auth_server1_acctport"
	COMMAND IAP2 "key $auth_server1_key"
	COMMAND IAP2 "end"
	COMMAND IAP2 "commit apply"
	sleep 5
	
	COMMAND IAP2 "ip dhcp vlan666"
	COMMAND IAP2 "server-type Local"
	COMMAND IAP2 "server-vlan 666"
	COMMAND IAP2 "subnet 66.6.6.6"
	COMMAND IAP2 "subnet-mask 255.255.255.0"
	COMMAND IAP2 "end"
	COMMAND IAP2 "commit apply"
	sleep 5
	STEP "---------Creat 1 ssid------------"
	set ssid "wifi_uplink_client_ap"
	set ssid_type "employee"
	set ssid_vlan "666"
	set ssid_opmode "wpa2-aes"
	STEP "Create 1 ssid:"
	INFO "ssid parameters: "
	INFO "ssid: $ssid"
	INFO "type: $ssid_type"
	INFO "vlan: $ssid_vlan"
	INFO "opmode: $ssid_opmode"
	COMMAND IAP2 "config t"
	COMMAND IAP2 "wlan ssid-profile $ssid"
	COMMAND IAP2 "type $ssid_type"
	COMMAND IAP2 "essid $ssid"
	COMMAND IAP2 "opmode $ssid_opmode"
	COMMAND IAP2 "vlan $ssid_vlan"
	COMMAND IAP2 "auth-server $servers"
	COMMAND IAP2 "captive-portal disable"
	COMMAND IAP2 "end"
	COMMAND IAP2 "commit apply"	
	sleep 10
	ADD_TO_CLEANUP {
		CONNECT IAP2
		COMMAND IAP2 "config t"
		COMMAND IAP2 "no wlan ssid-profile $ssid"
		COMMAND IAP2 "no wlan sta-profile"
		COMMAND IAP2 "uplink"
		COMMAND IAP2 "no enforce"
		COMMAND IAP2 "end"
		COMMAND IAP2 "commit apply"
		sleep 10
	} -type case	
	
	sleep 10

	STEP "Configure the WiFi-uplink on WiFi-uplink IAP."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}	
	set config {
		 no extended-ssid
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite wpa2-ccmp-psk
		 wpa-passphrase 12345678
		 uplink-band dot11a
		 exit
		uplink
		 no preemption
		 enforce wifi
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Check the WiFi-uplink configuration."	
	RETRY {
		set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
		[ regexp -nocase "auto-uplinktest" $out_client_IAP ] && [ regexp -nocase "uplink-band dot11a" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	COMMAND IAP1 "show client"
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10

	UTIL::Wait 10
	STEP "Verify add auth server successful!"
	set servers [IAP_CLI_GetRadiusServerName IAP2]
	if {[lsearch -exact $servers $auth_server1] == -1} {
		FAIL "Add Extenal Authentication Server $auth_server1 failed" -ABORT CASE
	}
	PASS "Add Extenal Authentication Server $auth_server1 successfully"

	STEP "Restarting primary radius server..."
	CONNECT RADIUS
	set auth_server1_exe [getVar RADIUS SOFTWARE.RADIUS.PRI.EXE]
	COMMAND RADIUS "killall -9 $auth_server1_exe"
	COMMAND RADIUS "cd $auth_server1_config"
	COMMAND RADIUS "rm -rf users"
	COMMAND RADIUS "touch users"
	if {$radius_client_username != "" && $radius_client_password != ""} {
		COMMAND RADIUS "echo \"$radius_client_username Cleartext-Password := $radius_client_password\" > users"
	}
	COMMAND RADIUS "cat users"
	COMMAND RADIUS "rm -rf clients.conf"
	COMMAND RADIUS "touch clients.conf"
	set clients_content "client $master_ip \{\nsecret    = $auth_server1_key\nshortname       = automation_test\n\}\n"
	set vc_ip $master_ip
	if {$vc_ip != "0.0.0.0"} {
		append clients_content "client $vc_ip \{\nsecret          = $auth_server1_key\nshortname       = automation_test\n\}\n"
	}
	
	set acsii_clients_content ""
	set chars [split $clients_content {}]
	foreach char $chars {
		append acsii_clients_content {\\} [format "%o" [scan $char %c]]
	}
	COMMAND RADIUS {printf "$acsii_clients_content" > "clients.conf"}
	COMMAND RADIUS {cat clients.conf}
	COMMAND RADIUS "$auth_server1_exe -d $auth_server1_config"
	if {![regexp "$auth_server1_exe" [COMMAND RADIUS  "ps ax|grep  --color=never radius | grep -v grep"]]} {
	   FAIL "$auth_server1_exe start failed" -ABORT CASE
	}
	
	STEP "Verify ssid creat sucessful!"
	set output [IAP_CLI_GetNetworkDetails IAP2 "$ssid"]
	set lines [split $output "\n\r"]
	foreach line $lines {
		set line [string trim $line]
		if {$line == ""} {continue}
		if {[regexp {^Network Not Found$} $line]} {
			FAIL "Created SSID failed" -ABORT CASE
		}
	}

	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND a -IAP IAP1 -ssid "auto-uplinktest" -opmode wpa2-psk-aes -passPhrase 12345678
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
#	ClientConnectPingTest -handle LAPTOP2 -BAND a -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode opensystem
	STEP "Traffic test!"
	set output_show_ap_bss_table [COMMAND IAP2 "show ap bss-table"]
	if {[regexp "Dell AP BSS Table" $output_show_ap_bss_table]} {
		set title "Dell_AP_BSS_Table"
	} elseif {[regexp "Alcatel-Lucent AP BSS Table" $output_show_ap_bss_table]} {
		set title "Alcatel-Lucent_AP_BSS_Table"
	} else {
		set title "Aruba_AP_BSS_Table"
	}
	set output [ARUBA::parse $output_show_ap_bss_table]
	array set temp $output
	set ABAND $temp($title,phy,0)
	set GBAND $temp($title,phy,1)
	INFO "a-band is $ABAND!"
	INFO "g-band is $GBAND!"
	if {[regexp "g" $ABAND]} {
		set ABAND $temp($title,phy,1)
		set GBAND $temp($title,phy,0)
	}	
	STEP "Configure CLient profile"
#	createXML2 LAPTOP2 $ssid wpa2-aes
	set client_tool "[getVar LAPTOP2 SOFTWARE.CLIENT.PATH]/[getVar LAPTOP2 SOFTWARE.CLIENT.EXE]"
	array set win_wireless_interface [ getClientInterfaceInfo LAPTOP2 [ getVar LAPTOP2 INTERFACE.WIRELESS.ADAPTER] ]
	set master_bssid [ regsub -all {:} [ getBSSID IAP2 $ssid $ABAND ] ""]
	set bssid $master_bssid
# ###########################################	
	STEP "Connect client to 5G!"
	set client_xml_file_param ""
	lappend client_xml_file_param -profilename $ssid -ssid $ssid
	lappend client_xml_file_param -authentication "wpa2_aes"
	lappend client_xml_file_param  -useOneX "true"
	lappend client_xml_file_param -eapMethod "peap_mschapv2"
	lappend client_xml_file_param -username $radius_client_username -password $radius_client_password

	eval Win_GenerateXMLFile LAPTOP2 $client_xml_file_param
	ADD_TO_CLEANUP {
		Win_DisconnectFromSSID LAPTOP2 "$ssid"
		Win_DeleteXMLFile LAPTOP2 "$ssid"
	} -type case

	set connect_result(LAPTOP2) "0"
	set connected(LAPTOP2) 0
	RETRY {
		set connect_result(LAPTOP2) [Win_AddWirelessProfileAndConnect LAPTOP2 $bssid -eapMethod "peap_mschapv2" -interface [getVar LAPTOP2 SOFTWARE.CLIENT.IFACE] -profilename $ssid -ssid $ssid]
	} -condition {
		$connect_result(LAPTOP2) == 1
	} -onPass {
		INFO "LAPTOP2 execute connection successfully"
	} -onFail {
		FAIL "LAPTOP2 execute connection failed"
	} -count 3 -wait 

	if {$connect_result(LAPTOP2) != 1} {
		FAIL "LAPTOP2 execute connection failed" -ABORT CASE
	}
	
	STEP "Verifying Client(s) connected successfully or not"
	UTIL::Wait 10

	set connected(LAPTOP2) [Win_IsClientConnected LAPTOP2]
	set i 0
	while {$connected(LAPTOP2) == 0 && $i != 3} {
		Win_AddWirelessProfileAndConnect LAPTOP2 $bssid -eapMethod "peap_mschapv2" -interface "[getVar LAPTOP2 SOFTWARE.CLIENT.IFACE]" -profilename $ssid -ssid $ssid
		UTIL::Wait 20
		set connected(LAPTOP2) [Win_IsClientConnected LAPTOP2]
		incr i
	}
		
	if {$connected(LAPTOP2) != 1} {
		FAIL "LAPTOP2 connect to $ssid---$bssid failed" -ABORT CASE
	}
	
	set client_ip_list ""
	STEP "Getting client LAPTOP2 ip address..."
	set client_ip(LAPTOP2) 0
	set client_ip(LAPTOP2) [Win_GetIPAddress LAPTOP2 -interface "[getVar LAPTOP2 SOFTWARE.CLIENT.IFACE]"]
	if {$client_ip(LAPTOP2) == 0} {
		FAIL "Got LAPTOP2 ip address failed" -ABORT CASE
	}
	if [IsPrivateIP $client_ip(LAPTOP2)] {
		FAIL "IP of LAPTOP2 is private ip, got ip address failed" -ABORT CASE
	}
	lappend client_ip_list $client_ip(LAPTOP2)
# ################################

	STEP "Client ping external PC server"
	COMMAND IAP2 "show client"
	set ret [WIN::pingIp LAPTOP2 $server_ip -count 10 -passPer 60 -timeout 40]
	if {$ret != 1} {
		FAIL "CLIENT ping $server_ip failed"
	}
	STEP "client disconnects from IAP"
	sleep 5
	RETRY {
		COMMAND LAPTOP2 "$client_tool dc"
		STEP "Check the connecting result"
		sleep 5
		set cmd_gs [COMMAND LAPTOP2 "$client_tool gs"] 
	} -condition {
		[regexp {"disconnected"} $cmd_gs]
	} -count 5 -onPass {
		PASS "Client disconnected"
	} -onFail {
		FAIL "Client disconnected failed"
	} -wait 10
	DISCONNECT IAP1
	DISCONNECT IAP2
}
CASE RN-20613 {WiFi-uplink use 2.4GHz, authentication use WPA2-AES-PSK. Verify the client IAP can follow the HT mode of the service IAP} {
	CONNECT IAP1
	CONNECT IAP2
	STEP "Configure the SSID on service IAP."

	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	
	set config {
		wlan ssid-profile auto-uplinktest
		 essid auto-uplinktest
		 type employee
		 opmode wpa2-psk-aes
		 wpa-passphrase 12345678
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}

	set config {
		wlan access-rule auto-uplinktest
		 rule any any match any any any permit
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	set config {
		arm 
		 wide-bands 2.4ghz
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
	
	STEP "Check RUNNING-CONFIGURATION on service IAP."
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running | include 5ghz\n"]
	} -condition {
		[regexp -nocase "wide-bands 2.4ghz" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The Wide band configuration of the service IAP was configured successfully."
	} -onFail {
		FAIL "The Wide band was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Configure the WiFi-uplink on WiFi-uplink IAP."
	set client_IAP_ip [GetIAPBr0IP IAP2]
	set IAP2_sid [swarm::Login $client_IAP_ip admin admin]
	set sid $IAP2_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}

	set config {
	     no extended-ssid
		wlan ssid-profile wifi_uplink_client_ap
		 essid wifi_uplink_client_ap
		 type employee
		 opmode opensystem
		 vlan guest
		 exit
		 wlan access-rule wifi_uplink_client_ap
		 rule any any match any any any permit
		 exit
		wlan sta-profile
		 essid auto-uplinktest
		 cipher-suite wpa2-ccmp-psk
		 wpa-passphrase 12345678
		 uplink-band dot11g
		 exit
		uplink
		 no preemption
		 enforce wifi
		 no failover-internet
		 failover-vpn-timeout 180
		 failover-internet-pkt-lost-cnt 10
		 failover-internet-pkt-send-freq 30
		 exit
	}
	RETRY {
	  set results [swarm::Config $client_IAP_ip $sid $config]
	  set out_client_IAP [COMMAND IAP2 "show running-config"]
	} -condition {
	 [ regexp -nocase "auto-uplinktest" $out_client_IAP ]
	} -count 10 -onPass {
		PASS "The Wifi-uplink configuration on client IAP was configured successfully."
	} -onFail {
		FAIL "The Wifi-uplink configuration on client IAP was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		COMMAND IAP1 "show running-config\n"
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}

	STEP "Check the width of the client IAP 2G band and the width of the service IAP 2G band. Both of them should be HT40 mode."
	RETRY {
		IAP::getFullAccess IAP1
		set nchannel_IAP1 [COMMAND IAP1 "cat /proc/sys/dev/wifi1/nchannel\n"]
		regexp {([\d]+)[\s~#]*$} $nchannel_IAP1 - nchannel_IAP1
		COMMAND IAP1 "exit\n"
		IAP::getFullAccess IAP2
		set nchannel_IAP2 [COMMAND IAP2 "cat /proc/sys/dev/wifi1/nchannel\n"]
		regexp {([\d]+)[\s~#]*$} $nchannel_IAP2 - nchannel_IAP2
		COMMAND IAP2 "exit\n"
	} -condition {
		[regexp $nchannel_IAP1 $nchannel_IAP2 ] && [expr { $nchannel_IAP1>256 } ] && [expr { $nchannel_IAP2>256 } ]
	} -count 10 -onPass {
		PASS "The client IAP used a wide 2G channel to connect to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP used a wide 2G channel to connect to the service IAP failed." -ABORT CASE
	} -wait 10

	STEP "Configure the HT20 mode on the 2G channel of the service IAP. Then check the configuration."
	set master_ip [GetIAPBr0IP IAP1]
	set IAP1_sid [swarm::Login $master_ip admin admin]
	set sid $IAP1_sid
	if {$sid==0} {
		FAIL "Login failed" -ABORT CASE
	}
	set config {
		arm 
		 wide-bands none
		 exit
	}
	set results [swarm::Config $master_ip $sid $config]
		if {$results != 1} {
			FAIL "$results" -ABORT CASE
		}
		
	RETRY {
		set out_service_IAP [COMMAND IAP1 "show running | include none\n"]
	} -condition {
		[regexp -nocase "wide-bands none" $out_service_IAP ]
	} -count 10 -onPass {
		PASS "The HT20 mode configuration of the service IAP was configured successfully."
	} -onFail {
		FAIL "The HT20 mode was configured failed" -ABORT CASE
	} -wait 10
	
	STEP "Check the WiFi-uplink status and uplink status."
	RETRY {
		set wifiuplkstatus_client_IAP [COMMAND IAP2 "show wifi-uplink status"]
		set uplkstatus_client_IAP [COMMAND IAP2 "show uplink status"]
	} -condition {
		[regexp "configured\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp "enabled\[\\s\]+:YES" $wifiuplkstatus_client_IAP ] && [regexp -nocase "wifi-sta\[\\s\]+up" $uplkstatus_client_IAP]
	} -count 10 -onPass {
		PASS "The client IAP connected to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP connected to the service IAP failed." -ABORT CASE
	} -wait 10
	
	STEP "Check the width of the client IAP 2G band and the width of the service IAP 2G band. Both of them should be HT20 mode."
	RETRY {
		IAP::getFullAccess IAP1
		set nchannel_IAP1 [COMMAND IAP1 "cat /proc/sys/dev/wifi1/nchannel\n"]
		regexp {([\d]+)[\s~#]*$} $nchannel_IAP1 - nchannel_IAP1
		COMMAND IAP1 "exit\n"
		IAP::getFullAccess IAP2
		set nchannel_IAP2 [COMMAND IAP2 "cat /proc/sys/dev/wifi1/nchannel\n"]
		regexp {([\d]+)[\s~#]*$} $nchannel_IAP2 - nchannel_IAP2
		COMMAND IAP2 "exit\n"
	} -condition {
				[regexp $nchannel_IAP1 $nchannel_IAP2 ] && [expr { $nchannel_IAP1<256 } ] && [expr { $nchannel_IAP2<256 } ]
	} -count 10 -onPass {
		PASS "The client IAP used a HT20 mode 5G channel to connect to the service IAP successfully."
	} -onFail {
		FAIL "The client IAP used a HT20 mode 5G channel to connect to the service IAP failed." -ABORT CASE
	} -wait 10
	set pass 0
	for {set i 1} {$i <= 10} {incr i} {
		sleep 5
		STEP "ping IAP default gateway"
		set ping_results [COMMAND IAP2 "ping $server_ip\n"]
		INFO "ping result:$ping_results"

		if {![regexp "received,\\s(.*?)%\\spacket loss" $ping_results result lost]} {
			FAIL "Get ping result failed!"
		}
		INFO "lost is:$lost"
		if {$lost <= 40} {
			PASS "Client_ap ping the default gw successfully"
			set pass 1
			break
		} else {
			continue
		}
		if {$pass != 1} {
			FAIL "Client_ap ping the default gw failed"
		}
	}
	STEP "Verify client1 connect to service IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP1 -BAND a -IAP IAP1 -ssid "auto-uplinktest" -opmode wpa2-psk-aes -passPhrase 12345678
	STEP "Verify client2 connect to client IAP and ping server ip successful!"
	ClientConnectPingTest -handle LAPTOP2 -BAND a -IAP IAP2 -ssid "wifi_uplink_client_ap" -opmode opensystem
	DISCONNECT IAP1
	DISCONNECT IAP2
}
ENDSCRIPT
