<?php

include "./class/0.all.inc.php";




##############################################################################
// HACK 000


$poc = new POC();
##############################################################################
// HACK 010

$poc->poc4intro();	//  OK 
$poc->poc4googleHacking();	 // OK 
##############################################################################
// HACK 011
$poc->poc4discover4host();
// HACK 012
$poc->poc4scan4ip();

// HACK 013 
$poc->poc4scan4ip4port();
##############################################################################



##############################################################################
// HACK 020
$poc->poc4scan4ip4enum();
##############################################################################


##############################################################################
$poc = new poc4bof();
// HACK 044
$poc->poc4shellcode();// OK
$poc->bof2start(); // OK
$poc->bof2exp4app4server(); // OK
$poc->poc4bof2ret2stack4linux(); // OK
$poc->poc4bof2ret2stack4win(); // OK
$poc->poc4bof2ret2seh4win(); // OK
$poc->poc4bof2ret2canary4linux(); // Not yet
$poc->poc4bof2ret2fmt4linux_intro(); // OK
$poc->poc4bof2ret2lib(); // OK
$poc->poc4bof2ret2got4linux(); // OK
$poc->poc4bof2ret2pie(); // Not yet
$poc->poc4bof2ret2OffByOne4linux(); // OK
$poc->poc4bof2ret2heap4linux_intro();  // Not yet
$poc->poc4bof2ret2heap4linux_OffByOne();  // Not yet
$poc->poc4bof2ret2int4linux(); // OK
$poc->poc4bof2ret2fmt4linux_advanced(); // OK
$poc->poc4bof2ret2heap4linux_fmtstr();  // Not yet  //buffer_overflow_heap_format_string();
$poc->poc4bof2ret2rop(); // OK


##############################################################################

##############################################################################

// HACK 060

$poc->poc4host4root();
$poc->poc4host4root4crackingPassword();
$poc->poc4bof4setuid0();
$poc->poc4host4root4racecondition();
$poc->poc4host4root4setuid0();
$poc->poc4host4root4Spyware4keylog();
$poc->poc4host4root();

##############################################################################


##############################################################################
// HACK 022
$poc->poc4Exploit4Vuln();
$poc->poc4scan4ip4enum();
##############################################################################


##############################################################################
// HACK 030
$poc = new poc4malware();

intro::poc4malware4intro();$poc->pause(); // OK
$poc->poc4malware4backdoor4static();$poc->pause(); // OK
$poc->poc4malware4backdoor4Heuristics();$poc->pause(); // OK
$poc->poc4malware4bypass4hips();$poc->pause();	// OK
$poc->poc4malware4backdoor4langage();$poc->pause();  // OK
$poc->poc4malware4backdoor4exploit();$poc->pause(); // OK
$poc->bof2exp4app4server();$poc->pause(); // OK
$poc->poc4malware4buffer_overflow_intro();$poc->pause();
$poc->poc4malware4trojan4linux();$poc->pause(); // OK
$poc->poc4malware4trojan();$poc->pause(); // OK
$poc->poc4malware4sandbox();$poc->pause(); // OK
$poc->poc4malware4backdoor_persistance();$poc->pause(); // OK
$poc->poc4malware4backdoor4win_persistance_32_exemple();$poc->pause(); // OK
$poc->poc4malware4backdoor_injected_into_app();$poc->pause(); // OK
$poc->poc4malware4backdoor_injected_into_pid();$poc->pause();
$poc->question("les Malwares de nos jours utilisent-ils les Injections de code dans la memoire d'un autre processus");
$poc->poc4malware4backdoor_injected_into_pid_exemple();$poc->pause();
$poc->poc4malware4bypass4nids();$poc->pause();
$poc->poc4malware4bypass4fw();$poc->pause();
$poc->poc4malware4rootkit();$poc->pause(); // OK 
$poc->poc4malware4rootkit4win_hook_dll_32_exemple();$poc->pause();
$poc->poc4malware4sandbox();$poc->pause(); // OK
$poc->poc4malware4detection_honeypot_honeyd();$poc->pause();
$poc->poc4malware4eradication();$poc->pause();
intro::poc4malware4analysis();$poc->pause();
##############################################################################

##############################################################################


##############################################################################



##############################################################################
$poc->poc4IdentVuln(); // OK 
##############################################################################


##############################################################################
// HACK 070 
$poc->poc4host4sys4enum();
##############################################################################


##############################################################################
// HACK 082
$poc->poc4lan4sniffing();
##############################################################################


##############################################################################
// HACK 083
$poc->poc4lan4crypto();
##############################################################################


##############################################################################
	// WIFI 
//$poc = new test_wifi();
//$poc->poc4wifi();
//$bssid = "00:21:29:A6:F6:3C";
//$essid = "zack";
//$station = "68:94:23:09:D0:7F";
//$poc->Quiz_wifi();
//$poc->scan_acces_point ();
//$poc->wifi_crack_step_by_step ($bssid, $station, $essid);
//$poc->wireless_device ();
//$poc->enable_monitoring_interface ();
//$poc->show_all_acces_point ();
//$poc->show_all_station_in_essid_selected ($bssid, $essid);
//$poc->test_inject_data_in_interface_monitor ();
//$poc->get_handshake_from_one_station_in_one_essid ( $bssid, $station, $essid ); // ne fonctionne pas avec aircrack -> j'arrive pas a avoir le handshake
//$poc->crack_handshake ( "/media/trucrypt5/EH/TMP/capture_handshake.pcap" );
//$poc->wifi_crack_faster ( $bssid );
//$poc->get_handshake_from_all_station_in_all_essid ();
//$poc->get_handshake_from_all_station_in_one_essid ( $bssid );
//$poc->crack_handshake ( "/opt/aircrack-ng-1.2-beta1/wpa.cap" );
//$poc->method_crack_wifi();//ok
//$poc->method_0_Deauthentication ();//ok
//$poc->method_1_Fake_authentication ();//ok
//$poc->method_2_Interactive_packet_replay ();//ok
//$poc->method_3_ARP_request_replay ();
//$poc->method_4_KoreK_chopchop ();//ok
//$poc->method_5_Fragmentation ();//ok
//$poc->method_6_Cafe_latte ();//ok
//$poc->method_7_Client_oriented_fragmentation ();
//$poc->method_8_WPA_Migration ();
//$poc->method_9_Injection_test ();
//$poc->WPA_crack();//ok
//$poc->fakeAP();
//$poc->wids();
//$poc->wips();
##############################################################################
?>
