<?php


class poc4net extends poc4malware{
    
    
    public function __construct() {
        parent::__construct();
        
    }
    
    
    public function poc4find2service2name8net($port,$protocol){        
        $ip = rand(1,255).".".rand(0,255).".".rand(0,255).".".rand(1,255) ;
        if(!$this->ip4priv($ip)){
          $ips =  $this->ip4cidr2port($ip, $port, $protocol);
          if (!empty($ips)) {
              $max_iter = count($ips);
              $this->rouge("ITER $max_iter");
              $gauche_iter = intval($max_iter/2);
              $droite_iter = intval($max_iter-$gauche_iter);
              $file_path = "/tmp/$ip.$port.$protocol.".__FUNCTION__.".lst";
              $fp = fopen($file_path, 'w+');
              foreach ($ips as $ip_addr) {
                  if(!empty($ip_addr)){                     
                      $eth = $this->ip4eth4target($ip_addr);
                      $domain = $this->ip2domain($ip_addr);
                      $data = "$eth $domain $ip_addr ip4port FALSE";
                      $data = $data."\n";
                      fputs($fp,$data);
                  }
              }
              fclose($fp);
              if (1<$max_iter) $this->requette("php parallel.php \"cat $file_path | awk 'FNR>0 && FNR<=$gauche_iter' | parallel --progress --no-notice -k -j$gauche_iter php pentest.php IP {} \" \"cat  $file_path | awk 'FNR>$gauche_iter && FNR<=$max_iter' | parallel --progress --no-notice -k -j$droite_iter php pentest.php IP {} \" 0 ");
              else $this->requette("php pentest.php PORT \"'$eth' '$domain' '$ip_addr' '$port' '$protocol' 'FALSE'\" ");
              
          }
        }
    }
    
    
    public function poc4find2service2name($service2name){
        $sql = "select id8ip,port,protocol,service2name,service2version,service2product,service2extrainfo,port2banner,port2cve FROM PORT WHERE service2name LIKE \"%$service2name%\" ORDER BY id8ip DESC;";
        
        $conn = $this->mysql_ressource->query($sql);
        $file_path = "/tmp/$service2name.lst";
        $fp = fopen($file_path, 'w+');
        while($row = $conn->fetch_assoc()){
            //system("clear");
            $id8ip = $row['id8ip'];
            //$this->article("id8ip", $id8ip);
            $sql2 = "select ip,id8domain from IP where id = $id8ip;";
            $ip = $this->mysql_ressource->query($sql2)->fetch_assoc()['ip'];
            $id8domain = $this->mysql_ressource->query($sql2)->fetch_assoc()['id8domain'];
            $sql3 = "select eth,domain from DOMAIN where id = $id8domain;";
            $eth = $this->mysql_ressource->query($sql3)->fetch_assoc()['eth'];
            $domain = $this->mysql_ressource->query($sql3)->fetch_assoc()['domain'];
   
            
            echo "\n\n";
            $this->article("eth", $eth);
            $this->article("domain", $domain);
            $this->article("ip", $ip);
            
            if (!$this->ip4priv($ip)){
                    $port2cve = trim(base64_decode($row['port2cve']));
                    
                    $port = $row['port'];
                    $this->article("PORT Number", $port);
                    $protocol = $row['protocol'];
                    $this->article("protocol", $protocol);
                    
                    $service2name = $row['service2name'];
                    $this->article("service2name", $service2name);
                    $service2version = $row['service2version'];
                    $this->article("service2version", $service2version);
                    $service2product = $row['service2product'];
                    $this->article("service2product", $service2product);
                    $service2extrainfo = $row['service2extrainfo'];
                    $this->article("service2extrainfo", $service2extrainfo);
                    $port2banner = base64_decode($row['port2banner']);
                    $this->article("Banner", $port2banner);
                    //$this->article("port2cve", $port2cve);
                    $this->pause();
                    $data = "$eth $domain $ip $port $protocol FALSE";
                    $data = $data."\n";
                    fputs($fp,$data);
                
            }
        }
        
        $ports = file($file_path);
        foreach ($ports as $port_args){
            if(!empty($port_args)){
               $query = "php pentest.php PORT \"$port_args\" "; 
                $this->requette($query);$this->pause();
            }
        }
        
        //$process = 8 ;$this->run4split4port($file_path, $process);
        
        


        
        
    
        
    }
    
    

    public function poc4find2cve(){
        $sql = "select distinct(port2cve),id8ip,service2name,service2version,service2product,service2extrainfo from PORT where port2cve IS NOT NULL;";
        
        $conn = $this->mysql_ressource->query($sql);
        while($row = $conn->fetch_assoc()){
            system("clear");
            $id8ip = $row['id8ip'];
            //$this->article("id8ip", $id8ip);
            $sql2 = "select ip from IP where id = $id8ip;";
            $ip = $this->mysql_ressource->query($sql2)->fetch_assoc()['ip'];
            $this->article("ip", $ip);
            if (!$this->ip4priv($ip)){
                $port2cve = trim(base64_decode($row['port2cve']));
                if(!empty($port2cve)){
                    
                    $service2name = $row['service2name'];
                    $this->article("service2name", $service2name);
                    $service2version = $row['service2version'];
                    $this->article("service2version", $service2version);
                    $service2product = $row['service2product'];
                    $this->article("service2product", $service2product);
                    $service2extrainfo = $row['service2extrainfo'];
                    $this->article("service2extrainfo", $service2extrainfo);
                    $this->article("port2cve", $port2cve);
                    $this->pause();
                }
            }
        }
    }
    
    
    public function poc4db2collect() {
$ip2fonction = "ip4port";
//$service = $argv[1];
$sql4 = "select distinct(service2name) from PORT where id8ip > 100 ORDER BY id8ip DESC;";
$con4 = $this->mysql_ressource->query($sql4);
while ($row = $con4->fetch_assoc()){
    $service = $row["service2name"];
    if( (!empty($service)) && (!stristr($service, "http")) && (!stristr($service, "unknown")) ){
        $this->article("Service ", $service);
        $sql = "select id8ip,port,protocol from PORT where service2name = \"$service\" AND id8ip > 150 ;";
        $conn = $this->mysql_ressource->query($sql);
        while ($row = $conn->fetch_assoc())
        {
            $id8ip = $row["id8ip"];
            $port = $row["port"];
            $protocol = $row["protocol"];
            
            $sql2 = "select ip,id8domain from IP where id = $id8ip ;";
            $con2 = $this->mysql_ressource->query($sql2);
            $row = $con2->fetch_assoc();
            $ip = $row["ip"];
            $id8domain = $row["id8domain"];
            
            $sql3 = "select domain from DOMAIN where id = $id8domain ;";
            $con3 = $this->mysql_ressource->query($sql3);
            $row = $con3->fetch_assoc();
            $domain = $row["domain"];
            
            
            $ips = $this->ip4cidr2port($ip, $port,$protocol);
            
            
            if (!empty($ips)) {
                $max_iter = count($ips);
                $this->rouge("ITER $max_iter");
                $gauche_iter = intval($max_iter/2);
                $droite_iter = intval($max_iter-$gauche_iter);
                $file_path = "$this->dir_tmp/$id8domain.$id8ip.$port.$protocol.$service.".__FUNCTION__.".lst";
                $fp = fopen($file_path, 'w+');
                foreach ($ips as $ip_addr) {
                    if(!empty($ip_addr)){
                        $eth = $this->ip4eth4target($ip_addr);
                        $data = "$eth $domain $ip_addr $ip2fonction FALSE";
                        $data = $data."\n";
                        fputs($fp,$data);
                    }
                }
                fclose($fp);
                if (1<$max_iter) $this->requette("php parallel.php \"cat  $file_path | awk 'FNR>0 && FNR<=$gauche_iter' | parallel --progress --no-notice -k -j$gauche_iter php pentest.php IP {} \" \"cat  $file_path | awk 'FNR>$gauche_iter && FNR<=$max_iter' | parallel --progress --no-notice -k -j$droite_iter php pentest.php IP {} \" 0 ");
                
            }
            
            
            
            foreach ($ips as $ip_addr){
                if(!empty($ip_addr)){
                    
                    
                    $obj_ip = new IP($eth,$domain,$ip_addr);
                    $obj_ip->$ip2fonction();
                }
                
            }
            
            
            
            
            
            
            
            
            
        }
    }
    
}
return "";
    }



}
?>