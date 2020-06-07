<?php

/*
 for i in `cat '/home/rohff/Desktop/words_search.keys' ` ; do echo $i ; pdfgrep -i -n "$i" ./*.pdf ; read STDIN ; done
 
 Steganalysis: Detecting hidden information with computer forensic analysis

 technique de stenographie :
 	1- Injection 
 	2- Substitution 
 	3- Generating a new file 
 *
 */

class IMG extends FILE {
	
	
	
	public  function __construct($image) {
	parent::__construct($image);
	}
	
	
	
	
	public function image2detect4steganography(){
		$this->ssTitre(__FUNCTION__);
		$this->requette("");
		
	}
	
	
	public function image2stenography4poc(){
		$this->ssTitre("Digital image steganography of encrypted text- JPG, GIF, PNG, BMP.");
		$this->requette("steganography -e $this->dir_tmp/input.png $this->dir_tmp/output.png 'salut rohff' ");		
		$this->requette("diff $this->dir_tmp/input.png $this->dir_tmp/output.png  ");
		$this->requette("cat $this->dir_tmp/output.png | grep 'salut rohff' ");
		$this->requette("steganography -d  $this->dir_tmp/output.png  ");
		
		
	}
	
	
	
	
	
	
}
?>