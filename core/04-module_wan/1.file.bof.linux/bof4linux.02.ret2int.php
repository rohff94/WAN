<?php

class ret2int4linux extends bin4linux{


	public function __construct($bin_bof) {
		parent::__construct($bin_bof);
		$name = __CLASS__;
		$rep_path = "$this->dir_tmp/$name";
		if (!file_exists($rep_path)) $this->create_folder($rep_path);
	}

	
	/*
	
	 */
	public function buffer_overflow_integer($arch) {
		$this->chapitre("Integer Overflow");

	}
	
	public function payload_ret2int4linux_got($argv1,$argv2){
		$cmd = "-$argv1 -$argv2";
		$this->requette("$this->file_path $cmd");
		return $cmd;
	}


}

?>