<?php

class com4file extends com4net {
    
    
    public function __construct() {
        parent::__construct();
    }
    
    
    public function file4exist8name($stream,$filename):bool{
        $this->ssTitre(__FUNCTION__);
        $filepath = $this->file4locate($stream,$filename);
        if (!empty($filepath)){
            return TRUE;
        }
        ELSE return FALSE;
    }
    
    public function file4exist8path($stream,$filepath):bool{
        $this->ssTitre(__FUNCTION__);
        $filepath_found = "";
        $data = "ls -al $filepath";
        $filepath_found = $this->req_str($stream,$data, $this->stream_timeout,"| awk '{print $9}' $this->filter_file_path ");
        
        if (!empty($filepath_found)){
            $chaine = "file exist";
            $this->note($chaine);
            return TRUE;
        }
        else {
            $chaine = "file does not exist";
            $this->rouge($chaine);
            return FALSE;
        }
    }
    
    public function file4locate($stream,$filename){
        $this->ssTitre(__FUNCTION__);
        
        $data = "which $filename ";
        $files_found = "";
        $files_found = trim($this->req_str($stream,$data,$this->stream_timeout*3,"$this->filter_file_path | grep '$filename' "));
        if( !empty($files_found)) return $files_found ;
        
        $data = "locate $filename ";
        $files_found = "";
        $files_found = trim($this->req_str($stream,$data,$this->stream_timeout*3,"$this->filter_file_path | grep '$filename' "));
        if( !empty($files_found)) return $files_found ;
        
        
        $data = "find / -iname $filename -type f -exec ls {} \; 2> /dev/null ";
        $files_found = "";
        $files_found = trim($this->req_str($stream,$data,$this->stream_timeout*3,"$this->filter_file_path | grep '$filename' "));
        if( !empty($files_found)) return $files_found ;
    }
    
    public function file4search8path($stream,$file_path,$search_data):bool{
        $this->ssTitre(__FUNCTION__);
        $search_data = trim($search_data);
        
        $data = "cat $file_path";
        $lines_str = $this->req_str($stream,$data,$this->stream_timeout,"| grep '$search_data' ");
        
        if (strstr($lines_str, $search_data)!==FALSE)
        {
            $this->article($search_data, "Found ");
            return TRUE ;
        }
        
        $this->article($search_data, "Not Found");
        return FALSE;
    }
    
    public function file4add($stream,$filename,$add_data){
        $this->ssTitre(__FUNCTION__);
        $obj_filename = new FILE($stream,$filename);
        
        if ($this->file4search8path($stream,$obj_filename->file_path, $add_data)){
            $this->note("Already Added: $add_data");
            return TRUE;
        }
        else {
            $this->note("ADD: $add_data");
            $this->req_str($stream,"echo '$add_data' >> $obj_filename->file_path",$this->stream_timeout,"");
            $data = "cat $obj_filename->file_path";
            $rst = $this->req_str($stream,$data,$this->stream_timeout,"| grep '$add_data' | grep -Po '$add_data'  ");
            if (!empty($rst)) {$this->log2succes("SUCCES ADD: $add_data");return TRUE;}
            else {$this->log2error("Failed ADD");return FALSE;}
        }
        
    }
    
    
    public function file4writable($stream,$filename){
        $this->ssTitre(__FUNCTION__);
        $writable_rst = array();
        if ($this->file4exist8path($stream,$filename)){
            $data = "stat $filename";
            $writable_test = trim($this->req_str($stream,$data,$this->stream_timeout,""));
            if (preg_match('/[0-7]{3}(?<user2write>[0-7]{1})\/[rwx\-]{7}/',$writable_test,$writable_rst))
            {
                if (isset($writable_rst['user2write'])){
                    $this->article("User Permission",$writable_rst['user2write']);
                    if ($writable_rst['user2write']>6) {
                        $this->rouge("Writeable $filename");
                        return TRUE;}
                        else {$this->note("Not Writeable less 6 $filename");return FALSE;}
                }
            }
            else {$this->note("Not Writeable $filename");return FALSE;}
        }
    }
    
    public function file4readable($stream,$filename){
        $this->ssTitre(__FUNCTION__);
        $readable_rst = array();
        $data = "stat $filename";
        $readable_test = trim($this->req_str($stream,$data,$this->stream_timeout,""));
        if (preg_match('/[0-7]{3}(?<user2read>[0-7]{1})\/[rwx\-]{7}/',$readable_test,$readable_rst))
        {
            if (isset($readable_rst['user2read'])){
                $this->article("readable",$readable_rst['user2read']);
                if ($readable_rst['user2read']>4) {
                    $this->note("readable $filename");
                    return TRUE;}
                    
            }
        }
        else {$this->note("Not readable $filename");return FALSE;}
    }
    
    
    
    public function file4replace($stream,$filename,$search_data,$replace_data){
        $result = "";
        $this->ssTitre(__FUNCTION__);
        $obj_filename = new FILE($stream,$filename);
        
        if ($this->file4search8path($stream,$obj_filename->file_path,$search_data)){
            $data = "cat $obj_filename->file_path";
            $lines_tab = $this->req_tab($stream,$data,$this->stream_timeout,"");
            
            foreach ($lines_tab as $line){
                if (preg_match('#['.$search_data.']#',$line))
                {
                    $this->article("Searching", "Found ");
                    $result .= str_replace($search_data, $replace_data, $line);
                }
                else {
                    $result .= $line;
                }
            }
            
            $this->article("Replacing", "Data ");
            $data = "echo '$result' > $obj_filename->file_path";
            $this->req_str($stream,$data,$this->stream_timeout,"");
            
        }
        else {
            $this->note("Data Not found: $search_data");
        }
        
        return $result;
    }
    
    
    
    public function avd2list2avd($stream):array{
        $data = "/home/rohff/Android/Sdk/tools/emulator -list-avds";
        $filter = "";
        return $this->req_tab($stream, $data, $this->stream_timeout, $filter);
    }
    
    public function adb2devices():array{
        $data = "idevicepair pair";
        $filter = "";
        $this->req_str("", $data, $this->stream_timeout, $filter);
        $this->pause();
        //ERROR: Could not validate with device 3e66f3d96ada57fce2060a1aeaf400e7460a2985 because a passcode is set.
        //Please enter the passcode on the device and retry.
        //rohff@labs:~$ idevicepair pair
        //SUCCESS: Paired with device 3e66f3d96ada57fce2060a1aeaf400e7460a2985
        
        // adb server is out of date. killing...
        // daemon started successfully *
        // List of devices attached
        // emulator-5554 device
        
        $data = "adb devices -l";
        $filter = " | grep '	device' | cut -d' ' -f1 ";
        return $this->req_tab("", $data, $this->stream_timeout, $filter);
    }
    
    

    
}

?>