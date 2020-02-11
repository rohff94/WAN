<?php

class com4obj extends com4net {
    var $stream_timeout ;
    var $path_parallel ;
    
    
    function __construct(){
        parent::__construct();
        $this->stream_timeout = 5 ;
    }
   
    public function services4pentest($eth,$domain,$service_name,$protocol,$fonction2run){
        $domain = trim($domain);
        $id8ports = array();
        $id8ips = array();
        $id8service = array();
        
        $this->article("Domain 2 Search",$domain );
        $obj_domain = new DOMAIN($eth, $domain);
        $obj_domain->domain2services($service_name,$protocol,$fonction2run);
        
        
    }
    

    
    
    public function run4split4ip($ip_file_list,$step_by){
        $cmd = "";
        $ob_file = new FILE($ip_file_list);
        $ob_file->requette("cat $ob_file->file_path");
        
        $max_iter = $ob_file->file_file2lines();
        $ob_file->article("ITER",$max_iter);
        $step_by = trim($step_by) ;
        $ob_file->article("STEP BY", $step_by);

        $start1 = 0; $end1 =0;
        while ($start1<$max_iter) {
            $start1 = $end1 ;
            $end1 = $start1+$step_by ;
            $ob_file->requette("cat $ob_file->file_path | awk 'FNR>$start1 && FNR<=$end1' | parallel --progress --no-notice -k -j$step_by php pentest.php IP {} ");            
            $this->pause();
        }

    }
    
    public function run4split4port($service_file_list,$process){
        $cmd = "";
        $ob_file = new FILE($service_file_list);
        $ob_file->requette("cat $ob_file->file_path");
        
        $max_iter = intval($ob_file->req_ret_str("wc -l $ob_file->file_path | cut -d' ' -f1 "));
        $ob_file->article("ITER",$max_iter);
        $process = trim($process) ;
        $ob_file->article("PROC", $process);
        
        $iter = intval($max_iter/$process);
        $ob_file->article("MAX ITER", $iter);
        $thread = $ob_file->service2thread($iter) ;
        $start1 = 0; $end1 =0;
        for($i=0;$end1<=$max_iter;$i++){
            $start1 = $i*$iter ;
            $end1 = $start1+$iter ;
            echo "\n";
            $ob_file->article("START/END $i/$process $iter (Max Iter $max_iter)", "$start1-$end1");
            $ob_file->cmd("localhost","php parallel.php \"awk 'FNR>$start1 && FNR<=$end1' $ob_file->file_path | parallel --progress --no-notice -k -j$thread php pentest.php PORT {} \" \"tac $ob_file->file_path | awk 'FNR>$start1 && FNR<=$end1' | parallel --progress --no-notice -k -j$thread php pentest.php PORT {} \" 0 ");
        }
        //$this->requette("gedit $service_file_list");
        $this->note("kill -9 $(ps aux | grep '$ob_file->file_name'  | grep 'php' | awk '{ print $2}')");
        $this->pause();
        $this->titre("Execution...");
        $start1 = 0; $end1 =0;
        for($i=0;$end1<=$max_iter;$i++){
            $start1 = $i*$iter ;
            $end1 = $start1+$iter ;
            echo "\n";
            $ob_file->article("START/END $i/$process $iter (Max Iter $max_iter)", "$start1-$end1");
            $ob_file->requette("php parallel.php \"awk 'FNR>$start1 && FNR<=$end1' $ob_file->file_path | parallel --progress --no-notice -k -j$thread php pentest.php PORT {} \" \"tac $ob_file->file_path | awk 'FNR>$start1 && FNR<=$end1' | parallel --progress --no-notice -k -j$thread php pentest.php PORT {} \" 0 ");
        }
        return $cmd;
    }
    

    public function run4spilt4cmd($start,$end){
        $cmd = "";
        $middle = $end/2 ;
        if ($middle<=$end-1) return $cmd;
    }
    
    
    
    
    
    
    
    
    
    
}

?>

