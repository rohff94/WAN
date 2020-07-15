<?php

class com4for extends com4wifi {
    
 
    public function __construct() {
        parent::__construct();
    }
    
    
    
    
    
    public function for4linux_Dyn4invest_preload_library($stream, $cmd) {
        $cmd = trim($cmd);
        $filter = "";
        $this->req_str($stream,  "/tmp/preloadcheck $cmd", $this->stream_timeout, $filter);
        $filter = trim($filter);
        return $this->req_str($stream,  "gdb --batch -q -ex \"b dlsym\" -ex \"bt\" -ex \"run\" $cmd", $this->stream_timeout, $filter);
    }
    
    
}
?>   