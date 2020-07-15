<?php

class com4file extends com4net {
    
    
    public function __construct() {
        parent::__construct();
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