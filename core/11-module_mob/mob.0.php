<?php

class mobile extends ETH{
    var $device_name;


    public function __construct($stream,$device) {
        $device = trim($device);
        parent::__construct($stream,$device);
        $this->device_name = basename($device);
    }
	
}
