<?php
class STREAM4REQ extends com4code{
    var $stream ; 
    var $stream_timeout ;
    
    
    public function __construct($stream) {
        parent::__construct();
        $this->stream = $stream;
        $this->stream_timeout = 5 ;
    }

    
    
    
    
    function id2env($id,$nops, $shellcode_hex) {
        $this->ssTitre("PUT $id in ENV" );
        $shell = str_repeat("\x90", $nops );
        $shell .= $this->hex2raw($shellcode_hex);
        $this->cmd("localhost", "export $id=$nops*$shellcode_hex" );
        putenv ("$id=$shell" );
        $this->ssTitre("Check fmt in ENV" );
        // article("Remarque","Shellcode doit etre en raw");
        $this->requette("env | grep '$id' " );
    }
    
    
    
    
    
}
?>