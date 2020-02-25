<?php

include "./core/0.all.inc.php";

$config = new DATA();
$config->start("Training Ethical Hacking", "");

$config_file_path = "./config.xml";

if(!file_exists($config_file_path)) {
    echo "\n\tFor thee first time you need to enter: Email,user2agent,Mysql Host/Login/Passwd, OPENVAS LOGIN/PASS\n";
    echo "Enter Email:\n";
    $email = trim(fgets(STDIN)); 
    
    echo "Enter USER AGENT:\n";
    $user2agent = trim(fgets(STDIN)); 
    
    echo "Enter MYSQL HOST:\n";
    $mysql_host = trim(fgets(STDIN)); 
    
    echo "Enter MYSQL LOGIN:\n";
    $mysql_login  = trim(fgets(STDIN));
    
    echo "Enter MYSQL PASSWORD:\n";
    $mysql_passwd = trim(fgets(STDIN)); 
    
    echo "Enter OPENVAS LOGIN:\n";
    $openvas_login  = trim(fgets(STDIN));
    
    echo "Enter OPENVAS PASSWORD:\n";
    $openvas_passwd = trim(fgets(STDIN)); 
    
    
    echo "Enter ROOT PASSWORD:\n";
    $root_passwd = trim(fgets(STDIN)); 
    
    echo "Enter faraday workspace name:\n";
    system("ls  ~/.faraday/report/");
    $faraday_workspace_name = trim(fgets(STDIN)); 
    
    
    $myXMLData = <<<CFG
<?xml version='1.0' encoding='UTF-8'?>
<document>
<user2agent>$user2agent</user2agent>
<email>$email</email>
<mysql_host>$mysql_host</mysql_host>
<mysql_login>$mysql_login</mysql_login>
<mysql_passwd>$mysql_passwd</mysql_passwd>
<openvas_login>$openvas_login</openvas_login>
<openvas_passwd>$openvas_passwd</openvas_passwd>
<root_passwd>$root_passwd</root_passwd>
<faraday_workspace_name>$faraday_workspace_name</faraday_workspace_name>
</document>
CFG;
    
    file_put_contents($config_file_path, $myXMLData);
}



$config->install4ub();


$config->requette("sudo chown $config->user2local:$config->user2local -R $config->racine");

?>