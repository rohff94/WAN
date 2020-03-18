<?php

$config_file_path = "./config.php";

if(!file_exists($config_file_path)) {
    echo "\n\tYou are Using this tools For the first time, you need to enter: Email,user2agent,Mysql Host/Login/Passwd, root PASS\n";
    echo "Enter Email:\n";
    $user2email = trim(fgets(STDIN)); 
    
    echo "Enter USER AGENT:\n";
    $user2agent = trim(fgets(STDIN)); 
    
    echo "Enter MYSQL HOST:\n";
    $mysql_host = trim(fgets(STDIN)); 
    
    echo "Enter MYSQL LOGIN:\n";
    $mysql_login  = trim(fgets(STDIN));
    
    echo "Enter MYSQL PASSWORD:\n";
    $mysql_passwd = trim(fgets(STDIN)); 
    
    echo "Enter ROOT PASSWORD:\n";
    $root_passwd = trim(fgets(STDIN)); 

    
    
    $myXMLData = <<<CFG
<?php
\$user2email = '$user2email';
\$user2agent = '$user2agent';
\$mysql_host = '$mysql_host';
\$mysql_login  = '$mysql_login';
\$mysql_passwd = '$mysql_passwd';
\$root_passwd = '$root_passwd';
?>
CFG;
    
    file_put_contents($config_file_path, $myXMLData);
}


include "./core/0.all.inc.php";
$config = new DATA();
$config->start("Installing All Tools", "");
$config->install4ub();
$config->requette("sudo chown $config->user2local:$config->user2local -R $config->racine");






?>