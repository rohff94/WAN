<?php


if ($argc != 4) {
	echo "\033[01;31m Usage: " . __FILE__ . " cmd1 cmd2 time2sleep \033[0m\n";
	var_dump($argc);
	var_dump($argv);
	exit ( 0 );
}
$cmd1 = trim ( $argv [1] );
$cmd2 = trim ( $argv [2] );
$time2sleep = trim ( $argv [3] );

$cmd1_exec = base64_decode($cmd1);
$cmd2_exec = base64_decode($cmd2);


//$query1 = "$cmd1_exec 2> /dev/null ";
$query1 = "xterm -T \"$cmd1\" -e \"echo $cmd1 | base64 -d | sh - \" 2> /dev/null ";
$query2 = "$cmd2_exec";
echo "\t\033[32;40;1;1m Open two Terminals Windows\033[0m\n";
echo "\t\033[36;40;1;1m 1:\033[0m \033[37;40;1;1m $cmd1_exec \033[0m\n";
echo "\t\033[36;40;1;1m Time:\033[0m \033[37;40;1;1m $time2sleep \033[0m\n";
echo "\t\033[36;40;1;1m 2:\033[0m \033[37;40;1;1m $query2 \033[0m\n";

$pid = pcntl_fork ();
if ($pid) {
	system ( $query1 );
} else {
	sleep ( $time2sleep );
	system ( $query2 );
}

?>
