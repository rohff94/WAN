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
//$query1 = "python /usr/bin/terminator --geometry=1100x450-0+0 -T \"1: $cmd1\" -e \"$cmd1 && read Enter\" 2> /dev/null ";
//$query2 = "python /usr/bin/terminator --geometry=1100x450-0-0 -T \"2: $cmd2\" -e \"$cmd2 && read Enter\" 2> /dev/null ";
//$query1 = "gnome-terminal -e  \"$cmd1 | base64 -d | sh - \" 2> /dev/null ";
//$query2 = "gnome-terminal -e  \"$cmd2 | base64 -d | sh - \" 2> /dev/null ";
//$cmd1 = addcslashes($cmd1,'"');
//$cmd2 = addcslashes($cmd2,'"');
$query1 = "xterm -T \"$cmd1\" -e \"echo $cmd1 | base64 -d | sh - \" 2> /dev/null ";
$query2 = "xterm -T \"$cmd2\" -e \"echo $cmd2 | base64 -d | sh - \" 2> /dev/null ";
echo "\t\033[32;40;1;1m Open two Terminals Windows\033[0m\n";
//echo "\t\033[36;40;1;1m 1:\033[0m \033[37;40;1;1m $query1 \033[0m\n";
echo "\t\033[36;40;1;1m 1:\033[0m \033[37;40;1;1m $cmd1_exec \033[0m\n";
//echo "\t\033[36;40;1;1m 2:\033[0m \033[37;40;1;1m $query2 \033[0m\n";
echo "\t\033[36;40;1;1m 2:\033[0m \033[37;40;1;1m $cmd2_exec \033[0m\n";

$pid = pcntl_fork ();
if ($pid) {
	system ( $query1 );
} else {
	sleep ( $time2sleep );
	system ( $query2 );
}

?>
