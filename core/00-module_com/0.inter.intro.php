<?php


abstract class intro{
	

	
	
	public function start($chaine,$sommaire){
	    system("clear");
	    echo("\n\t\t[#] Title: $chaine\n\t\t[#] Version: 0.8\n\t\t[#] Date: ".date('l jS \of F Y h:i:s A')."\n\t\t[#] Author: Mr. Rafik GUEHRIA\n\t\t[#] Job: Trainer Ethical Hacking, Pentester, Digital Forensic Investigator, Exploit Development.\n\t\t[#] \t\t( CEH, ECSA, LPT, CHFI, SEC760 )\n\t\t[#] CV: https://www.linkedin.com/in/rguehria/\n\t\t[#] VDO: https://www.youtube.com/user/rof94\n\t\t[#] Website Perso: http://www.pentesting.eu\n\t\t[#] Email Perso: r.guehria@pentesting.eu\n\t\t[#] GitHub: https://github.com/rohff94/WAN\n");
	    system("/usr/games/cowsay -f '/usr/share/cowsay/cows/ghostbusters.cow' \"\033[36;1;1m".strtoupper($chaine)."\033[0m\n$sommaire\"");
	    echo "\n";
	}
		
	

	
	
}
?>
