<?php

# rename // for i in `find . -type f -iname "*.php" | sort -u`;do  mv -v $i  $(echo "$i" | sed "s/ip.port.auth.service2/service./g") ;done

//  for i in `find . -type f -iname "*.php" | sort -u`;do echo -e "include_once(\"$i\");" | tac | uniq | grep 'core' | grep -v "all.inc" | tee -a ./all.inc.class.php.bak ;done


include_once("./core/00-module_com/1.conf.0.php");
include_once("./core/00-module_com/1.conf.install.0.php");
include_once("./core/00-module_com/2.com.0.com4display.php");
include_once("./core/00-module_com/2.com.1.com4user.php");
include_once("./core/00-module_com/2.com.2.com4net.php");
include_once("./core/00-module_com/2.com.3.com4obj.php");
include_once("./core/00-module_com/2.com.4.com4malw.php");
include_once("./core/00-module_com/2.com.5.com4bin.php");
include_once("./core/00-module_com/2.com.6.com4dot.php");
include_once("./core/00-module_com/2.com.7.com4code.php");
include_once("./core/00-module_com/2.com.8.com4for.php");
include_once("./core/00-module_com/3.data.php");
include_once("./core/01-module_wan/eth.0.php");
include_once("./core/01-module_wan/eth.domain.0.php");
include_once("./core/01-module_wan/eth.host.0.php");
include_once("./core/01-module_wan/ip.0.php");
include_once("./core/01-module_wan/ip.port.0.php");
include_once("./core/01-module_wan/ip.port.auth.0.php");
include_once("./core/01-module_wan/port.0.com.php");
include_once("./core/01-module_wan/service.0.com.php");
include_once("./core/02-module_services/service.asterisk.php");
include_once("./core/02-module_services/service.exploitdb.php");
include_once("./core/02-module_services/service.ftp.php");
include_once("./core/02-module_services/service.ipmi.php");
include_once("./core/02-module_services/service.mysql.php");
include_once("./core/02-module_services/service.netbios.php");
include_once("./core/02-module_services/service.nfs.php");
include_once("./core/02-module_services/service.rlogin.php");
include_once("./core/02-module_services/service.sip.php");
include_once("./core/02-module_services/service.smb.php");
include_once("./core/02-module_services/service.smtp.php");
include_once("./core/02-module_services/service.snmp.php");
include_once("./core/02-module_services/service.ssh.php");
include_once("./core/02-module_services/service.ssl.php");
include_once("./core/02-module_services/service.vnc.php");
include_once("./core/02-module_services/service.vpn.php");
include_once("./core/03-module_web/web.0.php");
include_once("./core/03-module_web/web.url.0.php");
include_once("./core/03-module_web/web.url.param.0.php");
include_once("./core/03-module_web/web.url.param.1.ce.php");
include_once("./core/03-module_web/web.url.param.2.fi.php");
include_once("./core/03-module_web/web.url.param.3.sqli.php");
include_once("./core/03-module_web/web.url.param.4.xml.php");
include_once("./core/03-module_web/web.url.param.5.xss.php");
include_once("./core/03-module_web/web.url.param.all.php");
include_once("./core/04-module_lan/lan.0.php");
include_once("./core/04-module_lan/lan.linux.0.com.php");
include_once("./core/04-module_lan/lan.linux.1.check.0.enum.php");
include_once("./core/04-module_lan/lan.linux.1.check.1.misc.php");
include_once("./core/04-module_lan/lan.linux.1.check.2.exploits.php");
include_once("./core/04-module_lan/lan.linux.1.check.3.suid.php");
include_once("./core/04-module_lan/lan.linux.1.check.4.jobs.php");
include_once("./core/04-module_lan/lan.linux.1.check.5.com.php");
include_once("./core/04-module_lan/lan.linux.1.check.6.users.php");
include_once("./core/04-module_lan/lan.linux.2.root.0.com.php");
include_once("./core/04-module_lan/lan.linux.2.root.1.backdoor.php");
include_once("./core/04-module_lan/lan.linux.2.root.2.injected.php");
include_once("./core/04-module_lan/lan.linux.2.root.3.trojan.php");
include_once("./core/04-module_lan/lan.linux.2.root.4.rootkit.php");
include_once("./core/04-module_lan/lan.linux.2.root.5.pivot.php");
include_once("./core/04-module_lan/lan.linux.2.root.6.tunnel.php");
include_once("./core/04-module_lan/lan.linux.3.root.0.com.php");
include_once("./core/04-module_lan/lan.win.0.php");
include_once("./core/05-module_file/file.0.php");
include_once("./core/05-module_file/file.bin.0.php");
include_once("./core/05-module_file/file.bin.linux.0.php");
include_once("./core/05-module_file/file.bin.win.0.php");
include_once("./core/05-module_file/file.image.php");
include_once("./core/05-module_file/file.pcap.php");
include_once("./core/05-module_file/file.pdf.php");
include_once("./core/05-module_file/file.vm.php");
include_once("./core/06-module_bof4linux/bof4linux.01.ret2code.php");
include_once("./core/06-module_bof4linux/bof4linux.02.ret2int.php");
include_once("./core/06-module_bof4linux/bof4linux.03.ret2fmt.php");
include_once("./core/06-module_bof4linux/bof4linux.04.ret2stack.php");
include_once("./core/06-module_bof4linux/bof4linux.05.ret2lib.php");
include_once("./core/06-module_bof4linux/bof4linux.06.ret2got.php");
include_once("./core/06-module_bof4linux/bof4linux.07.ret2canary.php");
include_once("./core/06-module_bof4linux/bof4linux.08.ret2pie.php");
include_once("./core/06-module_bof4linux/bof4linux.09.ret2rop.php");
include_once("./core/06-module_bof4linux/bof4linux.10.ret2heap.php");
include_once("./core/06-module_bof4linux/bof4linux.sploits.php");
include_once("./core/08-module_bof4win/bof4win.02.ret2int.php");
include_once("./core/08-module_bof4win/bof4win.04.ret2stack.php");
include_once("./core/08-module_bof4win/bof4win.05.ret2lib.php");
include_once("./core/08-module_bof4win/bof4win.07.ret2canary.php");
include_once("./core/09-module_malw4win/malw4win.0.php");
include_once("./core/09-module_malw4win/malw4win.1.backdoor.php");
include_once("./core/09-module_malw4win/malw4win.2.injected.php");
include_once("./core/09-module_malw4win/malw4win.3.trojan.php");
include_once("./core/09-module_malw4win/malw4win.4.rootkit.php");
include_once("./core/09-module_malw4win/malw4win.5.tunnel.php");
include_once("./core/09-module_malw4win/malw4win.6.worm.php");
include_once("./core/10-module_for/vmem.linux.0.php");
include_once("./core/10-module_for/vmem.win.0.php");
include_once("./core/11-module_mob/mob.0.php");
include_once("./core/11-module_mob/mob.android.php");
include_once("./core/12-module_doc/doc.0.php");
include_once("./core/12-module_doc/doc.forensic.php");
include_once("./core/12-module_doc/doc.incident.php");
include_once("./core/12-module_doc/doc.pentest.php");
include_once("./core/13-module_poc/0.poc.0.enum.php");
include_once("./core/13-module_poc/0.poc.1.service.php");
include_once("./core/13-module_poc/0.poc.2.web.php");
include_once("./core/13-module_poc/0.poc.3.lan.php");
include_once("./core/13-module_poc/0.poc.4.bof.php");
include_once("./core/13-module_poc/0.poc.5.root.php");
include_once("./core/13-module_poc/0.poc.6.malware.php");
include_once("./core/13-module_poc/1.poc.php");



?>
