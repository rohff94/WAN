<?php

# rename // for i in `find . -type f -iname "*.php" | sort -u`;do  mv -v $i  $(echo "$i" | sed "s/ip.port.auth.service2/service./g") ;done

//  for i in `find . -type f -iname "*.php" | sort -u`;do echo -e "include_once(\"$i\");" | tac | uniq | grep -E "(core|poc)" | grep -v "all.inc" | tee -a ./all.inc.class.php.bak ;done

include_once("./core/00-module_conf/1.conf.0.php");
include_once("./core/00-module_conf/1.conf.install.0.php");
include_once("./core/01-module_data/1.display.php");
include_once("./core/01-module_data/3.data.php");
include_once("./core/02-module_com/2.com.1.com4user.php");
include_once("./core/02-module_com/2.com.2.com4net.php");
include_once("./core/02-module_com/2.com.3.com4file.php");
include_once("./core/02-module_com/2.com.4.com4malw.php");
include_once("./core/02-module_com/2.com.5.com4bin.php");
include_once("./core/02-module_com/2.com.6.com4dot.php");
include_once("./core/02-module_com/2.com.7.com4wifi.php");
include_once("./core/02-module_com/2.com.8.com4code.php");
include_once("./core/03-module_local/0.stream.php");
include_once("./core/03-module_local/eth.0.php");
include_once("./core/03-module_local/eth.cidr.php");
include_once("./core/03-module_local/eth.domain.0.php");
include_once("./core/03-module_local/eth.host.0.php");
include_once("./core/03-module_local/ip.0.php");
include_once("./core/03-module_local/ip.port.0.php");
include_once("./core/04-module_wan/0.file.com/1.file.0.php");
include_once("./core/04-module_wan/0.file.com/1.file.bin.0.php");
include_once("./core/04-module_wan/0.file.com/1.file.bin.linux.0.php");
include_once("./core/04-module_wan/0.file.com/file.image.php");
include_once("./core/04-module_wan/0.file.com/file.pcap.php");
include_once("./core/04-module_wan/1.file.bof.linux/bof4linux.01.ret2code.php");
include_once("./core/04-module_wan/1.file.bof.linux/bof4linux.02.ret2int.php");
include_once("./core/04-module_wan/1.file.bof.linux/bof4linux.03.ret2fmt.php");
include_once("./core/04-module_wan/1.file.bof.linux/bof4linux.04.ret2stack.php");
include_once("./core/04-module_wan/1.file.bof.linux/bof4linux.05.ret2lib.php");
include_once("./core/04-module_wan/1.file.bof.linux/bof4linux.06.ret2got.php");
include_once("./core/04-module_wan/1.file.bof.linux/bof4linux.07.ret2canary.php");
include_once("./core/04-module_wan/1.file.bof.linux/bof4linux.08.ret2pie.php");
include_once("./core/04-module_wan/1.file.bof.linux/bof4linux.09.ret2rop.php");
include_once("./core/04-module_wan/1.file.bof.linux/bof4linux.10.ret2heap.php");
include_once("./core/04-module_wan/1.file.bof.linux/bof4linux.sploits.php");
include_once("./core/04-module_wan/2.com.9.auth.php");
include_once("./core/04-module_wan/lan.linux.0.check.0.protocol.php");
include_once("./core/04-module_wan/lan.linux.1.check.0.enum.php");
include_once("./core/04-module_wan/lan.linux.1.check.1.key.php");
include_once("./core/04-module_wan/lan.linux.1.check.1.misc.php");
include_once("./core/04-module_wan/lan.linux.1.check.2.exploits.php");
include_once("./core/04-module_wan/lan.linux.1.check.3.suid.php");
include_once("./core/04-module_wan/lan.linux.1.check.4.jobs.php");
include_once("./core/04-module_wan/lan.linux.2.root.1.backdoor.php");
include_once("./core/04-module_wan/lan.linux.2.root.2.injected.php");
include_once("./core/04-module_wan/lan.linux.2.root.3.trojan.php");
include_once("./core/04-module_wan/lan.linux.2.root.4.rootkit.php");
include_once("./core/04-module_wan/lan.linux.2.root.5.pivot.php");
include_once("./core/04-module_wan/lan.linux.2.root.6.tunnel.php");
include_once("./core/04-module_wan/lan.linux.3.check.5.com.php");
include_once("./core/04-module_wan/service.0.asterisk.php");
include_once("./core/04-module_wan/service.0.smb.php");
include_once("./core/04-module_wan/service.0.ssh.php");
include_once("./core/05-module_service/service.1.all.php");
include_once("./core/06-module_web/web.0.php");
include_once("./core/06-module_web/web.url.0.php");
include_once("./core/06-module_web/web.url.param.0.php");
include_once("./core/06-module_web/web.url.param.1.ce.php");
include_once("./core/06-module_web/web.url.param.2.fi.php");
include_once("./core/06-module_web/web.url.param.3.sqli.php");
include_once("./core/06-module_web/web.url.param.4.xml.php");
include_once("./core/06-module_web/web.url.param.5.xss.php");
include_once("./core/06-module_web/web.url.param.all.php");
include_once("./core/07-module_lan/lan.0.php");
include_once("./core/07-module_lan/lan.linux.0.com.php");
include_once("./core/07-module_lan/lan.linux.1.check.6.users.php");






?>
