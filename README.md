# WAN


DOMAIN:
WAN$ php pentest.php DOMAIN "<interface> <domain> <function2run> <pause for true or false>"
WAN$ php pentest.php DOMAIN "vmnet6 hack.vlan domain4pentest false"

HOST : 
WAN$ php pentest.php HOST "<interface> <domain> <hostname> <function2run> <pause for true or false>"
WAN$ php pentest.php HOST "vmnet6 hack.vlan host4pentest false"

IP:
WAN$ php pentest.php IP "<interface> <domain> <ip> <function2run> <pause for true or false>"
WAN$ php pentest.php IP "vmnet6 hack.vlan 10.60.10.163 ip4service false"
WAN$ php pentest.php IP "vmnet6 hack.vlan 10.60.10.163 ip4pentest true"

PORT:
WAN$ php pentest.php PORT "<interface> <domain> <ip> <port Number> <Protocol T|U > <function2run> <pause for true or false>"
WAN$ php pentest.php PORT "vmnet6 hack.vlan 10.60.10.163 80 T port4pentest true"

WEB:
WAN$ php pentest.php WEB "<interface> <domain> <siteweb> <function2run> <pause for true or false>"
WAN$ php pentest.php WEB "vmnet6 hack.vlan http://owasp.hack.vlan:80/ web4pentest true"

URL:
WAN$ php pentest.php URL "<interface> <domain> <url> <function2run> <pause for true or false>"
WAN$ php pentest.php URL "vmnet6 hack.vlan http://owasp.hack.vlan:80/test.php?id=1 url4pentest true"


FOR:
WAN$ php pentest.php FOR "<type WIN|LINUX> <vmem_path> <vmem_profile> "
WAN$ php pentest.php FOR "WIN /tmp/stuxnet.vmem WinXPSP2x86"
WAN$ php pentest.php FOR "LINUX /tmp/test.vmem ub1604x86"