/*
 * Tag on cmd.exe
 */

import "pe"


rule cmd {
	meta:
		author = "zxcyq"
	strings:
		$str_cmdPDB = "cmd.pdb" nocase
		$str_copyright = "Copyright (c) Microsoft Corporation. All rights reserved." nocase
		$str_startShellExecServiceProviderHeader = "onecore\\base\\cmd\\StartShellExecServiceProvider.h" nocase
	condition:
		(
			filesize == 283KB and // filesize > 200KB and filesize < 285KB and
			pe.is_pe and
			pe.characteristics & pe.EXECUTABLE_IMAGE and // (not pe.is_dll()) and
			pe.number_of_exports == 0 and
			pe.imports("ntdll.dll") and

			all of ($str_*)
		)
}
