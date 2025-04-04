/*
 * Tag on large LNK files.
 */

rule largeLNK {
	meta:
		description = "Detects uncommon file size of LNK files"
		author = "ren-zxcyq"
		date = "2025-3-23"
		severity = "LOW"
	condition:
		uint16(0) == 0x004c
		and filename == "*\.lnk"
		and filesize &gt; 500B
}
