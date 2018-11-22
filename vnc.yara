rule ultravnc_server_1_05
{
meta:
	author = "YARANAVOIR"
	maltype = "Misc."
	version = "0.1"
	date = "22/11/2018"
    strings:
        $a = { f3 5b 26 4b a5 4b e7 b0 fd 5d 7f 56 f1 f6 38 2e }
	$b = { 00 74 00 65 00 6d 00 20 00 50 00 72 00 6f 00 70 }
	$c = { 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 77 }
    condition:
        ($a) and ($b) and ($c)
}

rule vnc_hooks_dll_1_05
{
meta:
	author = "YARANAVOIR"
	maltype = "Misc."
	version = "0.1"
	date = "22/11/2018"
    strings:
        $a = { 14 04 02 e1 ff b0 fa 3a 8d d0 d4 7d 98 4d eb 33 }
	$b = { e6 aa c2 e3 8c 8a c3 2a 21 8b 66 87 83 bd 57 58 }
	$c = { 36 e2 36 eb 36 f5 37 3d 37 45 37 5a 37 65 37 b0 }
    condition:
        ($a) and ($b) and ($c)
}

rule vnc_clang_server_dll_1_05
{
meta:
	author = "YARANAVOIR"
	maltype = "Misc."
	version = "0.1"
	date = "22/11/2018"
    strings:
        $a = { 6e 6f 22 3d 2e 31 2e 30 2e 30 30 32 20 22 72 70 }
	$b = { 00 20 00 64 00 61 00 6e 00 73 00 20 00 6c 00 65 }
	$c = { 00 6c 00 6f 00 67 00 69 00 6e 00 20 00 57 00 69 }
    condition:
        ($a) and ($b) and ($c)
}