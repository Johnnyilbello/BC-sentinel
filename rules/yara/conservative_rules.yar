rule BCS_EICAR_Test
{
    meta:
        description = "File di test antivirus EICAR"
        weight = 100
    strings:
        $e = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
    condition:
        filesize <= 128 and $e
}

rule BCS_Encoded_PowerShell
{
    meta:
        description = "PowerShell con parametro encoded"
        weight = 20
    strings:
        $p = /powershell(\.exe)?[ \t]+[^\r\n]{0,200}(-enc|-encodedcommand)[ \t]+[A-Za-z0-9+\/=]{24,}/ nocase ascii
    condition:
        filesize < 5MB and $p
}

rule BCS_Script_Downloader_Primitives
{
    meta:
        description = "Script con primitive di download dinamico"
        weight = 15
    strings:
        $a1 = "DownloadString" nocase ascii
        $a2 = "Invoke-WebRequest" nocase ascii
        $a3 = "URLDownloadToFile" nocase ascii
        $a4 = "bitsadmin" nocase ascii
    condition:
        filesize < 10MB and 2 of them
}

rule BCS_Possible_Packed_PE
{
    meta:
        description = "Possibile PE packed/offuscato"
        weight = 8
    strings:
        $mz = { 4D 5A }
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
    condition:
        $mz at 0 and any of ($upx*)
}
