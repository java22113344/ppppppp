/*
   RANSOMWARE DETECTION RULES
   Detects ransomware characteristics
   Covers: WannaCry, Petya, Cerber, Locky, GandCrab
*/

rule Ransomware_Generic_Encryption {
    meta:
        description = "Detects ransomware encryption patterns"
        author = "Security Team"
        date = "2026-01-03"
        severity = 9
        family = "Ransomware"
    
    strings:
        $enc1 = "CryptEncrypt"
        $enc2 = "CryptDecrypt"
        $enc3 = "CryptCreateHash"
        $enc4 = "CryptImportKey"
        $enc5 = "AES_Encrypt"
        $enc6 = "RSA_Encrypt"
        $enc7 = "EVP_Encrypt"
    
    condition:
        2 of them
}

rule Ransomware_Generic_File_Extension {
    meta:
        description = "Detects ransomware file extension patterns"
        severity = 8
    
    strings:
        $ext1 = ".locked"
        $ext2 = ".encrypted"
        $ext3 = ".cry"
        $ext4 = ".cerber"
        $ext5 = ".locky"
        $ext6 = ".wannacry"
        $ext7 = ".petya"
        $ext8 = ".onion"
        $ext9 = ".bitcoin"
    
    condition:
        1 of them
}

rule Ransomware_Generic_Ransom_Note {
    meta:
        description = "Detects ransomware ransom note creation"
        severity = 9
    
    strings:
        $ransom1 = "!READ_ME!"
        $ransom2 = "README.txt"
        $ransom3 = "DECRYPT.txt"
        $ransom4 = "HELP_RESTORE"
        $ransom5 = "HOW_TO_DECRYPT"
        $ransom6 = "Your files are encrypted"
        $ransom7 = "pay in bitcoins"
        $ransom8 = "contact us"
    
    condition:
        1 of them
}

rule Ransomware_Generic_Crypto_Currency {
    meta:
        description = "Detects cryptocurrency references"
        severity = 7
    
    strings:
        $crypto1 = "Bitcoin"
        $crypto2 = "BTC"
        $crypto3 = "Monero"
        $crypto4 = "XMR"
        $crypto5 = "wallet"
        $crypto6 = "address"
        $crypto7 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/  // Bitcoin address
    
    condition:
        2 of them
}

rule Ransomware_Generic_Volume_Shadow_Copy {
    meta:
        description = "Detects attempts to delete shadow copies"
        severity = 9
    
    strings:
        $vss1 = "vssadmin"
        $vss2 = "delete shadows"
        $vss3 = "shadow copy"
        $vss4 = "wmic"
        $vss5 = "shadowcopy"
        $vss6 = "fsutil"
    
    condition:
        2 of them
}

rule Ransomware_Generic_System_Disable {
    meta:
        description = "Detects attempts to disable system protection"
        severity = 8
    
    strings:
        $sys1 = "taskkill"
        $sys2 = "Windows Defender"
        $sys3 = "Firewall"
        $sys4 = "UAC"
        $sys5 = "disable"
        $sys6 = "WinDefend"
    
    condition:
        2 of them
}

rule Ransomware_WannaCry {
    meta:
        description = "Detects WannaCry ransomware"
        severity = 10
        family = "WannaCry"
    
    strings:
        $wc1 = "wcry"
        $wc2 = ".wncry"
        $wc3 = "taskdl.exe"
        $wc4 = "tasksche.exe"
        $wc5 = "WNcry2.0"
        $wc6 = "EternalBlue"
    
    condition:
        2 of them
}

rule Ransomware_Petya {
    meta:
        description = "Detects Petya/NotPetya ransomware"
        severity = 10
        family = "Petya"
    
    strings:
        $petya1 = ".petya"
        $petya2 = "petya"
        $petya3 = "perfc"
        $petya4 = "chcp.com"
        $petya5 = "attrib.exe"
        $petya6 = "taskkill"
    
    condition:
        3 of them
}

rule Ransomware_Locky {
    meta:
        description = "Detects Locky ransomware"
        severity = 9
        family = "Locky"
    
    strings:
        $locky1 = ".locky"
        $locky2 = ".asacp"
        $locky3 = ".odin"
        $locky4 = ".thor"
        $locky5 = "Locky"
        $locky6 = "affid="
    
    condition:
        2 of them
}

rule Ransomware_Cerber {
    meta:
        description = "Detects Cerber ransomware"
        severity = 9
        family = "Cerber"
    
    strings:
        $cerber1 = ".cerber"
        $cerber2 = ".cerber2"
        $cerber3 = ".cerber3"
        $cerber4 = "decryption_id"
        $cerber5 = "Cerber"
    
    condition:
        2 of them
}

rule Ransomware_GandCrab {
    meta:
        description = "Detects GandCrab ransomware"
        severity = 9
        family = "GandCrab"
    
    strings:
        $gandcrab1 = ".GDCB"
        $gandcrab2 = "gandcrab"
        $gandcrab3 = ".crab"
        $gandcrab4 = "GandCrab"
        $gandcrab5 = "readmecrab"
    
    condition:
        2 of them
}

rule Ransomware_Generic_Drive_Enumeration {
    meta:
        description = "Detects drive enumeration (target search)"
        severity = 7
    
    strings:
        $drive1 = "GetLogicalDrives"
        $drive2 = "GetDriveType"
        $drive3 = "FindFirstFile"
        $drive4 = "FindNextFile"
        $drive5 = "SetFilePointer"
    
    condition:
        3 of them
}
