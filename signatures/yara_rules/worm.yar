/*
   WORM DETECTION RULES
   Detects self-replicating malware
*/

rule Worm_Generic_Replication {
    meta:
        description = "Detects worm replication patterns"
        author = "Security Team"
        severity = 9
        family = "Worm"
    
    strings:
        $rep1 = "CopyFile"
        $rep2 = "CopyFileEx"
        $rep3 = "MoveFile"
        $rep4 = "CreateFile"
        $rep5 = "WriteFile"
        $rep6 = "FindFirstFile"
    
    condition:
        4 of them
}

rule Worm_Generic_Network_Propagation {
    meta:
        description = "Detects network-based propagation"
        severity = 9
    
    strings:
        $net1 = /\\\\.*\\share/
        $net2 = /\\\\.*\\backup/
        $net3 = "InternetOpen"
        $net4 = "SMTP"
        $net5 = "SendMail"
    
    condition:
        2 of them
}

rule Worm_Generic_USB_Propagation {
    meta:
        description = "Detects USB-based propagation"
        severity = 8
    
    strings:
        $usb1 = "USB"
        $usb2 = "autorun.inf"
        $usb3 = "removable media"
        $usb4 = "GetDriveType"
    
    condition:
        2 of them
}

rule Worm_Conficker {
    meta:
        description = "Detects Conficker worm"
        severity = 10
        family = "Conficker"
    
    strings:
        $conf1 = "conficker"
        $conf2 = "downadup"
        $conf3 = "kido"
        $conf4 = "windows-update"
    
    condition:
        2 of them
}

rule Worm_WannaCry_Propagation {
    meta:
        description = "Detects WannaCry worm network propagation"
        severity = 10
        family = "WannaCry"
    
    strings:
        $wan1 = "EternalBlue"
        $wan2 = "445"
        $wan3 = "smb"
        $wan4 = "propagate"
    
    condition:
        2 of them
}
