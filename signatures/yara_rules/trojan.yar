/*
   TROJAN DETECTION RULES
   Detects trojan characteristics
   Covers: Zeus, Emotet, Trickbot, Dridex, IcedID
*/

rule Trojan_Generic_C2_Communication {
    meta:
        description = "Detects Command & Control communication"
        author = "Security Team"
        date = "2026-01-03"
        severity = 9
        family = "Trojan"
    
    strings:
        $c2_1 = /http:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
        $c2_2 = /http:\/\/.*\/cmd/
        $c2_3 = /http:\/\/.*\/control/
        $c2_4 = /http:\/\/.*\/bot/
        $c2_5 = /http:\/\/.*\/panel/
        $c2_6 = "beacon"
        $c2_7 = "report"
    
    condition:
        2 of them
}

rule Trojan_Generic_Information_Stealing {
    meta:
        description = "Detects information stealing behavior"
        severity = 8
    
    strings:
        $steal1 = "GetForegroundWindow"
        $steal2 = "GetWindowText"
        $steal3 = "GetClipboardData"
        $steal4 = "GetAsyncKeyState"
        $steal5 = "keylog"
        $steal6 = "password"
        $steal7 = "credential"
    
    condition:
        3 of them
}

rule Trojan_Generic_Network_Activity {
    meta:
        description = "Detects suspicious network activity"
        severity = 7
    
    strings:
        $net1 = "InternetOpen"
        $net2 = "InternetConnect"
        $net3 = "HttpSendRequest"
        $net4 = "URLDownloadToFile"
        $net5 = "WinInet"
        $net6 = "socket"
        $net7 = "recv"
    
    condition:
        3 of them
}

rule Trojan_Generic_Downloader {
    meta:
        description = "Detects trojan downloader patterns"
        severity = 8
    
    strings:
        $down1 = "URLDownloadToFile"
        $down2 = "CreateFileA"
        $down3 = "WriteFile"
        $down4 = "ExecuteA"
        $down5 = "WinExec"
        $down6 = "ShellExecute"
    
    condition:
        3 of them
}

rule Trojan_Generic_Backdoor {
    meta:
        description = "Detects backdoor characteristics"
        severity = 9
    
    strings:
        $bd1 = "CreateProcess"
        $bd2 = "CreateNamedPipe"
        $bd3 = "SetServiceObjectSecurity"
        $bd4 = "CreateService"
        $bd5 = "StartService"
        $bd6 = "cmd.exe"
    
    condition:
        3 of them
}

rule Trojan_Zeus {
    meta:
        description = "Detects Zeus banking trojan"
        severity = 9
        family = "Zeus"
    
    strings:
        $zeus1 = "zeus"
        $zeus2 = "zbot"
        $zeus3 = "config.bin"
        $zeus4 = "knownDLLs"
        $zeus5 = "stolen.data"
    
    condition:
        2 of them
}

rule Trojan_Emotet {
    meta:
        description = "Detects Emotet modular trojan"
        severity = 9
        family = "Emotet"
    
    strings:
        $emotet1 = "emotet"
        $emotet2 = "heodo"
        $emotet3 = "geodo"
        $emotet4 = "scriptupdate"
        $emotet5 = /[0-9]{3}\.[0-9]{3}\.[0-9]{3}\.[0-9]{3}:[0-9]{4,5}/
    
    condition:
        2 of them
}

rule Trojan_Trickbot {
    meta:
        description = "Detects Trickbot banking trojan"
        severity = 9
        family = "Trickbot"
    
    strings:
        $trick1 = "trickbot"
        $trick2 = "trick"
        $trick3 = "tinba"
        $trick4 = "bot"
        $trick5 = "socks5"
    
    condition:
        2 of them
}

rule Trojan_Dridex {
    meta:
        description = "Detects Dridex banking trojan"
        severity = 9
        family = "Dridex"
    
    strings:
        $dridex1 = "dridex"
        $dridex2 = "cridex"
        $dridex3 = "isfb"
        $dridex4 = "bebloh"
        $dridex5 = "bugat"
    
    condition:
        2 of them
}

rule Trojan_IcedID {
    meta:
        description = "Detects IcedID banking trojan"
        severity = 9
        family = "IcedID"
    
    strings:
        $iced1 = "icedid"
        $iced2 = "bokbot"
        $iced3 = "license.dat"
        $iced4 = "stats.dat"
    
    condition:
        2 of them
}

rule Trojan_Generic_Lateral_Movement {
    meta:
        description = "Detects lateral movement techniques"
        severity = 8
    
    strings:
        $lateral1 = "PsExec"
        $lateral2 = "WMI"
        $lateral3 = "RDP"
        $lateral4 = "RemoteRegistry"
        $lateral5 = "SMB"
    
    condition:
        2 of them
}

rule Trojan_Generic_Privilege_Escalation {
    meta:
        description = "Detects privilege escalation attempts"
        severity = 8
    
    strings:
        $priv1 = "privilege"
        $priv2 = "escalate"
        $priv3 = "admin"
        $priv4 = "SYSTEM"
        $priv5 = "UAC"
    
    condition:
        2 of them
}
