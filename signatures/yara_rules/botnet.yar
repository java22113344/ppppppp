/*
   BOTNET DETECTION RULES
   Detects Command & Control communication
*/

rule Botnet_Generic_C2_Communication {
    meta:
        description = "Detects botnet C2 beaconing"
        author = "Security Team"
        severity = 10
        family = "Botnet"
    
    strings:
        $c2_1 = /http:\/\/[a-z]+\.[a-z]+\/[a-z]/
        $c2_2 = "beacon"
        $c2_3 = "report status"
        $c2_4 = "check in"
        $c2_5 = "command"
        $c2_6 = "update"
    
    condition:
        2 of them
}

rule Botnet_Generic_DGA {
    meta:
        description = "Detects Domain Generation Algorithm"
        severity = 9
    
    strings:
        $dga1 = "GenerateDomain"
        $dga2 = "DGA"
        $dga3 = "domain generation"
        $dga4 = /[a-z]{10,}[0-9]{3,}/
    
    condition:
        2 of them
}

rule Botnet_Mirai {
    meta:
        description = "Detects Mirai botnet"
        severity = 9
        family = "Mirai"
    
    strings:
        $mirai1 = "mirai"
        $mirai2 = "IoT"
        $mirai3 = "telnet"
        $mirai4 = "ssh"
    
    condition:
        2 of them
}

rule Botnet_Zeus_P2P {
    meta:
        description = "Detects Zeus P2P botnet"
        severity = 9
        family = "Zeus"
    
    strings:
        $p2p1 = "p2p"
        $p2p2 = "peer"
        $p2p3 = "node"
        $p2p4 = "zeus"
    
    condition:
        2 of them
}
