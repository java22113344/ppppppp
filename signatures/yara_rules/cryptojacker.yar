/*
   CRYPTOCURRENCY MINER DETECTION RULES
   Detects crypto mining malware
*/

rule Cryptojacker_Generic_Mining {
    meta:
        description = "Detects crypto mining operations"
        author = "Security Team"
        severity = 6
        family = "Cryptojacker"
    
    strings:
        $mine1 = "stratum"
        $mine2 = "mining"
        $mine3 = "miner"
        $mine4 = "monero"
        $mine5 = "xmrig"
        $mine6 = "nicehash"
    
    condition:
        2 of them
}

rule Cryptojacker_Generic_CPU_Usage {
    meta:
        description = "Detects excessive CPU mining"
        severity = 5
    
    strings:
        $cpu1 = "cpu intensive"
        $cpu2 = "process priority"
        $cpu3 = "thread"
        $cpu4 = "affinity"
    
    condition:
        2 of them
}

rule Cryptojacker_Monero {
    meta:
        description = "Detects Monero mining malware"
        severity = 6
        family = "Cryptojacker"
    
    strings:
        $xmr1 = "xmr"
        $xmr2 = "monero"
        $xmr3 = "moneroocean"
        $xmr4 = "donate"
    
    condition:
        2 of them
}

rule Cryptojacker_Bitcoin {
    meta:
        description = "Detects Bitcoin mining malware"
        severity = 6
        family = "Cryptojacker"
    
    strings:
        $btc1 = "bitcoin"
        $btc2 = "btc"
        $btc3 = "stratum"
        $btc4 = "poolserver"
    
    condition:
        2 of them
}
