/*
EICAR DETECTOR FOR YOUR SCANNER
*/

rule EICAR_TEST_FILE {
    meta:
        description = "EICAR Standard Antivirus Test File"
        severity = 5
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_CMD {
    strings:
        $cmd1 = "cmd.exe"
        $cmd2 = "powershell"
    condition:
        any of them
}
