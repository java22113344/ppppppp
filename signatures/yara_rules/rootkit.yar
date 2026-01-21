/*
   ROOTKIT DETECTION RULES
   Detects rootkit characteristics
   Covers: Kernel-level hooks, SSDT modifications
*/

rule Rootkit_Generic_Kernel_Hook {
    meta:
        description = "Detects kernel-level hooks"
        author = "Security Team"
        date = "2026-01-03"
        severity = 10
        family = "Rootkit"
    
    strings:
        $hook1 = "SetWindowsHookEx"
        $hook2 = "SetWinEventHook"
        $hook3 = "IAT Hook"
        $hook4 = "SSDT Hook"
        $hook5 = "Code Cave"
        $hook6 = "Inline Hook"
    
    condition:
        2 of them
}

rule Rootkit_Generic_Hidden_Process {
    meta:
        description = "Detects process hiding techniques"
        severity = 9
    
    strings:
        $hide1 = "HideProcess"
        $hide2 = "UnlinkFromActiveProcessList"
        $hide3 = "NtQuerySystemInformation"
        $hide4 = "CreateRemoteThread"
        $hide5 = "Ring 0"
    
    condition:
        2 of them
}

rule Rootkit_Generic_Kernel_Mode {
    meta:
        description = "Detects kernel mode operations"
        severity = 10
    
    strings:
        $kernel1 = "kernel mode"
        $kernel2 = "kernel"
        $kernel3 = ".sys"
        $kernel4 = "driver"
        $kernel5 = "ioctl"
        $kernel6 = "Ring 0"
    
    condition:
        2 of them
}

rule Rootkit_Generic_Device_Driver {
    meta:
        description = "Detects suspicious device drivers"
        severity = 9
    
    strings:
        $driver1 = ".sys"
        $driver2 = "DriverEntry"
        $driver3 = "Irp"
        $driver4 = "IOCTL"
        $driver5 = "DeviceControl"
    
    condition:
        2 of them
}

rule Rootkit_Generic_File_Hiding {
    meta:
        description = "Detects file system hiding"
        severity = 8
    
    strings:
        $fhide1 = "DirectoryControl"
        $fhide2 = "SetFilePointer"
        $fhide3 = "ReadFile"
        $fhide4 = "AlternateDataStream"
        $fhide5 = "ADS"
    
    condition:
        2 of them
}

rule Rootkit_Generic_Registry_Hiding {
    meta:
        description = "Detects registry manipulation"
        severity = 8
    
    strings:
        $reghide1 = "RegOpenKey"
        $reghide2 = "RegQueryValue"
        $reghide3 = "RegSetValue"
        $reghide4 = "CmRegisterCallback"
        $reghide5 = "HookRegistry"
    
    condition:
        2 of them
}

rule Rootkit_Stuxnet {
    meta:
        description = "Detects Stuxnet rootkit"
        severity = 10
        family = "Stuxnet"
    
    strings:
        $stux1 = "stuxnet"
        $stux2 = "siemens"
        $stux3 = "step7"
        $stux4 = "mrxnet.sys"
    
    condition:
        2 of them
}

rule Rootkit_ZeroAccess {
    meta:
        description = "Detects ZeroAccess rootkit"
        severity = 10
        family = "ZeroAccess"
    
    strings:
        $za1 = "zeroaccess"
        $za2 = "max++"
        $za3 = "sirefef"
        $za4 = "tilded"
    
    condition:
        2 of them
}

rule Rootkit_TDSS {
    meta:
        description = "Detects TDSS/Alureon rootkit"
        severity = 10
        family = "TDSS"
    
    strings:
        $tdss1 = "tdss"
        $tdss2 = "alureon"
        $tdss3 = "rtkt"
        $tdss4 = "mbrk"
    
    condition:
        2 of them
}

rule Rootkit_Generic_Bootkit {
    meta:
        description = "Detects bootkit characteristics"
        severity = 10
    
    strings:
        $boot1 = "MBR"
        $boot2 = "Master Boot Record"
        $boot3 = "bootloader"
        $boot4 = "BIOS"
        $boot5 = "UEFI"
    
    condition:
        2 of them
}

rule Rootkit_Generic_Network_Hiding {
    meta:
        description = "Detects network connection hiding"
        severity = 8
    
    strings:
        $nethide1 = "TcpTable"
        $nethide2 = "UdpTable"
        $nethide3 = "HookNetwork"
        $nethide4 = "HideConnection"
    
    condition:
        2 of them
}

rule Rootkit_Generic_Anti_Detection {
    meta:
        description = "Detects anti-rootkit detection techniques"
        severity = 9
    
    strings:
        $anti1 = "UnhookWindowsHookEx"
        $anti2 = "RemoveHook"
        $anti3 = "DetectionEvasion"
        $anti4 = "AntiDebug"
        $anti5 = "AntiVM"
    
    condition:
        2 of them
}
