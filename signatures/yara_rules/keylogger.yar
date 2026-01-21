/*
   KEYLOGGER DETECTION RULES
   Detects keylogging and input hooking
*/

rule Keylogger_Generic_Hooks {
    meta:
        description = "Detects keylogger hook installations"
        author = "Security Team"
        severity = 8
        family = "Keylogger"
    
    strings:
        $hook1 = "SetWindowsHookEx"
        $hook2 = "GetAsyncKeyState"
        $hook3 = "GetKeyState"
        $hook4 = "GetKeyboardState"
        $hook5 = "GetForegroundWindow"
        $hook6 = "SetWinEventHook"
    
    condition:
        3 of them
}

rule Keylogger_Generic_Data_Exfiltration {
    meta:
        description = "Detects keystroke data collection"
        severity = 7
    
    strings:
        $data1 = "SendMessage"
        $data2 = "WriteFile"
        $data3 = "CreateFile"
        $data4 = "InternetOpen"
        $data5 = "POST"
        $data6 = "SendData"
    
    condition:
        3 of them
}

rule Keylogger_Generic_Hardware {
    meta:
        description = "Detects hardware keylogger communication"
        severity = 7
    
    strings:
        $hw1 = "USB"
        $hw2 = "Serial"
        $hw3 = "COM"
        $hw4 = "keyboard"
        $hw5 = "mouse"
    
    condition:
        2 of them
}

rule Keylogger_Generic_Process_Monitoring {
    meta:
        description = "Detects process window monitoring"
        severity = 6
    
    strings:
        $proc1 = "GetForegroundWindow"
        $proc2 = "GetWindowText"
        $proc3 = "GetProcessId"
        $proc4 = "EnumWindows"
        $proc5 = "GetWindowRect"
    
    condition:
        3 of them
}
