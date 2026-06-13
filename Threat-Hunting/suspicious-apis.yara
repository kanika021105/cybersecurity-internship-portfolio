rule SuspiciousWindowsAPIs {
    meta:
        description = "Detects files using suspicious Windows APIs"
        author = "kanika"
    strings:
        $virt_alloc = "VirtualAlloc"      // Memory allocation (shellcode)
        $write_proc = "WriteProcessMemory" // Writing to other processes
        $create_remote = "CreateRemoteThread" // Running code in other processes
        $encrypt_file = "CryptEncrypt"    // File encryption (ransomware)
        $key_log = "SetWindowsHookEx"     // Keylogging
    condition:
        2 of ($virt_alloc, $write_proc, $create_remote, $encrypt_file, $key_log)
}
