rule HexStringSearch {
    meta:
        description = "Searches for specific hex patterns used by malware"
        author = "kanika"
    strings:
        $cmd_prompt = { 43 4D 44 20 }  // "CMD " in hex
        $powershell = { 50 4F 57 45 52 53 48 45 4C 4C }  // "POWERSHELL"
        $wildcard_hex = { 4D 5A 90 ?? 00 }  // MZ followed by any byte then 00
    condition:
        $cmd_prompt or $powershell or $wildcard_hex
}
