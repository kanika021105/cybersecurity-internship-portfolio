rule SmallExecutable {
    meta:
        description = "Finds PE files (executables) smaller than 100KB"
        author = "kanika"
    strings:
        $mz = "MZ"  // DOS header signature
    condition:
        $mz at 0 and filesize < 100KB
}
