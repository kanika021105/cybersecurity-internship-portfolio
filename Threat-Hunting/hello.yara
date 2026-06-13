rule HelloWorld {
    meta:
        description = "This rule finds files containing the word Hello"
        author = "kanika"
        date = "2026-06-12"
    strings:
        $text = "Hello"
    condition:
        $text
}
