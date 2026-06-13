rule FindsItself {
    meta:
        description = "This rule detects its own YARA source file"
        author = "kanika"
    strings:
        $rule_name = "FindsItself"
        $yara_keyword = "rule"
        $string_declaration = "$"
    condition:
        $rule_name and $yara_keyword and $string_declaration
}
