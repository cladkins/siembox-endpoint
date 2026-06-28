rule SIEMBox_YARA_SelfTest
{
    meta:
        author      = "SIEMBox Endpoint"
        description = "Self-test rule: matches a benign marker string so operators can verify the YARA file-detection pipeline end-to-end without using a live malware sample."
        reference   = "https://github.com/cladkins/siembox-endpoint"
        severity    = "high"
    strings:
        // A deliberately unique, harmless marker. Writing this string into a
        // file inside a watched directory should produce a detection event.
        $marker = "SIEMBOX_YARA_SELFTEST"
    condition:
        $marker
}
