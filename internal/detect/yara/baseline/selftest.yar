rule SIEMBox_YARA_SelfTest
{
    meta:
        author      = "SIEMBox Endpoint"
        description = "Self-test rule: matches a benign marker string so operators can verify the YARA file-detection pipeline end-to-end without using a live malware sample."
        reference   = "https://github.com/cladkins/siembox-endpoint"
        severity    = "high"
    strings:
        // A deliberately unique, harmless marker (the README shows the text
        // to write). Writing it into a file inside a watched
        // directory should produce a detection event. It is spelled in hex
        // so this rule's own text (embedded in the agent binary) does not
        // contain the marker; otherwise every scan matches the agent itself.
        $marker = { 53 49 45 4D 42 4F 58 5F 59 41 52 41 5F 53 45 4C 46 54 45 53 54 }
    condition:
        $marker
}
