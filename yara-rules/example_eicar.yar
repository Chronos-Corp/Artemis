/*
Example rule so YARA scanning has something to demonstrate out of the box.
Matches the EICAR antivirus test string, not real malware. Replace this
directory's contents with your own rule set; anything under yara-rules/
(or the path in NSIC_YARA_RULES_DIR) is loaded at startup.
*/
rule Example_EICAR_Test_File
{
    meta:
        description = "Detects the EICAR AV test string"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}
