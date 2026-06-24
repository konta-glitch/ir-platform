/*
  Starter YARA rules for the IR platform.

  These are intentionally CONSERVATIVE, low-false-positive starter rules so
  the integration is useful out of the box without flooding reports. For
  real coverage, drop a full public ruleset into this directory — e.g.
  YARA-Forge (https://github.com/YARAHQ/yara-forge) or Florian Roth's
  signature-base (https://github.com/Neo23x0/signature-base). The scanner
  loads every .yar/.yara file in this folder, so adding rulesets is just a
  matter of copying files in.

  Each rule sets meta.severity and meta.mitre so the scanner can map a hit
  straight to a finding without guessing.
*/

rule SUSP_PowerShell_Encoded_Command_In_File
{
    meta:
        description = "File contains a PowerShell encoded-command invocation"
        severity = "high"
        mitre = "T1059.001"
        author = "IR Platform"
    strings:
        $enc1 = "-EncodedCommand" ascii wide nocase
        $enc2 = "-enc " ascii wide nocase
        $enc3 = "FromBase64String" ascii wide nocase
        $iex = "Invoke-Expression" ascii wide nocase
    condition:
        // Require an encoding indicator AND an execution indicator, to avoid
        // matching benign docs that merely mention these strings.
        (any of ($enc*)) and $iex
}

rule SUSP_Mimikatz_Strings
{
    meta:
        description = "File contains Mimikatz credential-dumping strings"
        severity = "critical"
        mitre = "T1003.001"
        author = "IR Platform"
    strings:
        $a = "sekurlsa" ascii wide nocase
        $b = "mimikatz" ascii wide nocase
        $c = "lsadump" ascii wide nocase
        $d = "kerberos::" ascii wide nocase
        $e = "crypto::" ascii wide nocase
    condition:
        2 of them
}

rule SUSP_CobaltStrike_Beacon_Indicators
{
    meta:
        description = "Possible Cobalt Strike beacon configuration markers"
        severity = "critical"
        mitre = "T1071.001"
        author = "IR Platform"
    strings:
        $a = "beacon.dll" ascii wide nocase
        $b = "%s as %s\\%s: %d" ascii
        $c = "ReflectiveLoader" ascii wide nocase
        $d = "%%IMPORT%%" ascii
    condition:
        2 of them
}

rule SUSP_Webshell_Common_Patterns
{
    meta:
        description = "Common web shell execution patterns"
        severity = "high"
        mitre = "T1505.003"
        author = "IR Platform"
    strings:
        $php1 = "eval($_POST" ascii nocase
        $php2 = "eval($_GET" ascii nocase
        $php3 = "system($_REQUEST" ascii nocase
        $asp1 = "eval(Request" ascii nocase
        $jsp1 = "Runtime.getRuntime().exec(request" ascii nocase
    condition:
        any of them
}

rule SUSP_Ransomware_Note_Indicators
{
    meta:
        description = "Possible ransomware ransom-note language"
        severity = "high"
        mitre = "T1486"
        author = "IR Platform"
    strings:
        $a = "your files have been encrypted" ascii wide nocase
        $b = "all your files" ascii wide nocase
        $c = "to decrypt your files" ascii wide nocase
        $d = "bitcoin" ascii wide nocase
        $e = ".onion" ascii wide nocase
    condition:
        // Note language plus a payment/contact channel
        ($a or $b or $c) and ($d or $e)
}
