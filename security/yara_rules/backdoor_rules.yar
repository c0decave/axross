rule suspicious_network_tools
{
    meta:
        author = "security-scan"
        severity = "medium"
        description = "Common network tooling usage"
    strings:
        $curl = /curl\s+https?:\/\// nocase
        $wget = /wget\s+https?:\/\// nocase
        $nc = /\bnc\s+.*-e\b/ nocase
        $ncat = /\bncat\s+.*-e\b/ nocase
        $socat = /\bsocat\s+tcp/ nocase
        $bash = /bash\s+-i/ nocase
        $powershell = /powershell\s+-enc/ nocase
    condition:
        any of them
}

rule base64_pipe_exec
{
    meta:
        author = "security-scan"
        severity = "high"
        description = "Base64 decoded and piped to shell"
    strings:
        $b1 = /base64\s+-d\s*\|\s*(sh|bash)/ nocase
        $b2 = /base64\s+--decode\s*\|\s*(sh|bash)/ nocase
        $b3 = /base64\s+-d\s*\|\s*python/ nocase
    condition:
        any of them
}

rule suspicious_reverse_shell
{
    meta:
        author = "security-scan"
        severity = "high"
        description = "Common reverse shell patterns"
    strings:
        $rs1 = /\/dev\/tcp\// nocase
        $rs2 = /bash\s+-i\s+>&\s+\/dev\/tcp\// nocase
        $rs3 = /python\s+-c\s+.*socket/ nocase
        $rs4 = /perl\s+-e\s+.*socket/ nocase
        $rs5 = /nc\s+.*\s+\|\s+sh/ nocase
    condition:
        any of them
}
