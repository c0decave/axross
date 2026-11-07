/*
 * axross supply-chain rules: what malicious PyPI packages do, beyond
 * GuardDog's rules (both run in security/supply_chain_scan.py). A hit is a
 * reason to read the code, recorded in the package's baseline when it is
 * harmless; a new hit in a version change fails the gate.
 *
 * meta: severity high|medium, path_include as GuardDog's (file names).
 */

rule axross_reverse_shell_dup2
{
    meta:
        description = "socket connected and its descriptor duplicated onto stdin/stdout - a reverse shell"
        severity = "high"
        path_include = "*.py,*.pyw,*.pth,*.pyx"
    strings:
        $connect = /\.connect\s*\(\s*\(\s*['"][^'"]+['"]\s*,\s*\d{2,5}\s*\)\s*\)/
        $dup2 = /os\s*\.\s*dup2\s*\(\s*\w+\s*\.\s*fileno\s*\(\s*\)\s*,\s*[012]\s*\)/
        $pty = /pty\s*\.\s*spawn\s*\(\s*['"]\/bin\/(ba|z)?sh/
        $shell = /['"]\/bin\/(ba|z)?sh['"]\s*,\s*['"]-i['"]/
    condition:
        $dup2 and ($connect or $pty or $shell)
}

rule axross_download_chmod_exec
{
    meta:
        description = "a file downloaded, made executable and started"
        severity = "high"
        path_include = "*.py,*.pyw,*.pth,setup.py,*.sh"
    strings:
        $dl1 = /urlretrieve\s*\(/
        $dl2 = /urlopen\s*\([^)]*\)\s*\.\s*read\s*\(/
        $dl3 = /requests\s*\.\s*get\s*\([^)]*\)\s*\.\s*content/
        $dl4 = /(curl|wget)\s+(-[a-zA-Z]+\s+)*https?:\/\//
        $chmod1 = /os\s*\.\s*chmod\s*\([^)]*(0o?7[0-7][0-7]|S_IX|stat\.S_IEXEC)/
        $chmod2 = /chmod\s+\+?[0-7]*x/
        $run = /(subprocess\s*\.\s*(Popen|call|run|check_output)|os\s*\.\s*(system|startfile|exec[lv]p?e?))\s*\(/
    condition:
        any of ($dl*) and any of ($chmod*) and $run
}

rule axross_pipe_to_shell
{
    meta:
        description = "a download piped into a shell or an interpreter"
        severity = "high"
        path_include = "*.py,*.pyw,*.pth,setup.py,*.cfg,*.toml,*.sh"
    strings:
        $a = /(curl|wget)\s[^|\n]{0,200}\|\s*(ba|z)?sh\b/
        $b = /(curl|wget)\s[^|\n]{0,200}\|\s*python[23]?\b/
        $c = /iex\s*\(\s*(New-Object\s+Net\.WebClient|iwr|Invoke-WebRequest)/ nocase
    condition:
        any of them
}

rule axross_windows_lolbins
{
    meta:
        description = "Windows living-off-the-land downloaders and encoded PowerShell"
        severity = "high"
        path_include = "*.py,*.pyw,*.pth,setup.py,*.bat,*.cmd,*.ps1"
    strings:
        $a = /powershell(\.exe)?["']?\s*,?\s*["']?\s*-(e|en|enc|encodedcommand)\b/ nocase
        $b = /certutil(\.exe)?\s+-urlcache/ nocase
        $c = /mshta(\.exe)?\s+https?:/ nocase
        $d = /bitsadmin(\.exe)?\s+\/transfer/ nocase
        $e = /regsvr32(\.exe)?\s+\/s\s+\/n\s+\/u\s+\/i:http/ nocase
        $f = /rundll32(\.exe)?\s+javascript:/ nocase
    condition:
        any of them
}

rule axross_persistence
{
    meta:
        description = "writes itself into a shell rc, cron, autostart or the Run key"
        severity = "high"
        path_include = "*.py,*.pyw,*.pth,setup.py"
    strings:
        $rc = /(\.bashrc|\.zshrc|\.bash_profile|\.profile|\.zprofile)['"]?\s*[,)]/
        $append = /open\s*\(.{0,200},\s*['"]a\+?b?['"]\s*\)/
        $cron = /(crontab\s+-l|\/etc\/cron\.d|\/var\/spool\/cron)/
        $autostart = /\.config\/autostart\/[^'"]*\.desktop/
        $runkey = /Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run/ nocase
        $launch = /Library\/LaunchAgents\/[^'"]+\.plist/
        $systemd = /\.config\/systemd\/user\/[^'"]+\.service/
    condition:
        ($rc and $append) or $cron or $autostart or $runkey or $launch or $systemd
}

rule axross_credential_theft
{
    meta:
        description = "reads credential stores or browser profiles and has a way out (network)"
        severity = "high"
        path_include = "*.py,*.pyw,*.pth,setup.py"
    strings:
        $s1 = ".ssh/id_rsa"
        $s2 = ".ssh/id_ed25519"
        $s3 = ".aws/credentials"
        $s4 = ".git-credentials"
        $s5 = ".pypirc"
        $s6 = ".npmrc"
        $s7 = ".docker/config.json"
        $s8 = ".kube/config"
        $s9 = "Login Data"
        $s10 = "Local State"
        $s11 = "wallet.dat"
        $s12 = /Exodus|Electrum|MetaMask|atomic\\Local Storage/
        $s13 = "Cookies"
        $s14 = /\.mozilla\/firefox\/[^'"]*logins\.json|key4\.db/
        $net1 = /requests\s*\.\s*(post|put)\s*\(/
        $net2 = /urlopen\s*\(\s*\w+\s*,\s*data\s*=/
        $net3 = /smtplib|ftplib|socket\s*\.\s*socket/
        $net4 = /discord(app)?\.com\/api\/webhooks|api\.telegram\.org\/bot/
    condition:
        2 of ($s*) and any of ($net*)
}

rule axross_fingerprint_beacon
{
    meta:
        description = "user, host and environment collected and sent - a beacon of a stealer or a dependency-confusion probe"
        severity = "high"
        path_include = "*.py,*.pyw,*.pth,setup.py"
    strings:
        $u = /getpass\s*\.\s*getuser\s*\(|os\s*\.\s*getlogin\s*\(|os\s*\.\s*environ\s*\[\s*['"](USER|USERNAME)['"]\s*\]/
        $h = /socket\s*\.\s*gethostname\s*\(|platform\s*\.\s*node\s*\(|os\s*\.\s*uname\s*\(/
        $send1 = /requests\s*\.\s*(post|get)\s*\([^)]*(params|data|json)\s*=/
        $send2 = /urlopen\s*\(\s*['"]https?:\/\/[^'"]+\?[^'"]*['"]\s*\+/
        $send3 = /socket\s*\.\s*(gethostbyname|getaddrinfo)\s*\([^)]*\+[^)]*\./
    condition:
        $u and $h and any of ($send*)
}

rule axross_install_hook_cmdclass
{
    meta:
        description = "setup.py replaces the install/develop/egg_info command - code at install time"
        severity = "medium"
        path_include = "setup.py"
    strings:
        $c = /cmdclass\s*=\s*\{[^}]*['"](install|develop|egg_info|bdist_wheel|build_py)['"]\s*:/
        $net = /urlopen|requests\.|socket\.|subprocess|os\.system|exec\s*\(/
    condition:
        $c and $net
}

rule axross_decompress_exec_chain
{
    meta:
        description = "decoded or decompressed data executed (exec/eval/compile/marshal)"
        severity = "high"
        path_include = "*.py,*.pyw,*.pth,*.pyx"
    strings:
        $a = /(exec|eval)\s*\(\s*(zlib|lzma|bz2|gzip)\s*\.\s*decompress\s*\(/
        $b = /(exec|eval)\s*\(\s*marshal\s*\.\s*loads\s*\(/
        $c = /(exec|eval)\s*\(\s*(bytes|bytearray)\s*\.\s*fromhex\s*\(/
        $d = /(exec|eval)\s*\(\s*codecs\s*\.\s*decode\s*\([^)]*rot.?13/
        $e = /(exec|eval)\s*\(\s*['"][^'"]{0,40}['"]\s*\.\s*join\s*\(\s*(map\s*\(\s*chr|\[?\s*chr\s*\()/
        $f = /__import__\s*\(\s*['"](zlib|base64|marshal)['"]\s*\)\s*\.\s*(decompress|b64decode|loads)\s*\([^)]*\)\s*\)\s*\)/
    condition:
        any of them
}

rule axross_lambda_obfuscation
{
    meta:
        description = "code hidden in lambda chains or reversed/encoded strings with exec"
        severity = "medium"
        path_include = "*.py,*.pyw,*.pth"
    strings:
        $a = /_\s*=\s*lambda\s+__?\s*:\s*__import__/
        $b = /exec\s*\(\s*\w+\s*\[\s*::\s*-1\s*\]\s*\)/
        $c = /exec\s*\(\s*\(\s*_\s*\)\s*\(/
        $d = /getattr\s*\(\s*__builtins__\s*,\s*['"](ex|ev)['"]\s*\+\s*['"](ec|al)['"]\s*\)/
    condition:
        any of them
}

rule axross_key_store_copy
{
    meta:
        description = "GPG or SSH key folders copied, archived or sent"
        severity = "high"
        path_include = "*.py,*.pyw,*.pth,setup.py"
    strings:
        $gpg = /\.gnupg|private-keys-v1\.d|secring\.gpg/
        $ssh = /\.ssh['"\/]|id_rsa|id_ed25519|id_ecdsa/
        $copy = /shutil\s*\.\s*(copy|copy2|copytree|make_archive)\s*\(|zipfile\s*\.\s*ZipFile\s*\(|tarfile\s*\.\s*open\s*\(|\.read\s*\(\s*\)/
        $out = /requests\s*\.\s*(post|put)|urlopen|socket\s*\.\s*socket|smtplib|ftplib|webhooks/
    condition:
        ($gpg or $ssh) and $copy and $out
}

rule axross_browser_data_theft
{
    meta:
        description = "browser profiles (passwords, cookies) read or copied"
        severity = "high"
        path_include = "*.py,*.pyw,*.pth,setup.py"
    strings:
        $b1 = /(google-chrome|chromium|BraveSoftware|Microsoft[\/\\]+Edge|opera|vivaldi|Yandex)/ nocase
        $b2 = /\.mozilla[\/\\]+firefox|Firefox[\/\\]+Profiles/ nocase
        $f1 = "Login Data"
        $f2 = "Cookies"
        $f3 = "logins.json"
        $f4 = /key[34]\.db/
        $f5 = "Local State"
        $act = /sqlite3\s*\.\s*connect|shutil\s*\.\s*copy|CryptUnprotectData|win32crypt|os_crypt|encrypted_key/
    condition:
        any of ($b*) and any of ($f*) and $act
}
