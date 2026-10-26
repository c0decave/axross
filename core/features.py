"""What axross can do on this machine, what is missing and how to get it.

The Help > Features… window (ui/features_dialog.py) and every place that
meets a missing feature (the connection dialog, the Analysis dock) read
this module:

* **Connections** - every registered backend (core.backend_registry), with
  its pip extra or the system command it needs;
* **Files and analysis** - the optional extras that are no backend
  (archives, sift, PDF metadata, ...);
* **External tools** - programs axross uses when they are on PATH
  (ripgrep, fd, rsync, ffmpeg, the forensic and VirtualBox extensions'
  qemu-img, Sleuth Kit, TestDisk and VBoxManage, ...), with the package
  command of this system's package manager to copy;
* **Voice** - the voice packages (pip extra ``voice``) and every voice and
  speech recognition model (core.voice_models), downloaded on demand with
  pinned SHA-256 sums - in a frozen build too.

A pip feature is installed with this Python's pip into axross' own
environment (:func:`pip_command`), never in a frozen build: there the
answer is the axross-full download of the same release.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import shutil
import sys
from dataclasses import dataclass

#: The pip extras of pyproject.toml without "all" (a test holds them equal).
EXTRAS: dict[str, tuple[str, ...]] = {
    "smb": ("smbprotocol>=1.13",),
    "webdav": ("requests>=2.33.0", "defusedxml>=0.7"),
    "s3": ("boto3>=1.28",),
    "azure": ("azure-storage-blob>=12.19", "azure-storage-file-share>=12.15"),
    "onedrive": ("msal>=1.26", "requests>=2.33.0"),
    "gdrive": ("google-api-python-client>=2.100", "google-auth-oauthlib>=1.1", "google-auth-httplib2>=0.2"),
    "dropbox": ("dropbox>=12.0",),
    "fuse": ("fusepy>=3.0",),
    "winrm": ("pywinrm>=0.4",),
    "wmi": ("impacket>=0.11",),
    "exchange": ("exchangelib>=5.0",),
    "adb": ("adb-shell>=0.4",),
    "archive": ("py7zr>=1.1.3", "rarfile>=4.0", "backports.zstd>=1.0; python_version < '3.14'"),
    "tftp": ("tftpy>=0.8",),
    "postgres": ("psycopg[binary]>=3.1",),
    "redis": ("redis>=5.0",),
    "mongo": ("pymongo>=4.18.2",),
    "git": ("dulwich>=1.2.9", "urllib3>=2.8.0"),
    "dns": ("dnspython>=2.6.1",),
    "magic": ("puremagic>=1.20",),
    "encoding": ("chardet>=5.2",),
    "snmp": ("pysnmp>=6.2",),
    "ldap": ("ldap3>=2.9",),
    "mac": ("manuf>=1.1",),
    "whois": ("ipwhois>=1.3",),
    "ntp": ("ntplib>=0.4",),
    "metadata": ("pypdf>=6.21.2",),
    "sift": ("sift-summarizer>=0.1.86",),
    "media": ("numpy>=2.0",),
    "voice": ("piper-tts>=1.8.0", "onnxruntime>=1.31.0", "faster-whisper>=1.2.1",
              "ctranslate2>=4.8.4"),
}

#: Extras that are no backend: (extra, name, import probe, what it gives).
_EXTRA_FEATURES = (
    ("sift", "File analysis (sift)", "sift", "the Analysis dock explains files"),
    ("archive", "7z and RAR archives", "py7zr", "open, list and extract .7z and .rar"),
    ("metadata", "PDF metadata removal", "pypdf", "Remove Metadata on PDF files"),
    ("magic", "File type by content", "puremagic", "type detection from the bytes"),
    ("encoding", "Text encoding detection", "chardet", "axross.text_encoding"),
    ("wmi", "impacket (SMB share list, network search, WMI)", "impacket",
     "Find on Network Hosts, SmbSession.shares_list, the WMI backend"),
    ("dns", "DNS lookups", "dns", "axross.dns_records"),
    ("snmp", "SNMP", "pysnmp", "axross.snmp_get / snmp_walk"),
    ("mac", "MAC vendor lookup", "manuf", "axross.mac_lookup"),
    ("whois", "WHOIS / ASN lookup", "ipwhois", "axross.whois"),
    ("ntp", "NTP time skew", "ntplib", "axross.time_skew"),
    ("fuse", "FUSE mount", "fuse", "mount a connection as a local folder"),
    ("media", "Equalizer and spectrum (numpy)", "numpy", "the Media Player's equalizer and spectrum"),
)


@dataclass(frozen=True)
class Tool:
    key: str
    name: str
    commands: tuple[str, ...]
    use: str
    #: Package name per family: arch, debian, fedora, suse, alpine, macos, windows.
    packages: dict
    #: Where the (single) command lives when its installer does not put it on
    #: PATH - VirtualBox on Windows and macOS.
    paths: tuple[str, ...] = ()


#: Where VirtualBox puts VBoxManage outside PATH - the places the VirtualBox
#: extension looks too (resources/extensions/virtualbox.py _KNOWN_PATHS; a
#: test holds them equal).
VBOXMANAGE_PATHS = (
    r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
    "/Applications/VirtualBox.app/Contents/MacOS/VBoxManage",
    "/usr/lib/virtualbox/VBoxManage",
)


TOOLS: tuple[Tool, ...] = (
    Tool("rg", "ripgrep", ("rg",), "fast text search in Find Files",
         {"arch": "ripgrep", "debian": "ripgrep", "fedora": "ripgrep", "suse": "ripgrep",
          "alpine": "ripgrep", "macos": "ripgrep", "windows": "BurntSushi.ripgrep.MSVC"}),
    Tool("fd", "fd", ("fd",), "fast name search in Find Files",
         {"arch": "fd", "debian": "fd-find", "fedora": "fd-find", "suse": "fd", "alpine": "fd",
          "macos": "fd", "windows": "sharkdp.fd"}),
    Tool("rsync", "rsync", ("rsync",), "the rsync backend and fast copies",
         {"arch": "rsync", "debian": "rsync", "fedora": "rsync", "suse": "rsync", "alpine": "rsync",
          "macos": "rsync"}),
    Tool("ffmpeg", "FFmpeg", ("ffmpeg", "ffprobe"), "video thumbnails and media details",
         {"arch": "ffmpeg", "debian": "ffmpeg", "fedora": "ffmpeg-free", "suse": "ffmpeg",
          "alpine": "ffmpeg", "macos": "ffmpeg", "windows": "Gyan.FFmpeg"}),
    Tool("svn", "Subversion", ("svn",), "the Subversion backend",
         {"arch": "subversion", "debian": "subversion", "fedora": "subversion", "suse": "subversion",
          "alpine": "subversion", "macos": "subversion"}),
    Tool("rsh", "rsh client", ("rsh",), "the rsh backend",
         {"arch": "inetutils", "debian": "rsh-client", "fedora": "rsh"}),
    Tool("nfs", "NFS client", ("mount.nfs",), "the NFS backend",
         {"arch": "nfs-utils", "debian": "nfs-common", "fedora": "nfs-utils", "suse": "nfs-client",
          "alpine": "nfs-utils"}),
    Tool("iscsi", "open-iscsi", ("iscsiadm",), "the iSCSI backend",
         {"arch": "open-iscsi", "debian": "open-iscsi", "fedora": "iscsi-initiator-utils",
          "suse": "open-iscsi"}),
    Tool("mtp", "MTP filesystem", ("jmtpfs",), "the MTP backend (or simple-mtpfs, go-mtpfs)",
         {"arch": "jmtpfs", "debian": "jmtpfs", "fedora": "jmtpfs"}),
    # The Forensic Tools extension (resources/extensions/forensic_tools.py).
    Tool("qemu-img", "qemu-img", ("qemu-img",),
         "Forensic Tools: Image Info and Convert to Raw Image (qcow2, VDI, VMDK, VHD)",
         {"arch": "qemu-img", "debian": "qemu-utils", "fedora": "qemu-img", "suse": "qemu-tools",
          "alpine": "qemu-img", "macos": "qemu"}),
    Tool("sleuthkit", "The Sleuth Kit", ("fls", "icat"),
         "Forensic Tools: Browse File System and Extract, deleted files included",
         {"arch": "sleuthkit", "debian": "sleuthkit", "fedora": "sleuthkit", "suse": "sleuthkit",
          "macos": "sleuthkit"}),
    Tool("testdisk", "TestDisk / PhotoRec", ("testdisk", "photorec"),
         "Forensic Tools: Recover Partitions and Carve Files",
         {"arch": "testdisk", "debian": "testdisk", "fedora": "testdisk", "suse": "testdisk",
          "alpine": "testdisk", "macos": "testdisk"}),
    # The VirtualBox extension (resources/extensions/virtualbox.py).
    Tool("virtualbox", "VirtualBox (VBoxManage)", ("VBoxManage",),
         "VirtualBox extension: register a .vbox, attach a disk image to a VM",
         {"arch": "virtualbox", "debian": "virtualbox", "fedora": "VirtualBox",
          "suse": "virtualbox", "macos": "--cask virtualbox", "windows": "Oracle.VirtualBox"},
         paths=VBOXMANAGE_PATHS),
)
#: Backends that need a system command: the tool that brings it.
_BACKEND_TOOL = {"svn": "svn", "rsh": "rsh", "nfs": "nfs", "iscsi": "iscsi", "mtp": "mtp", "rsync": "rsync"}

_INSTALLERS = {
    "arch": "sudo pacman -S --needed {pkg}",
    "debian": "sudo apt install {pkg}",
    "fedora": "sudo dnf install {pkg}",
    "suse": "sudo zypper install {pkg}",
    "alpine": "sudo apk add {pkg}",
    "macos": "brew install {pkg}",
    "windows": "winget install {pkg}",
}


@dataclass(frozen=True)
class Feature:
    key: str  # "backend:smb", "extra:sift", "tool:rg"
    name: str
    group: str  # "Connections", "Files and analysis", "External tools"
    available: bool
    pip_extra: str | None = None
    requirements: tuple[str, ...] = ()
    commands: tuple[str, ...] = ()
    tool: Tool | None = None
    note: str = ""
    #: A model of core.voice_models that the Features window downloads.
    download: str = ""


def _importable(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def collect() -> list[Feature]:
    """Every feature with its state, grouped and in display order."""
    from core import backend_registry as BR

    tools = {tool.key: tool for tool in TOOLS}
    out: list[Feature] = []
    for info in BR.all_backends():
        extra = info.required_extra if info.required_extra in EXTRAS else None
        tool = tools.get(_BACKEND_TOOL.get(info.protocol_id, ""))
        out.append(Feature(
            key=f"backend:{info.protocol_id}", name=info.display_name, group="Connections",
            available=bool(info.available), pip_extra=extra,
            requirements=EXTRAS.get(extra, ()) if extra else (),
            commands=tool.commands if tool else (), tool=tool,
            note=info.install_hint or "",
        ))
    for extra, name, probe, use in _EXTRA_FEATURES:
        out.append(Feature(
            key=f"extra:{extra}", name=name, group="Files and analysis",
            available=_importable(probe), pip_extra=extra, requirements=EXTRAS[extra], note=use,
        ))
    for tool in TOOLS:
        out.append(Feature(
            key=f"tool:{tool.key}", name=tool.name, group="External tools",
            available=tool_available(tool),
            commands=tool.commands, tool=tool, note=tool.use,
        ))
    out.extend(voice_features())
    return out


def tool_available(tool: Tool) -> bool:
    """Every command of *tool* on PATH - or, for a one-command tool, at one
    of the places its installer puts it (Tool.paths)."""
    if all(shutil.which(cmd) for cmd in tool.commands):
        return True
    return len(tool.commands) == 1 and any(os.path.isfile(p) for p in tool.paths)


def voice_features() -> list[Feature]:
    """The voice packages and one entry per voice and recognition model."""
    from core import voice_models as VM

    out = [Feature(
        key="extra:voice", name="Voice packages (Piper, faster-whisper)", group="Voice",
        available=_importable("piper") and _importable("faster_whisper"), pip_extra="voice",
        requirements=EXTRAS["voice"],
        note="talk with the Agent dock: speech output and local speech recognition "
             "(piper-tts is GPL-3.0-or-later)",
    )]
    for model in VM.MODELS:
        out.append(Feature(
            key=f"voice:{model.id}", name=model.title, group="Voice",
            available=VM.installed(model), download=model.id,
            note=f"{model.size / 1e6:.0f} MB download, pinned SHA-256, into {VM.model_dir(model)}",
        ))
    return out


def linux_family(os_release: str) -> str:
    """The package family of an /etc/os-release text: arch, debian,
    fedora, suse, alpine, or "" when it is none of them."""
    values = {}
    for line in os_release.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip().strip('"').lower()
    ids = [values.get("ID", "")] + values.get("ID_LIKE", "").split()
    for family, names in (("arch", ("arch",)), ("debian", ("debian", "ubuntu")),
                          ("fedora", ("fedora", "rhel", "centos")),
                          ("suse", ("suse", "opensuse")), ("alpine", ("alpine",))):
        if any(i in names or i.startswith(names) for i in ids if i):
            return family
    return ""


def system_family() -> str:
    if sys.platform == "darwin":
        return "macos"
    if sys.platform == "win32":
        return "windows"
    try:
        with open("/etc/os-release", encoding="utf-8", errors="replace") as fh:
            return linux_family(fh.read())
    except OSError:
        return ""


def how_to_get(feature: Feature, *, family: str | None = None) -> str:
    """One line that says how to get *feature*: the pip command, the
    package command of *family*, or what it needs."""
    if feature.download:
        from core import voice_models as VM

        model = VM.model(feature.download)
        size = f" ({model.size / 1e6:.0f} MB)" if model is not None else ""
        return f"Download Model{size}"
    if feature.pip_extra:
        return f"pip install axross[{feature.pip_extra}]"
    tool = feature.tool
    if tool is not None:
        family = system_family() if family is None else family
        package = tool.packages.get(family)
        if package and family in _INSTALLERS:
            return _INSTALLERS[family].format(pkg=package)
        return f"the {' / '.join(tool.commands)} command ({tool.name})"
    return feature.note or "nothing to install"


def is_frozen() -> bool:
    """A PyInstaller build (slim or full), not a Python install."""
    return bool(getattr(sys, "frozen", False))


def can_pip_install() -> tuple[bool, str]:
    """Whether Install can run pip here, and why not."""
    if is_frozen():
        return False, ("This is a frozen axross build: pip cannot add to it. The axross-full "
                       "build of the same release has every optional feature.")
    if importlib.util.find_spec("pip") is None:
        return False, "This Python has no pip module (python -m pip)."
    return True, ""


def in_virtualenv() -> bool:
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix) or bool(os.environ.get("VIRTUAL_ENV"))


def pip_command(features: list[Feature]) -> list[str]:
    """``python -m pip install <requirements>`` for *features*, into the
    Python that runs axross."""
    requirements: list[str] = []
    for feature in features:
        for requirement in feature.requirements:
            if requirement not in requirements:
                requirements.append(requirement)
    return [sys.executable, "-m", "pip", "install", *requirements]


def download_url(version: str) -> str:
    return f"https://github.com/c0decave/axross/releases/tag/v{version}"


def refresh_availability() -> None:
    """After an install: Python finds the new packages, and every backend's
    availability is asked again on its next read."""
    from core import backend_registry as BR

    importlib.invalidate_caches()
    for info in BR.all_backends():
        probe = getattr(info, "_availability", None)
        if isinstance(probe, BR._ImportProbe):
            probe.reset()
