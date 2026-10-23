"""VirtualBox: register a .vbox machine, attach a disk image to a VM.

Right-click a ``.vbox`` file: *Register in VirtualBox* (``VBoxManage
registervm``) - the machine shows up in the running VirtualBox. Right-click
a ``.vdi`` / ``.vmdk`` / ``.vhd`` / ``.vhdx``: *Attach to VirtualBox VM…* -
pick the machine (and the controller when it has several), the disk goes on
the first free port (``VBoxManage storageattach``). Local files only: the
paths are VirtualBox's own. Every command is an argument list; nothing is
parsed by a shell.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field

from core.subprocess_env import clean_child_env

EXTENSION = {
    "name": "VirtualBox",
    "version": "1.0",
    "description": "Right-click: register a .vbox machine in VirtualBox, or attach a "
    ".vdi / .vmdk / .vhd disk image to a virtual machine (VBoxManage).",
    "author": "axross",
}

DISK_SUFFIXES = (".vdi", ".vmdk", ".vhd", ".vhdx")
TIMEOUT = 60
#: Devices per port: IDE has master and slave, the others one.
DEVICES_PER_PORT = {"PIIX3": 2, "PIIX4": 2, "ICH6": 2}
_KNOWN_PATHS = (
    r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
    "/Applications/VirtualBox.app/Contents/MacOS/VBoxManage",
    "/usr/lib/virtualbox/VBoxManage",
)


class VBoxError(RuntimeError):
    pass


@dataclass
class Controller:
    name: str
    type: str
    ports: int
    max_ports: int
    used: dict[tuple[int, int], str] = field(default_factory=dict)

    def free_slot(self) -> tuple[int, int, bool] | None:
        """``(port, device, grow)``: the first free slot; *grow* when the
        controller needs one more port for it. None when it is full."""
        devices = DEVICES_PER_PORT.get(self.type, 1)
        for port in range(self.ports):
            for device in range(devices):
                if self.used.get((port, device), "none") == "none":
                    return port, device, False
        if self.ports < self.max_ports:
            return self.ports, 0, True
        return None


def vboxmanage() -> str | None:
    found = shutil.which("VBoxManage") or shutil.which("vboxmanage")
    if found:
        return found
    return next((p for p in _KNOWN_PATHS if os.path.isfile(p)), None)


def run(argv: list[str]) -> str:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT, check=False,
                              env=clean_child_env())
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VBoxError(str(exc)) from exc
    if proc.returncode != 0:
        lines = [ln for ln in (proc.stderr or proc.stdout).splitlines() if ln.strip()]
        error = next((ln.split("error:", 1)[1].strip() for ln in lines if "error:" in ln),
                     lines[-1] if lines else f"exit {proc.returncode}")
        raise VBoxError(error)
    return proc.stdout


def parse_vms(text: str) -> list[tuple[str, str]]:
    """``(name, uuid)`` from ``VBoxManage list vms``."""
    found = []
    for line in text.splitlines():
        match = re.match(r'^"(.*)" \{([0-9a-fA-F-]{36})\}\s*$', line)
        if match:
            found.append((match.group(1), match.group(2)))
    return found


def parse_machine(text: str) -> tuple[str, list[Controller]]:
    """``(state, controllers)`` from ``showvminfo --machinereadable``."""
    values = {}
    for line in text.splitlines():
        match = re.match(r'^"?([^"=]+)"?="?(.*?)"?$', line.strip())
        if match:
            values[match.group(1)] = match.group(2)
    controllers = []
    i = 0
    while f"storagecontrollername{i}" in values:
        name = values[f"storagecontrollername{i}"]
        ctl = Controller(
            name=name,
            type=values.get(f"storagecontrollertype{i}", ""),
            ports=int(values.get(f"storagecontrollerportcount{i}", "0") or 0),
            max_ports=int(values.get(f"storagecontrollermaxportcount{i}", "0") or 0),
        )
        prefix = f"{name}-"
        for key, value in values.items():
            if key.startswith(prefix) and not key.startswith(prefix + "ImageUUID"):
                tail = key[len(prefix):].split("-")
                if len(tail) == 2 and all(t.isdigit() for t in tail):
                    ctl.used[(int(tail[0]), int(tail[1]))] = value
        controllers.append(ctl)
        i += 1
    return values.get("VMState", ""), controllers


def disk_controllers(controllers: list[Controller]) -> list[Controller]:
    """Controllers a hard disk can go on (not floppy, with room)."""
    return [c for c in controllers if c.type not in ("I82078",) and c.free_slot() is not None]


def register_argv(exe: str, path: str) -> list[str]:
    return [exe, "registervm", path]


def attach_argvs(exe: str, vm: str, ctl: Controller, path: str) -> list[list[str]]:
    slot = ctl.free_slot()
    if slot is None:
        raise VBoxError(f"the controller {ctl.name} has no free port")
    port, device, grow = slot
    argvs = []
    if grow:
        argvs.append([exe, "storagectl", vm, "--name", ctl.name, "--portcount", str(port + 1)])
    argvs.append([exe, "storageattach", vm, "--storagectl", ctl.name, "--port", str(port),
                  "--device", str(device), "--type", "hdd", "--medium", path])
    return argvs


def register(path: str, exe: str | None = None) -> str:
    exe = exe or vboxmanage()
    if exe is None:
        raise VBoxError("VBoxManage was not found - is VirtualBox installed?")
    run(register_argv(exe, path))
    return path


def attach(path: str, vm: str, controller: str, exe: str | None = None) -> str:
    """Attach *path* to *vm* on *controller*; the slot used, as text."""
    exe = exe or vboxmanage()
    if exe is None:
        raise VBoxError("VBoxManage was not found - is VirtualBox installed?")
    state, controllers = parse_machine(run([exe, "showvminfo", vm, "--machinereadable"]))
    ctl = next((c for c in controllers if c.name == controller), None)
    if ctl is None:
        raise VBoxError(f"the VM has no controller {controller!r}")
    port, device, _grow = ctl.free_slot() or (None, None, None)
    for argv in attach_argvs(exe, vm, ctl, path):
        run(argv)
    return f"{controller} port {port} device {device}" + (f" (VM {state})" if state else "")


def activate(api):
    from PyQt6.QtWidgets import QInputDialog, QMessageBox

    def local_path(ctx):
        if not ctx.is_local:
            api.notify("VirtualBox needs a local file")
            return None
        return ctx.paths[0]

    def do_register(ctx):
        path = local_path(ctx)
        if path is None:
            return
        api.run_in_background(
            lambda: register(path),
            on_done=lambda p: api.notify(f"registered {os.path.basename(p)} in VirtualBox"),
            on_error=lambda exc: QMessageBox.warning(api.window, "Register in VirtualBox",
                                                     str(exc)),
        )

    def do_attach(ctx):
        path = local_path(ctx)
        if path is None:
            return
        exe = vboxmanage()
        if exe is None:
            QMessageBox.warning(api.window, "Attach to VirtualBox VM",
                                "VBoxManage was not found - is VirtualBox installed?")
            return

        def got_vms(vms):
            if not vms:
                api.notify("VirtualBox has no machines")
                return
            labels = [name for name, _uuid in vms]
            choice, ok = QInputDialog.getItem(api.window, "Attach to VirtualBox VM",
                                              f"Attach {os.path.basename(path)} to:", labels,
                                              editable=False)
            if not ok:
                return
            uuid = vms[labels.index(choice)][1]
            api.run_in_background(
                lambda: parse_machine(run([exe, "showvminfo", uuid, "--machinereadable"])),
                on_done=lambda result: got_machine(choice, uuid, *result),
                on_error=failed,
            )

        def got_machine(name, uuid, state, controllers):
            usable = disk_controllers(controllers)
            if not usable:
                QMessageBox.warning(api.window, "Attach to VirtualBox VM",
                                    f"{name} has no controller with a free port.")
                return
            ctl = usable[0]
            if len(usable) > 1:
                labels = [f"{c.name} ({c.type})" for c in usable]
                choice, ok = QInputDialog.getItem(api.window, "Attach to VirtualBox VM",
                                                  "Controller:", labels, editable=False)
                if not ok:
                    return
                ctl = usable[labels.index(choice)]
            if state == "running":
                api.notify(f"{name} is running: the port must be hot-pluggable")
            api.run_in_background(
                lambda: attach(path, uuid, ctl.name, exe),
                on_done=lambda slot: api.notify(
                    f"attached {os.path.basename(path)} to {name}: {slot}"),
                on_error=failed,
            )

        def failed(exc):
            QMessageBox.warning(api.window, "Attach to VirtualBox VM", str(exc))

        api.run_in_background(lambda: parse_vms(run([exe, "list", "vms"])), on_done=got_vms,
                              on_error=failed)

    api.add_context_action("Register in VirtualBox", do_register, applies_to="single_file",
                           extensions=(".vbox",))
    api.add_context_action("Attach to VirtualBox VM…", do_attach, applies_to="single_file",
                           extensions=DISK_SUFFIXES)
