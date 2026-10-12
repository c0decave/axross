"""Credential storage using OS keyring.

Ensures keyring never falls back to an interactive CLI prompt by disabling
backends that require terminal input (for example chainer -> getpass).

Backend identification uses ``__module__.__name__`` (not just the class
name) because some no-op backends, notably ``keyring.backends.fail.Keyring``
and ``keyring.backends.null.Keyring``, all have the bare class name
``Keyring``. Only the module path distinguishes them from real desktop
backends.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

SERVICE_NAME = "axross"

_keyring_checked = False
_keyring_usable: bool = False
_keyring_backend_id: str = "unknown"

_UNUSABLE_MARKERS = ("chainer", "null", "fail", "plaintextkey", "nokeyring")


def _backend_identifier(backend) -> str:
    return f"{type(backend).__module__}.{type(backend).__name__}".lower()


def _is_unusable(backend) -> bool:
    return any(marker in _backend_identifier(backend) for marker in _UNUSABLE_MARKERS)


def _try_set_real_backend() -> bool:
    try:
        import keyring
        from keyring.backends import SecretService

        if SecretService.Keyring.priority >= 0:
            keyring.set_keyring(SecretService.Keyring())
            log.debug("Keyring: using SecretService backend")
            return True
    except Exception as exc:
        log.debug("SecretService backend not usable: %s", exc)
    try:
        import keyring
        from keyring.backends import kwallet

        if kwallet.DBusKeyring.priority >= 0:
            keyring.set_keyring(kwallet.DBusKeyring())
            log.debug("Keyring: using KWallet backend")
            return True
    except Exception as exc:
        log.debug("KWallet backend not usable: %s", exc)
    return False


def _ensure_non_interactive_keyring() -> None:
    global _keyring_checked, _keyring_usable, _keyring_backend_id
    if _keyring_checked:
        return
    _keyring_checked = True

    try:
        import keyring

        keyring_logger = logging.getLogger("keyring")
        prev_level = keyring_logger.level
        keyring_logger.setLevel(logging.CRITICAL)
        try:
            backend = keyring.get_keyring()
        finally:
            keyring_logger.setLevel(prev_level)

        ident = _backend_identifier(backend)
        if _is_unusable(backend):
            if _try_set_real_backend():
                backend = keyring.get_keyring()
                ident = _backend_identifier(backend)
                _keyring_usable = not _is_unusable(backend)
            else:
                _keyring_usable = False
                log.warning(
                    "Keyring backend %s cannot persist secrets; no SecretService "
                    "or KWallet daemon is reachable. Passwords will not be saved "
                    "between sessions.",
                    ident,
                )
        else:
            _keyring_usable = True
            log.debug("Keyring: using %s backend", ident)
        _keyring_backend_id = ident
    except ImportError:
        _keyring_usable = False
        _keyring_backend_id = "missing-keyring-package"
        log.warning("keyring package not installed; passwords will not be persisted")
    except Exception as exc:
        _keyring_usable = False
        _keyring_backend_id = f"error:{exc.__class__.__name__}"
        log.warning("Could not configure keyring backend: %s", exc)


def is_keyring_available() -> bool:
    _ensure_non_interactive_keyring()
    return _keyring_usable


def recheck_keyring() -> bool:
    global _keyring_checked
    _keyring_checked = False
    _ensure_non_interactive_keyring()
    if _keyring_usable:
        log.info("Keyring re-detected as usable: backend=%s", _keyring_backend_id)
    else:
        log.info("Keyring re-detect: still not usable (backend=%s)", _keyring_backend_id)
    return _keyring_usable


def keyring_status_message() -> str:
    _ensure_non_interactive_keyring()
    if _keyring_usable:
        return ""
    return (
        f"No usable system keyring (active backend: {_keyring_backend_id}). "
        "Passwords will not be persisted until a Secret-Service or KWallet "
        "provider is reachable. Install or unlock gnome-keyring, KWallet, "
        "or KeePassXC Secret Service integration, then re-check the keyring."
    )


def _entry_name(profile_name: str, suffix: str = "") -> str:
    return profile_name if not suffix else f"{profile_name}:{suffix}"


def store_password(profile_name: str, password: str) -> bool:
    _ensure_non_interactive_keyring()
    if not _keyring_usable:
        recheck_keyring()
    if not _keyring_usable:
        log.warning(
            "Refusing to save password for profile %r: %s",
            profile_name,
            keyring_status_message(),
        )
        return False
    try:
        import keyring

        keyring.set_password(SERVICE_NAME, _entry_name(profile_name), password)
        log.info(
            "Stored password for profile %r in keyring (%s)", profile_name, _keyring_backend_id
        )
        return True
    except Exception as exc:
        log.warning("Failed to store password for profile %r: %s", profile_name, exc)
        return False


def get_password(profile_name: str) -> str | None:
    _ensure_non_interactive_keyring()
    if not _keyring_usable:
        return None
    try:
        import keyring

        return keyring.get_password(SERVICE_NAME, _entry_name(profile_name))
    except Exception as exc:
        log.warning("Failed to retrieve password for profile %r: %s", profile_name, exc)
        return None


def delete_password(profile_name: str) -> bool:
    _ensure_non_interactive_keyring()
    if not _keyring_usable:
        return False
    try:
        import keyring

        keyring.delete_password(SERVICE_NAME, _entry_name(profile_name))
        log.info("Deleted password for profile %r from keyring", profile_name)
        return True
    except Exception as exc:
        try:
            import keyring.errors

            if isinstance(exc, keyring.errors.PasswordDeleteError):
                log.debug("No stored password to delete for profile %r", profile_name)
                return False
        except Exception:
            pass
        log.warning("Failed to delete password for profile %r: %s", profile_name, exc)
        return False


def store_proxy_password(profile_name: str, password: str) -> bool:
    return store_password(f"{profile_name}:proxy", password)


def get_proxy_password(profile_name: str) -> str | None:
    return get_password(f"{profile_name}:proxy")


def delete_proxy_password(profile_name: str) -> bool:
    return delete_password(f"{profile_name}:proxy")


def store_secret(profile_name: str, secret_name: str, value: str) -> bool:
    return store_password(f"{profile_name}:secret:{secret_name}", value)


def get_secret(profile_name: str, secret_name: str) -> str | None:
    return get_password(f"{profile_name}:secret:{secret_name}")


def delete_secret(profile_name: str, secret_name: str) -> bool:
    return delete_password(f"{profile_name}:secret:{secret_name}")
