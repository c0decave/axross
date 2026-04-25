"""Credential storage using OS keyring.

Ensures keyring never falls back to an interactive CLI prompt by disabling
backends that require terminal input (e.g. chainer → getpass).
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)

SERVICE_NAME = "axross"

_keyring_checked = False


def _ensure_non_interactive_keyring() -> None:
    """Configure keyring to never prompt on the terminal.

    If no suitable non-interactive backend is available, keyring operations
    will fail gracefully (caught by callers).
    """
    global _keyring_checked
    if _keyring_checked:
        return
    _keyring_checked = True

    try:
        import keyring
        import keyring.backend

        # Suppress noisy warnings from keyring's own backend detection
        kr_logger = logging.getLogger("keyring")
        prev_level = kr_logger.level
        kr_logger.setLevel(logging.CRITICAL)
        try:
            backend = keyring.get_keyring()
        finally:
            kr_logger.setLevel(prev_level)

        name = type(backend).__name__.lower()
        # These backends may block on CLI input or are useless
        bad_names = ("chainer", "null", "fail", "plaintextkey", "nokeyring")
        if any(n in name for n in bad_names):
            # Try to find a real desktop backend
            try:
                from keyring.backends import SecretService
                if SecretService.Keyring.priority >= 0:
                    keyring.set_keyring(SecretService.Keyring())
                    log.debug("Keyring: using SecretService backend")
                    return
            except Exception:
                pass
            try:
                from keyring.backends import kwallet
                if kwallet.DBusKeyring.priority >= 0:
                    keyring.set_keyring(kwallet.DBusKeyring())
                    log.debug("Keyring: using KWallet backend")
                    return
            except Exception:
                pass

            # No desktop backend — use silent no-op keyring. This is a
            # WARNING because the user's credentials will not survive a
            # restart; people expect "Save password" to actually save.
            log.warning(
                "No desktop keyring daemon found (SecretService/KWallet). "
                "Passwords will not persist across restarts."
            )

            class _NoKeyring(keyring.backend.KeyringBackend):
                priority = -1
                def get_password(self, service, username):
                    return None
                def set_password(self, service, username, password):
                    pass  # silently ignore
                def delete_password(self, service, username):
                    pass  # silently ignore

            keyring.set_keyring(_NoKeyring())
        else:
            log.debug("Keyring: using %s backend", type(backend).__name__)
    except ImportError:
        log.warning("keyring package not installed, credentials will not be persisted")
    except Exception as e:
        log.warning("Could not configure keyring backend: %s", e)


def _entry_name(profile_name: str, suffix: str = "") -> str:
    return profile_name if not suffix else f"{profile_name}:{suffix}"


def store_password(profile_name: str, password: str) -> bool:
    """Store a password in the OS keyring. Returns True on success."""
    try:
        import keyring
        _ensure_non_interactive_keyring()

        keyring.set_password(SERVICE_NAME, _entry_name(profile_name), password)
        log.debug("Stored password for profile %r in keyring", profile_name)
        return True
    except ImportError:
        log.warning("keyring package not installed — cannot persist password")
        return False
    except Exception as e:
        log.warning("Failed to store password for profile %r: %s", profile_name, e)
        return False


def get_password(profile_name: str) -> str | None:
    """Retrieve a password from the OS keyring."""
    try:
        import keyring
        _ensure_non_interactive_keyring()

        return keyring.get_password(SERVICE_NAME, _entry_name(profile_name))
    except ImportError:
        log.debug("keyring package not installed — no stored password for %r", profile_name)
        return None
    except Exception as e:
        log.warning("Failed to retrieve password for profile %r: %s", profile_name, e)
        return None


def delete_password(profile_name: str) -> bool:
    """Remove a password from the OS keyring."""
    try:
        import keyring
        _ensure_non_interactive_keyring()

        keyring.delete_password(SERVICE_NAME, _entry_name(profile_name))
        log.debug("Deleted password for profile %r from keyring", profile_name)
        return True
    except ImportError:
        log.debug("keyring package not installed — nothing to delete for %r", profile_name)
        return False
    except Exception as e:
        # PasswordDeleteError when there is no stored secret is expected,
        # keep it at debug level; everything else surfaces as a warning.
        try:
            import keyring.errors
            if isinstance(e, keyring.errors.PasswordDeleteError):
                log.debug("No stored password to delete for profile %r", profile_name)
                return False
        except Exception:
            pass
        log.warning("Failed to delete password for profile %r: %s", profile_name, e)
        return False


def store_proxy_password(profile_name: str, password: str) -> bool:
    """Store proxy password in keyring."""
    return store_password(f"{profile_name}:proxy", password)


def get_proxy_password(profile_name: str) -> str | None:
    """Retrieve proxy password from keyring."""
    return get_password(f"{profile_name}:proxy")


def delete_proxy_password(profile_name: str) -> bool:
    """Remove a proxy password from the OS keyring."""
    return delete_password(f"{profile_name}:proxy")


def store_secret(profile_name: str, secret_name: str, value: str) -> bool:
    """Store an auxiliary secret for a profile in the OS keyring."""
    return store_password(f"{profile_name}:secret:{secret_name}", value)


def get_secret(profile_name: str, secret_name: str) -> str | None:
    """Retrieve an auxiliary secret for a profile from the OS keyring."""
    return get_password(f"{profile_name}:secret:{secret_name}")


def delete_secret(profile_name: str, secret_name: str) -> bool:
    """Remove an auxiliary secret for a profile from the OS keyring."""
    return delete_password(f"{profile_name}:secret:{secret_name}")
