"""Read-only Windows registry helpers.

Every function in this module opens registry keys with ``KEY_READ`` access
only.  **No writes are ever performed.**
"""

from __future__ import annotations

import logging
import winreg
from typing import Any


logger = logging.getLogger(__name__)

# Friendly name → winreg constant mapping
HIVE_MAP: dict[str, int] = {
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKCR": winreg.HKEY_CLASSES_ROOT,
    "HKU": winreg.HKEY_USERS,
}


def read_registry_value(
    hive: int,
    subkey: str,
    value_name: str,
    *,
    access: int = winreg.KEY_READ,
) -> Any | None:
    """Read a single registry value, returning *None* on failure.

    Parameters:
        hive: Registry hive constant (e.g. ``winreg.HKEY_LOCAL_MACHINE``).
        subkey: Path beneath the hive.
        value_name: Name of the value to read.
        access: Access flags — always include ``KEY_READ``.

    Returns:
        The value data, or *None* if the key/value does not exist.
    """
    try:
        with winreg.OpenKey(hive, subkey, 0, access) as key:
            data, _ = winreg.QueryValueEx(key, value_name)
            return data
    except FileNotFoundError:
        return None
    except OSError:
        return None


def read_registry_values(
    hive: int,
    subkey: str,
    value_names: list[str],
    *,
    access: int = winreg.KEY_READ,
) -> dict[str, Any]:
    """Read multiple values from one registry key.

    Parameters:
        hive: Registry hive constant.
        subkey: Path beneath the hive.
        value_names: Names of the values to read.
        access: Access flags — always include ``KEY_READ``.

    Returns:
        A dict mapping each requested name to its data (or *None*).
    """
    result: dict[str, Any] = {}
    try:
        with winreg.OpenKey(hive, subkey, 0, access) as key:
            for name in value_names:
                try:
                    data, _ = winreg.QueryValueEx(key, name)
                    result[name] = data
                except FileNotFoundError:
                    result[name] = None
                except OSError:
                    result[name] = None
    except FileNotFoundError:
        for name in value_names:
            result[name] = None
    except OSError:
        for name in value_names:
            result[name] = None
    return result


def enumerate_subkeys(
    hive: int,
    subkey: str,
    *,
    access: int = winreg.KEY_READ,
) -> list[str]:
    """Return a list of subkey names under *hive\\subkey*.

    Parameters:
        hive: Registry hive constant.
        subkey: Path beneath the hive.
        access: Access flags — always include ``KEY_READ``.

    Returns:
        A (possibly empty) list of subkey name strings.
    """
    names: list[str] = []
    try:
        with winreg.OpenKey(hive, subkey, 0, access) as key:
            index = 0
            while True:
                try:
                    names.append(winreg.EnumKey(key, index))
                    index += 1
                except OSError:
                    break
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.debug("Cannot enumerate %s\\%s: %s", hive, subkey, exc)
    return names


def iter_subkey_values(
    hive: int,
    subkey: str,
    value_names: list[str],
    *,
    access: int = winreg.KEY_READ,
) -> list[tuple[str, dict[str, Any]]]:
    """Enumerate subkeys and read specified values from each.

    Parameters:
        hive: Registry hive constant.
        subkey: Path beneath the hive.
        value_names: Values to read from each child subkey.
        access: Access flags — always include ``KEY_READ``.

    Returns:
        A list of ``(subkey_name, values_dict)`` tuples.
    """
    results: list[tuple[str, dict[str, Any]]] = []
    for child in enumerate_subkeys(hive, subkey, access=access):
        child_path = f"{subkey}\\{child}"
        values = read_registry_values(hive, child_path, value_names, access=access)
        results.append((child, values))
    return results
