"""PassKeeper core: an encrypted, local password vault.

Storage format (version 2)
--------------------------
Everything lives in a single file, ``vault.pk``, which is a small JSON document:

    {
      "format": "passkeeper-vault",
      "version": 2,
      "kdf": {"name": "scrypt", "n": 131072, "r": 8, "p": 1, "salt": "<b64>"},
      "cipher": "AES-256-GCM",
      "nonce": "<b64>",
      "ciphertext": "<b64>"
    }

* A 256-bit key is derived from the master password with scrypt (memory-hard,
  so brute-forcing the master password is slow and expensive).
* The list of accounts is serialised to JSON and encrypted with AES-256-GCM.
  GCM is authenticated: a wrong master password or any tampering with the file
  makes decryption fail, so no password hash needs to be stored at all.
* The header (format, version, kdf, cipher) is bound to the ciphertext as
  associated data, so it cannot be altered without detection.
* Writes are atomic (temp file + ``os.replace``), so a crash mid-save never
  leaves a half-written vault behind.

The old 1.x files (``accounts.json``, ``salt.txt``, ``safe/main_password.txt``
and ``bkp.txt``) are not encrypted in any meaningful way. ``migrate_legacy``
converts them into a vault and then deletes them.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sys
import tempfile
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT_NAME = "passkeeper-vault"
FORMAT_VERSION = 2
VAULT_FILENAME = "vault.pk"
BACKUP_DIRNAME = "backups"
MAX_BACKUPS = 10

# scrypt cost parameters. n=2**17, r=8 uses 128 MiB of RAM per derivation,
# which is OWASP's recommended minimum for scrypt.
DEFAULT_KDF = {"name": "scrypt", "n": 2 ** 17, "r": 8, "p": 1}
KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12
MIN_MASTER_PASSWORD_LENGTH = 8


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

def app_dir() -> Path:
    """Folder the app lives in (works for both the .py script and a
    PyInstaller --onefile .exe, whose ``__file__`` points to a temp folder)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def data_dir() -> Path:
    """Folder where the vault and backups are stored.

    Defaults to the app folder, so the app stays portable (e.g. on a USB
    stick). Can be overridden with the ``PASSKEEPER_HOME`` environment variable.
    """
    override = os.environ.get("PASSKEEPER_HOME")
    return Path(override).expanduser().resolve() if override else app_dir()


def default_vault_path() -> Path:
    return data_dir() / VAULT_FILENAME


def default_backup_dir() -> Path:
    return data_dir() / BACKUP_DIRNAME


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class VaultError(Exception):
    """Base class for vault problems that should be shown to the user."""


class WrongPasswordError(VaultError):
    """The master password is wrong, or the vault file was tampered with."""


class CorruptVaultError(VaultError):
    """The file is not a readable PassKeeper vault."""


# --------------------------------------------------------------------------- #
# Low level helpers
# --------------------------------------------------------------------------- #

def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def derive_key(password: str, kdf: dict) -> bytes:
    if kdf.get("name") != "scrypt":
        raise CorruptVaultError(f"Unsupported key derivation: {kdf.get('name')!r}")
    n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=_b64d(kdf["salt"]),
        n=n, r=r, p=p,
        maxmem=128 * r * (n + p + 2) + 1024 * 1024,
        dklen=KEY_LENGTH,
    )


def _associated_data(header: dict) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` so that the file is either fully old or
    fully new, never half-written."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


# --------------------------------------------------------------------------- #
# Entries and vault
# --------------------------------------------------------------------------- #

@dataclass
class Entry:
    name: str
    username: str
    password: str
    notes: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created: str = field(default_factory=_now)
    modified: str = field(default_factory=_now)

    @classmethod
    def from_dict(cls, data: dict) -> "Entry":
        known = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        return cls(**known)


class Vault:
    """An unlocked vault. Holds the derived key in memory (never the master
    password itself) so changes can be saved without asking again."""

    def __init__(self, path: Path, key: bytes, kdf: dict, entries: list[Entry]):
        self.path = Path(path)
        self._key = key
        self._kdf = kdf
        self.entries = entries

    # ----- creating / opening -------------------------------------------- #

    @classmethod
    def create(cls, path: Path, master_password: str, kdf_params: dict | None = None,
               overwrite: bool = False) -> "Vault":
        path = Path(path)
        if path.exists() and not overwrite:
            raise VaultError(f"A vault already exists at {path}")
        if len(master_password) < MIN_MASTER_PASSWORD_LENGTH:
            raise VaultError(
                f"The master password must have at least {MIN_MASTER_PASSWORD_LENGTH} characters.")
        kdf = dict(kdf_params or DEFAULT_KDF)
        kdf["salt"] = _b64e(secrets.token_bytes(SALT_LENGTH))
        vault = cls(path, derive_key(master_password, kdf), kdf, [])
        vault.save()
        return vault

    @staticmethod
    def _read_document(path: Path) -> dict:
        try:
            doc = json.loads(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise
        except (OSError, ValueError) as exc:
            raise CorruptVaultError(f"{path} is not a readable vault file.") from exc
        if not isinstance(doc, dict) or doc.get("format") != FORMAT_NAME:
            raise CorruptVaultError(f"{path} is not a PassKeeper vault file.")
        if doc.get("version") != FORMAT_VERSION:
            raise CorruptVaultError(f"Unsupported vault version: {doc.get('version')!r}")
        return doc

    @classmethod
    def _decrypt_document(cls, doc: dict, password: str) -> tuple[bytes, list[Entry]]:
        try:
            kdf = doc["kdf"]
            key = derive_key(password, kdf)
            header = {k: doc[k] for k in ("format", "version", "kdf", "cipher")}
            plaintext = AESGCM(key).decrypt(
                _b64d(doc["nonce"]), _b64d(doc["ciphertext"]), _associated_data(header))
        except InvalidTag as exc:
            raise WrongPasswordError("Wrong master password.") from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise CorruptVaultError("The vault file is damaged.") from exc
        try:
            payload = json.loads(plaintext.decode("utf-8"))
            entries = [Entry.from_dict(e) for e in payload["entries"]]
        except (KeyError, TypeError, ValueError) as exc:
            raise CorruptVaultError("The vault contents are damaged.") from exc
        return key, entries

    @classmethod
    def open(cls, path: Path, master_password: str) -> "Vault":
        doc = cls._read_document(path)
        key, entries = cls._decrypt_document(doc, master_password)
        return cls(path, key, doc["kdf"], entries)

    # ----- saving --------------------------------------------------------- #

    def _serialise(self) -> bytes:
        header = {"format": FORMAT_NAME, "version": FORMAT_VERSION,
                  "kdf": self._kdf, "cipher": "AES-256-GCM"}
        payload = json.dumps({"entries": [asdict(e) for e in self.entries]}).encode("utf-8")
        nonce = secrets.token_bytes(NONCE_LENGTH)
        ciphertext = AESGCM(self._key).encrypt(nonce, payload, _associated_data(header))
        doc = dict(header, nonce=_b64e(nonce), ciphertext=_b64e(ciphertext))
        return json.dumps(doc, indent=2).encode("utf-8")

    def save(self) -> None:
        atomic_write_bytes(self.path, self._serialise())

    # ----- entries -------------------------------------------------------- #

    def get(self, entry_id: str) -> Entry:
        for entry in self.entries:
            if entry.id == entry_id:
                return entry
        raise KeyError(entry_id)

    def add_entry(self, name: str, username: str, password: str, notes: str = "") -> Entry:
        if not name.strip():
            raise VaultError("The account name cannot be empty.")
        entry = Entry(name=name.strip(), username=username, password=password, notes=notes)
        self.entries.append(entry)
        self.save()
        return entry

    def update_entry(self, entry_id: str, **changes) -> Entry:
        entry = self.get(entry_id)
        for key, value in changes.items():
            if key not in ("name", "username", "password", "notes"):
                raise ValueError(f"Cannot change field {key!r}")
            setattr(entry, key, value)
        entry.modified = _now()
        self.save()
        return entry

    def remove_entry(self, entry_id: str) -> None:
        entry = self.get(entry_id)
        self.entries.remove(entry)
        self.save()

    def sorted_entries(self) -> list[Entry]:
        return sorted(self.entries, key=lambda e: (e.name.casefold(), e.username.casefold()))

    # ----- master password ------------------------------------------------ #

    def change_master_password(self, new_password: str) -> None:
        if len(new_password) < MIN_MASTER_PASSWORD_LENGTH:
            raise VaultError(
                f"The master password must have at least {MIN_MASTER_PASSWORD_LENGTH} characters.")
        kdf = {k: v for k, v in self._kdf.items() if k != "salt"}
        kdf["salt"] = _b64e(secrets.token_bytes(SALT_LENGTH))
        self._kdf, self._key = kdf, derive_key(new_password, kdf)
        self.save()

    # ----- backups -------------------------------------------------------- #

    def create_backup(self, backup_dir: Path | None = None, keep: int = MAX_BACKUPS) -> Path:
        """Copy the (already encrypted) vault to a timestamped file and keep
        only the ``keep`` most recent automatic backups."""
        backup_dir = Path(backup_dir) if backup_dir else self.path.parent / BACKUP_DIRNAME
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        target = backup_dir / f"vault-{stamp}.pk"
        atomic_write_bytes(target, self._serialise())
        backups = sorted(backup_dir.glob("vault-*.pk"))
        for old in backups[:-keep] if keep else []:
            old.unlink()
        return target

    def restore_backup(self, backup_path: Path, password: str) -> int:
        """Replace the current entries with the ones in ``backup_path``.

        The backup must open with ``password`` (normally the current master
        password). A safety backup of the current state is made first.
        Returns the number of restored entries."""
        doc = self._read_document(backup_path)
        _, entries = self._decrypt_document(doc, password)
        self.create_backup()
        self.entries = entries
        self.save()
        return len(entries)


def list_backups(backup_dir: Path | None = None) -> list[Path]:
    backup_dir = Path(backup_dir) if backup_dir else default_backup_dir()
    return sorted(backup_dir.glob("vault-*.pk"), reverse=True)


# --------------------------------------------------------------------------- #
# Migration from PassKeeper 1.x
# --------------------------------------------------------------------------- #

LEGACY_ACCOUNTS = "accounts.json"
LEGACY_SALTS = "salt.txt"
LEGACY_MASTER = os.path.join("safe", "main_password.txt")
LEGACY_BACKUP = "bkp.txt"


def legacy_files_present(directory: Path | None = None) -> bool:
    directory = Path(directory) if directory else data_dir()
    return (directory / LEGACY_MASTER).exists() and (directory / LEGACY_SALTS).exists()


def _legacy_decrypt(encrypted: str) -> str:
    from math import tan
    return "".join(chr(round(tan(float(p)))) for p in encrypted.split("x")[:-1])


def read_legacy_entries(directory: Path, master_password: str) -> list[Entry]:
    """Verify the 1.x master password and decode the 1.x accounts."""
    directory = Path(directory)
    salts = (directory / LEGACY_SALTS).read_text().split("\n")
    stored_hash = (directory / LEGACY_MASTER).read_text()
    digest = str(hashlib.sha512((master_password + salts[0]).encode()).digest())
    if not secrets.compare_digest(digest, stored_hash):
        raise WrongPasswordError("Wrong master password.")

    accounts_file = directory / LEGACY_ACCOUNTS
    if not accounts_file.exists():
        return []
    accounts = json.loads(accounts_file.read_text())

    entries = []
    for idx in sorted(accounts, key=int):
        account = accounts[idx]
        salt = salts[int(idx)] if int(idx) < len(salts) else ""
        decoded = _legacy_decrypt(account["pwd"])
        if salt and decoded.endswith(salt):
            password = decoded[:-len(salt)]
        else:  # same rule the 1.x app used to display passwords
            password = decoded.split(salt[:-2])[0] if salt[:-2] else decoded
        entries.append(Entry(name=account["name"], username=account["usr"], password=password))
    return entries


def migrate_legacy(directory: Path | None, master_password: str,
                   vault_path: Path | None = None, kdf_params: dict | None = None) -> Vault:
    """Convert 1.x files into an encrypted vault, then delete the old files.

    The old files are only deleted after the new vault has been re-opened and
    checked to contain exactly the migrated entries."""
    directory = Path(directory) if directory else data_dir()
    vault_path = Path(vault_path) if vault_path else directory / VAULT_FILENAME
    entries = read_legacy_entries(directory, master_password)

    if len(master_password) < MIN_MASTER_PASSWORD_LENGTH:
        # Old master passwords had no length rule; don't lock users out.
        kdf = dict(kdf_params or DEFAULT_KDF)
        kdf["salt"] = _b64e(secrets.token_bytes(SALT_LENGTH))
        vault = Vault(vault_path, derive_key(master_password, kdf), kdf, [])
    else:
        vault = Vault.create(vault_path, master_password, kdf_params, overwrite=True)
    vault.entries = entries
    vault.save()

    check = Vault.open(vault_path, master_password)
    if [(e.name, e.username, e.password) for e in check.entries] != \
       [(e.name, e.username, e.password) for e in entries]:
        raise VaultError("Migration check failed; the old files were left untouched.")

    for name in (LEGACY_ACCOUNTS, LEGACY_SALTS, LEGACY_MASTER, LEGACY_BACKUP):
        try:
            (directory / name).unlink()
        except FileNotFoundError:
            pass
    safe_dir = directory / "safe"
    if safe_dir.is_dir() and not any(safe_dir.iterdir()):
        safe_dir.rmdir()
    return vault


__all__ = [
    "Entry", "Vault", "VaultError", "WrongPasswordError", "CorruptVaultError",
    "default_vault_path", "default_backup_dir", "data_dir", "app_dir",
    "list_backups", "legacy_files_present", "migrate_legacy",
    "MIN_MASTER_PASSWORD_LENGTH",
]
