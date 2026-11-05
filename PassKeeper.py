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
* The accounts and settings are serialised to JSON and encrypted with
  AES-256-GCM. GCM is authenticated: a wrong master password or any tampering
  with the file makes decryption fail, so no password hash is stored at all.
* The header (format, version, kdf, cipher) is bound to the ciphertext as
  associated data, so it cannot be altered without detection.
* Writes are atomic (temp file + ``os.replace``), so a crash mid-save never
  leaves a half-written vault behind.
* Only one PassKeeper can have a vault open at a time (``VaultLock``), so two
  windows can't overwrite each other's changes.

The old 1.x files (``accounts.json``, ``salt.txt``, ``safe/main_password.txt``
and ``bkp.txt``) are not encrypted in any meaningful way. ``migrate_legacy``
converts them into a vault and then overwrites and deletes them.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
import secrets
import sys
import tempfile
import uuid
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT_NAME = "passkeeper-vault"
FORMAT_VERSION = 2
VAULT_FILENAME = "vault.pk"
BACKUP_DIRNAME = "backups"

# How many backups of each kind are kept. None = keep all.
BACKUP_KEEP = {"auto": 10, "safety": 5, "manual": None}

# scrypt cost parameters. n=2**17, r=8 uses 128 MiB of RAM per derivation,
# which is OWASP's recommended minimum for scrypt.
DEFAULT_KDF = {"name": "scrypt", "n": 2 ** 17, "r": 8, "p": 1}
KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12
MIN_MASTER_PASSWORD_LENGTH = 8
PASSWORD_HISTORY_LIMIT = 10
EDITABLE_FIELDS = ("name", "username", "password", "url", "category", "notes", "totp")


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


class VaultLockedError(VaultError):
    """Another PassKeeper window already has this vault open."""


# --------------------------------------------------------------------------- #
# Low level helpers
# --------------------------------------------------------------------------- #

def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _parse_time(text: str) -> datetime:
    try:
        return datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return datetime.fromtimestamp(0, timezone.utc)


def _new_kdf(params: dict | None = None) -> dict:
    kdf = {k: v for k, v in (params or DEFAULT_KDF).items() if k != "salt"}
    kdf["salt"] = _b64e(secrets.token_bytes(SALT_LENGTH))
    return kdf


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


def secure_delete(path: Path) -> None:
    """Overwrite a file with random bytes, then delete it.

    This is best effort: SSDs, journaling file systems and cloud-synced
    folders may still keep old copies of the data elsewhere on the disk."""
    path = Path(path)
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return
    try:
        with open(path, "r+b") as f:
            remaining = size
            while remaining > 0:
                chunk = min(remaining, 64 * 1024)
                f.write(secrets.token_bytes(chunk))
                remaining -= chunk
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass  # still delete it below
    path.unlink()


# --------------------------------------------------------------------------- #
# Single-instance lock
# --------------------------------------------------------------------------- #

class VaultLock:
    """An operating-system lock on ``<vault>.lock``.

    It is released automatically if PassKeeper crashes, so it can never get
    "stuck" the way a plain marker file could."""

    def __init__(self, vault_path: Path):
        self.path = Path(str(vault_path) + ".lock")
        self._file = None

    def acquire(self) -> "VaultLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        f = open(self.path, "a+b")
        try:
            if os.name == "nt":
                import msvcrt
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            f.close()
            raise VaultLockedError(
                "PassKeeper is already open with this vault. Close the other window first.") from exc
        self._file = f
        return self

    def release(self) -> None:
        if self._file is None:
            return
        try:
            if os.name == "nt":
                import msvcrt
                self._file.seek(0)
                msvcrt.locking(self._file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        self._file.close()
        self._file = None

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *exc):
        self.release()


# --------------------------------------------------------------------------- #
# Entries and settings
# --------------------------------------------------------------------------- #

@dataclass
class Entry:
    name: str
    username: str = ""
    password: str = ""
    url: str = ""
    category: str = ""
    notes: str = ""
    totp: str = ""                       # 2FA secret (base32) or otpauth:// URI
    history: list = field(default_factory=list)   # [{"password", "changed"}], newest first
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created: str = field(default_factory=_now)
    modified: str = field(default_factory=_now)
    deleted: str | None = None           # set when the entry is in the trash

    @classmethod
    def from_dict(cls, data: dict) -> "Entry":
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in names})

    def same_content(self, other: "Entry") -> bool:
        return all(getattr(self, f) == getattr(other, f) for f in EDITABLE_FIELDS)


@dataclass
class Settings:
    autolock_minutes: int = 5        # 0 = never lock automatically
    clipboard_seconds: int = 20      # 0 = never clear the clipboard
    trash_days: int = 30             # deleted accounts are kept this long

    @classmethod
    def from_dict(cls, data: dict | None) -> "Settings":
        names = {f.name for f in fields(cls)}
        settings = cls(**{k: int(v) for k, v in (data or {}).items() if k in names})
        settings.autolock_minutes = max(0, settings.autolock_minutes)
        settings.clipboard_seconds = max(0, settings.clipboard_seconds)
        settings.trash_days = max(1, settings.trash_days)
        return settings


# --------------------------------------------------------------------------- #
# Vault
# --------------------------------------------------------------------------- #

class Vault:
    """An unlocked vault. Holds the derived key in memory (never the master
    password itself) so changes can be saved without asking again."""

    def __init__(self, path: Path, key: bytes, kdf: dict, entries: list[Entry],
                 settings: Settings | None = None):
        self.path = Path(path)
        self._key = key
        self._kdf = kdf
        self.entries = entries
        self.settings = settings or Settings()

    @property
    def backup_dir(self) -> Path:
        return self.path.parent / BACKUP_DIRNAME

    # ----- creating / opening -------------------------------------------- #

    @classmethod
    def create(cls, path: Path, master_password: str, kdf_params: dict | None = None,
               overwrite: bool = False) -> "Vault":
        path = Path(path)
        if path.exists() and not overwrite:
            raise VaultError(f"A vault already exists at {path}")
        check_master_password_rules(master_password)
        kdf = _new_kdf(kdf_params)
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

    @staticmethod
    def _decrypt_with_key(doc: dict, key: bytes) -> dict:
        try:
            header = {k: doc[k] for k in ("format", "version", "kdf", "cipher")}
            plaintext = AESGCM(key).decrypt(
                _b64d(doc["nonce"]), _b64d(doc["ciphertext"]), _associated_data(header))
        except InvalidTag as exc:
            raise WrongPasswordError("Wrong master password.") from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise CorruptVaultError("The vault file is damaged.") from exc
        try:
            payload = json.loads(plaintext.decode("utf-8"))
            if not isinstance(payload.get("entries"), list):
                raise ValueError("entries missing")
            return payload
        except (AttributeError, TypeError, ValueError) as exc:
            raise CorruptVaultError("The vault contents are damaged.") from exc

    @classmethod
    def _decrypt_document(cls, doc: dict, password: str) -> tuple[bytes, dict]:
        try:
            key = derive_key(password, doc["kdf"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CorruptVaultError("The vault file is damaged.") from exc
        return key, cls._decrypt_with_key(doc, key)

    @staticmethod
    def _entries_from_payload(payload: dict) -> list[Entry]:
        try:
            return [Entry.from_dict(e) for e in payload["entries"]]
        except (TypeError, ValueError) as exc:
            raise CorruptVaultError("The vault contents are damaged.") from exc

    @classmethod
    def open(cls, path: Path, master_password: str) -> "Vault":
        doc = cls._read_document(path)
        key, payload = cls._decrypt_document(doc, master_password)
        vault = cls(path, key, doc["kdf"], cls._entries_from_payload(payload),
                    Settings.from_dict(payload.get("settings")))
        if vault.purge_trash():
            vault.save()
        return vault

    def close(self) -> None:
        """Forget the key and the decrypted entries (used when locking)."""
        self._key = b""
        self.entries = []

    # ----- saving --------------------------------------------------------- #

    def _serialise(self, key: bytes | None = None, kdf: dict | None = None) -> bytes:
        header = {"format": FORMAT_NAME, "version": FORMAT_VERSION,
                  "kdf": kdf or self._kdf, "cipher": "AES-256-GCM"}
        payload = json.dumps({"entries": [asdict(e) for e in self.entries],
                              "settings": asdict(self.settings)}).encode("utf-8")
        return self._encrypt_payload(header, payload, key or self._key)

    @staticmethod
    def _encrypt_payload(header: dict, payload: bytes, key: bytes) -> bytes:
        nonce = secrets.token_bytes(NONCE_LENGTH)
        ciphertext = AESGCM(key).encrypt(nonce, payload, _associated_data(header))
        doc = dict(header, nonce=_b64e(nonce), ciphertext=_b64e(ciphertext))
        return json.dumps(doc, indent=2).encode("utf-8")

    def save(self) -> None:
        if not self._key:
            raise VaultError("The vault is locked.")
        atomic_write_bytes(self.path, self._serialise())

    # ----- entries -------------------------------------------------------- #

    def get(self, entry_id: str) -> Entry:
        for entry in self.entries:
            if entry.id == entry_id:
                return entry
        raise KeyError(entry_id)

    def active_entries(self) -> list[Entry]:
        return sorted((e for e in self.entries if not e.deleted),
                      key=lambda e: (e.name.casefold(), e.username.casefold()))

    def trash_entries(self) -> list[Entry]:
        return sorted((e for e in self.entries if e.deleted),
                      key=lambda e: e.deleted, reverse=True)

    def categories(self) -> list[str]:
        return sorted({e.category for e in self.entries if e.category and not e.deleted},
                      key=str.casefold)

    def search(self, query: str = "", category: str | None = None) -> list[Entry]:
        query = query.strip().casefold()
        result = []
        for e in self.active_entries():
            if category is not None and e.category != category:
                continue
            haystack = " ".join((e.name, e.username, e.url, e.category, e.notes)).casefold()
            if query and query not in haystack:
                continue
            result.append(e)
        return result

    @staticmethod
    def _clean(changes: dict) -> dict:
        for key in changes:
            if key not in EDITABLE_FIELDS:
                raise ValueError(f"Cannot change field {key!r}")
        clean = {k: ("" if v is None else str(v)) for k, v in changes.items()}
        if "name" in clean:
            clean["name"] = clean["name"].strip()
            if not clean["name"]:
                raise VaultError("The account name cannot be empty.")
        for key in ("url", "category", "totp"):
            if key in clean:
                clean[key] = clean[key].strip()
        if clean.get("totp"):
            import totp
            totp.parse(clean["totp"])  # raises ValueError with a helpful message
        return clean

    def add_entry(self, name: str, username: str = "", password: str = "", **extra) -> Entry:
        clean = self._clean(dict(name=name, username=username, password=password, **extra))
        entry = Entry(**clean)
        self.entries.append(entry)
        self.save()
        return entry

    def update_entry(self, entry_id: str, **changes) -> Entry:
        entry = self.get(entry_id)
        clean = self._clean(changes)
        new_password = clean.get("password", entry.password)
        if new_password != entry.password and entry.password:
            entry.history.insert(0, {"password": entry.password, "changed": _now()})
            del entry.history[PASSWORD_HISTORY_LIMIT:]
        for key, value in clean.items():
            setattr(entry, key, value)
        entry.modified = _now()
        self.save()
        return entry

    def remove_entry(self, entry_id: str) -> None:
        """Move an entry to the trash."""
        self.get(entry_id).deleted = _now()
        self.save()

    def restore_entry(self, entry_id: str) -> None:
        """Take an entry out of the trash."""
        self.get(entry_id).deleted = None
        self.save()

    def delete_forever(self, entry_id: str) -> None:
        self.entries.remove(self.get(entry_id))
        self.save()

    def empty_trash(self) -> int:
        before = len(self.entries)
        self.entries = [e for e in self.entries if not e.deleted]
        self.save()
        return before - len(self.entries)

    def purge_trash(self, now: datetime | None = None) -> int:
        """Drop trashed entries older than ``settings.trash_days`` (no save)."""
        limit = (now or datetime.now(timezone.utc)) - timedelta(days=self.settings.trash_days)
        before = len(self.entries)
        self.entries = [e for e in self.entries
                        if not e.deleted or _parse_time(e.deleted) > limit]
        return before - len(self.entries)

    def update_settings(self, **changes) -> Settings:
        data = asdict(self.settings)
        data.update(changes)
        self.settings = Settings.from_dict(data)
        self.save()
        return self.settings

    # ----- master password ------------------------------------------------ #

    def verify_password(self, password: str) -> bool:
        try:
            key = derive_key(password, self._kdf)
        except (ValueError, CorruptVaultError):
            return False
        return bool(self._key) and secrets.compare_digest(key, self._key)

    def change_master_password(self, current_password: str, new_password: str) -> list[Path]:
        """Change the master password and re-encrypt the backups with it.

        Returns the backups that could not be re-encrypted (they were made
        with some older master password), so the caller can offer to delete
        them."""
        if not self.verify_password(current_password):
            raise WrongPasswordError("The current master password is wrong.")
        check_master_password_rules(new_password)
        old_key, old_kdf = self._key, self._kdf
        new_kdf = _new_kdf(old_kdf)
        new_key = derive_key(new_password, new_kdf)

        # Decrypt every backup first, so a failure leaves everything unchanged.
        reencrypt, leftovers = [], []
        for backup in list_backups(self.backup_dir):
            try:
                doc = self._read_document(backup)
                if doc["kdf"] == old_kdf:
                    payload = self._decrypt_with_key(doc, old_key)
                else:
                    _, payload = self._decrypt_document(doc, current_password)
                reencrypt.append((backup, payload))
            except VaultError:
                leftovers.append(backup)

        self._kdf, self._key = new_kdf, new_key
        self.save()
        header = {"format": FORMAT_NAME, "version": FORMAT_VERSION,
                  "kdf": new_kdf, "cipher": "AES-256-GCM"}
        for backup, payload in reencrypt:
            stat = backup.stat()
            data = json.dumps(payload).encode("utf-8")
            atomic_write_bytes(backup, self._encrypt_payload(header, data, new_key))
            os.utime(backup, (stat.st_atime, stat.st_mtime))  # keep the backup's date
        return leftovers

    # ----- backups -------------------------------------------------------- #

    def create_backup(self, kind: str = "manual", backup_dir: Path | None = None) -> Path:
        """Save a timestamped, encrypted copy of the vault.

        ``kind`` is "manual" (kept forever), "auto" (made on exit, last 10
        kept) or "safety" (made before a restore, last 5 kept)."""
        if kind not in BACKUP_KEEP:
            raise ValueError(f"Unknown backup kind {kind!r}")
        backup_dir = Path(backup_dir) if backup_dir else self.backup_dir
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        target = backup_dir / f"vault-{kind}-{stamp}.pk"
        atomic_write_bytes(target, self._serialise())
        keep = BACKUP_KEEP[kind]
        if keep:
            same_kind = sorted(backup_dir.glob(f"vault-{kind}-*.pk"))
            for old in same_kind[:-keep]:
                old.unlink()
        return target

    def export_backup(self, destination: Path) -> Path:
        """Save an encrypted copy of the vault anywhere (USB stick, cloud folder...)."""
        destination = Path(destination)
        if destination.is_dir():
            destination = destination / f"passkeeper-backup-{datetime.now():%Y%m%d-%H%M%S}.pk"
        atomic_write_bytes(destination, self._serialise())
        return destination

    def restore_backup(self, backup_path: Path, password: str, mode: str = "replace") -> int:
        """Restore accounts from a backup made with ``password``.

        mode="replace": the backup replaces all current accounts.
        mode="merge": accounts missing here are added, and accounts changed
        more recently in the backup are updated; nothing is removed.

        A safety backup of the current state is made first. Returns the number
        of accounts restored (replace) or added/updated (merge)."""
        if mode not in ("replace", "merge"):
            raise ValueError(f"Unknown restore mode {mode!r}")
        doc = self._read_document(backup_path)
        _, payload = self._decrypt_document(doc, password)
        incoming = self._entries_from_payload(payload)
        self.create_backup("safety")
        if mode == "replace":
            self.entries = incoming
            self.settings = Settings.from_dict(payload.get("settings"))
            count = len([e for e in incoming if not e.deleted])
        else:
            count = 0
            by_id = {e.id: e for e in self.entries}
            for entry in incoming:
                mine = by_id.get(entry.id)
                if mine is None:
                    self.entries.append(entry)
                    count += 1
                elif _parse_time(entry.modified) > _parse_time(mine.modified) \
                        and not entry.same_content(mine):
                    self.entries[self.entries.index(mine)] = entry
                    count += 1
        self.save()
        return count

    # ----- CSV import / export ------------------------------------------- #

    def export_csv(self, path: Path) -> int:
        """Write all accounts to a CSV file (NOT encrypted). Returns the count."""
        rows = self.active_entries()
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["name", "url", "username", "password", "notes", "category", "totp"])
            for e in rows:
                writer.writerow([e.name, e.url, e.username, e.password, e.notes, e.category, e.totp])
        return len(rows)

    def import_csv(self, path: Path) -> tuple[int, int]:
        """Import accounts from a CSV export of Chrome, Edge, Firefox, Bitwarden,
        KeePassXC, PassKeeper and most other managers.

        Returns (added, skipped). Rows identical to an existing account are skipped."""
        rows = read_csv_accounts(path)
        existing = {(e.name, e.username, e.password) for e in self.entries if not e.deleted}
        added = skipped = 0
        for row in rows:
            key = (row["name"], row["username"], row["password"])
            if key in existing:
                skipped += 1
                continue
            try:
                self._clean(row)
            except ValueError:   # bad 2FA secret: keep the account, drop the secret
                row["totp"] = ""
            self.entries.append(Entry(**self._clean(row)))
            existing.add(key)
            added += 1
        if added:
            self.save()
        return added, skipped


# Column names used by common password managers, mapped to PassKeeper fields.
CSV_COLUMNS = {
    "name": ("name", "title", "account", "account name"),
    "url": ("url", "login_uri", "website", "web site", "uri", "login url"),
    "username": ("username", "login_username", "user", "login", "user name", "email"),
    "password": ("password", "login_password"),
    "notes": ("notes", "note", "extra", "comments"),
    "category": ("category", "folder", "group", "grouping"),
    "totp": ("totp", "login_totp", "otp", "otpauth"),
}


def read_csv_accounts(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise VaultError("The CSV file is empty.")
        headers = {h.strip().casefold(): h for h in reader.fieldnames if h}
        mapping = {}
        for target, candidates in CSV_COLUMNS.items():
            for candidate in candidates:
                if candidate in headers:
                    mapping[target] = headers[candidate]
                    break
        if "password" not in mapping:
            raise VaultError("Could not find a 'password' column in this CSV file.")
        rows = []
        for raw in reader:
            row = {target: (raw.get(column) or "") for target, column in mapping.items()}
            row = {k: row.get(k, "") for k in CSV_COLUMNS}
            if row.get("category", "").startswith("Root/"):     # KeePassXC groups
                row["category"] = row["category"][5:]
            elif row.get("category") == "Root":
                row["category"] = ""
            if not row["name"].strip():
                host = urlparse(row["url"]).hostname if row["url"] else ""
                row["name"] = (host or "").removeprefix("www.") if host else ""
            if not row["name"].strip():
                row["name"] = row["username"] or "Imported account"
            if not (row["password"] or row["username"]):
                continue
            rows.append(row)
        return rows


def list_backups(backup_dir: Path | None = None) -> list[Path]:
    backup_dir = Path(backup_dir) if backup_dir else default_backup_dir()
    return sorted(backup_dir.glob("vault-*.pk"), key=lambda p: p.stat().st_mtime, reverse=True)


def check_master_password_rules(password: str) -> None:
    if len(password) < MIN_MASTER_PASSWORD_LENGTH:
        raise VaultError(
            f"The master password must have at least {MIN_MASTER_PASSWORD_LENGTH} characters.")


def wipe_all_data(vault_path: Path | None = None) -> int:
    """Panic button: overwrite and delete the vault and all its backups.
    Returns the number of files removed."""
    vault_path = Path(vault_path) if vault_path else default_vault_path()
    backup_dir = vault_path.parent / BACKUP_DIRNAME
    targets = [vault_path] + (sorted(backup_dir.glob("vault-*.pk")) if backup_dir.is_dir() else [])
    removed = 0
    for target in targets:
        if target.exists():
            secure_delete(target)
            removed += 1
    if backup_dir.is_dir() and not any(backup_dir.iterdir()):
        backup_dir.rmdir()
    return removed


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
    """Convert 1.x files into an encrypted vault, then overwrite and delete
    the old files.

    The old files are only deleted after the new vault has been re-opened and
    checked to contain exactly the migrated entries."""
    directory = Path(directory) if directory else data_dir()
    vault_path = Path(vault_path) if vault_path else directory / VAULT_FILENAME
    entries = read_legacy_entries(directory, master_password)

    # Old master passwords had no length rule, so don't apply it here.
    kdf = _new_kdf(kdf_params)
    vault = Vault(vault_path, derive_key(master_password, kdf), kdf, entries)
    vault.save()

    check = Vault.open(vault_path, master_password)
    if [(e.name, e.username, e.password) for e in check.entries] != \
       [(e.name, e.username, e.password) for e in entries]:
        raise VaultError("Migration check failed; the old files were left untouched.")

    for name in (LEGACY_ACCOUNTS, LEGACY_SALTS, LEGACY_MASTER, LEGACY_BACKUP):
        secure_delete(directory / name)
    safe_dir = directory / "safe"
    if safe_dir.is_dir() and not any(safe_dir.iterdir()):
        safe_dir.rmdir()
    return vault


__all__ = [
    "Entry", "Settings", "Vault", "VaultLock", "VaultError", "WrongPasswordError",
    "CorruptVaultError", "VaultLockedError", "default_vault_path", "default_backup_dir",
    "data_dir", "app_dir", "list_backups", "legacy_files_present", "migrate_legacy",
    "wipe_all_data", "secure_delete", "check_master_password_rules",
    "MIN_MASTER_PASSWORD_LENGTH",
]
