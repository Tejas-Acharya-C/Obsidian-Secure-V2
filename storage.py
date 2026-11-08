"""Storage manager and filesystem security for Obsidian Secure V2.

Handles temporary storage of opaque encrypted file collections, manifest management,
path traversal validation, storage quota enforcement, and atomic collection publishing.
"""

from datetime import datetime, timezone
import io
import json
import logging
import os
import re
import secrets
import shutil
import tempfile
import threading
from typing import BinaryIO, Dict, List, Optional, Tuple
import zipfile

logger = logging.getLogger("obsidian_secure.storage")

# Default resource limits
DEFAULT_MAX_FILE_SIZE = 25 * 1024 * 1024       # 25 MB
DEFAULT_MAX_COLLECTION_SIZE = 50 * 1024 * 1024 # 50 MB
DEFAULT_MAX_FILE_COUNT = 10                     # 10 files
DEFAULT_MAX_TOTAL_STORAGE = 250 * 1024 * 1024   # 250 MB

# Validation regex: 128-bit hex string for share IDs (32 hex chars)
SHARE_ID_REGEX = re.compile(r"^[a-f0-9]{32}$")
# Validation regex for opaque file IDs: 8-64 alphanumeric, dash or underscore
FILE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_-]{8,64}$")


class StorageError(Exception):
    """Base exception for storage operations."""
    status_code = 500
    code = "STORAGE_ERROR"


class StorageUnavailableError(StorageError):
    """Raised when storage directory cannot be initialized or accessed."""
    status_code = 503
    code = "STORAGE_UNAVAILABLE"


class StorageFullError(StorageError):
    """Raised when configured storage quota or filesystem disk space is exhausted."""
    status_code = 507
    code = "STORAGE_FULL"


class PayloadTooLargeError(StorageError):
    """Raised when incoming payload exceeds limits."""
    status_code = 413
    code = "PAYLOAD_TOO_LARGE"


class FileTooLargeError(PayloadTooLargeError):
    """Raised when an individual ciphertext file exceeds the limit."""
    code = "FILE_TOO_LARGE"


class CollectionTooLargeError(PayloadTooLargeError):
    """Raised when the collection ciphertext total exceeds the limit."""
    code = "COLLECTION_TOO_LARGE"


class TooManyFilesError(PayloadTooLargeError):
    """Raised when file count exceeds the limit."""
    code = "TOO_MANY_FILES"


class DuplicateFileIdError(StorageError):
    """Raised when duplicate file IDs are supplied."""
    status_code = 400
    code = "DUPLICATE_FILE_ID"


class CollectionCollisionError(StorageError):
    """Raised when an attempt is made to overwrite an existing collection."""
    status_code = 409
    code = "COLLECTION_COLLISION"


class EmptyFileError(StorageError):
    """Raised when a ciphertext file is empty."""
    status_code = 400
    code = "EMPTY_FILE"


class CollectionNotFoundError(StorageError):
    """Raised when the requested share collection does not exist."""
    status_code = 404
    code = "COLLECTION_NOT_FOUND"


class FileNotFoundErrorInCollection(StorageError):
    """Raised when a specific ciphertext file does not exist in collection."""
    status_code = 404
    code = "FILE_NOT_FOUND"


class ManifestCorruptedError(StorageError):
    """Raised when collection manifest is missing or invalid."""
    status_code = 500
    code = "CORRUPTED_MANIFEST"


class InvalidIdentifierError(StorageError):
    """Raised when an identifier does not match strict allowlist format."""
    status_code = 400
    code = "INVALID_IDENTIFIER"


class ValidationError(StorageError):
    """Raised when request payload or files fail validation."""
    status_code = 400
    code = "VALIDATION_ERROR"


def validate_share_id(share_id: str) -> bool:
    """Validate share ID format against strict allowlist."""
    return bool(isinstance(share_id, str) and SHARE_ID_REGEX.match(share_id))


def validate_file_id(file_id: str) -> bool:
    """Validate file ID format against strict allowlist."""
    return bool(isinstance(file_id, str) and FILE_ID_REGEX.match(file_id))


class StorageManager:
    """Manages collection-based filesystem storage for opaque encrypted files."""

    def __init__(
        self,
        storage_dir: Optional[str] = None,
        max_file_size: Optional[int] = None,
        max_collection_size: Optional[int] = None,
        max_file_count: Optional[int] = None,
        max_total_storage: Optional[int] = None,
    ):
        raw_storage_dir = storage_dir or os.environ.get(
            "STORAGE_DIR",
            os.path.join(tempfile.gettempdir(), "obsidian_secure_v2_storage"),
        )
        self.storage_dir = os.path.abspath(raw_storage_dir)

        self.max_file_size = int(
            max_file_size
            or os.environ.get("MAX_FILE_SIZE", DEFAULT_MAX_FILE_SIZE)
        )
        self.max_collection_size = int(
            max_collection_size
            or os.environ.get("MAX_COLLECTION_SIZE", DEFAULT_MAX_COLLECTION_SIZE)
        )
        self.max_file_count = int(
            max_file_count
            or os.environ.get("MAX_FILE_COUNT", DEFAULT_MAX_FILE_COUNT)
        )
        self.max_total_storage = int(
            max_total_storage
            or os.environ.get("MAX_TOTAL_STORAGE", DEFAULT_MAX_TOTAL_STORAGE)
        )

        self.staging_dir = os.path.join(self.storage_dir, "_staging")
        self._lock = threading.Lock()

        # Initialize and verify storage at startup
        self._initialize_storage()

    def _initialize_storage(self) -> None:
        """Create and verify storage directory permissions and writability."""
        try:
            os.makedirs(self.storage_dir, mode=0o700, exist_ok=True)
            os.makedirs(self.staging_dir, mode=0o700, exist_ok=True)

            if not os.path.isdir(self.storage_dir):
                raise StorageUnavailableError("Storage path is not a directory.")

            # Test writability with a temporary test file
            probe_path = os.path.join(
                self.storage_dir, f".write_probe_{secrets.token_hex(8)}"
            )
            try:
                with open(probe_path, "wb") as f:
                    f.write(b"ok")
                os.remove(probe_path)
            except OSError as exc:
                raise StorageUnavailableError(
                    f"Storage directory is not writable: {exc}"
                ) from exc
        except Exception as exc:
            if isinstance(exc, StorageUnavailableError):
                raise
            raise StorageUnavailableError(
                f"Failed to initialize storage directory: {exc}"
            ) from exc

    def get_current_storage_usage(self) -> int:
        """Calculate total bytes occupied by published collections on disk."""
        total_bytes = 0
        try:
            for entry in os.scandir(self.storage_dir):
                if entry.is_dir() and entry.name != "_staging":
                    for item in os.scandir(entry.path):
                        if item.is_file():
                            total_bytes += item.stat().st_size
        except OSError as exc:
            logger.error("Failed to calculate storage usage: %s", exc)
        return total_bytes

    def get_safe_share_dir(self, share_id: str) -> str:
        """Resolve and verify path safety for a collection share directory."""
        if not validate_share_id(share_id):
            raise InvalidIdentifierError("Invalid share ID format.")

        resolved_path = os.path.normpath(os.path.join(self.storage_dir, share_id))
        if os.path.commonpath([self.storage_dir, resolved_path]) != self.storage_dir:
            raise InvalidIdentifierError("Path traversal detected in share ID.")

        return resolved_path

    def get_safe_file_path(self, share_dir: str, file_id: str) -> str:
        """Resolve and verify path safety for a ciphertext file in a collection."""
        if not validate_file_id(file_id):
            raise InvalidIdentifierError("Invalid file ID format.")

        resolved_path = os.path.normpath(os.path.join(share_dir, f"{file_id}.enc"))
        if os.path.commonpath([share_dir, resolved_path]) != share_dir:
            raise InvalidIdentifierError("Path traversal detected in file ID.")

        return resolved_path

    def store_collection(
        self,
        files: List[Tuple[BinaryIO, Optional[str]]],
        custom_share_id: Optional[str] = None,
    ) -> Dict:
        """Safely store an uploaded collection of encrypted files.

        Args:
            files: List of (file_stream, optional_custom_file_id)
            custom_share_id: Optional 128-bit hex share ID validated against allowlist.

        Returns:
            Collection manifest dictionary.
        """
        if not files:
            raise ValidationError("No files provided in request.")

        if len(files) > self.max_file_count:
            raise TooManyFilesError(
                f"Collection exceeds maximum file count of {self.max_file_count}."
            )

        # Validate custom file IDs if provided
        assigned_file_ids: List[str] = []
        for _, custom_id in files:
            if custom_id:
                if not validate_file_id(custom_id):
                    raise InvalidIdentifierError(
                        f"Custom file ID '{custom_id}' is invalid."
                    )
                if custom_id in assigned_file_ids:
                    raise DuplicateFileIdError(
                        f"Duplicate file ID '{custom_id}' in upload request."
                    )
                assigned_file_ids.append(custom_id)
            else:
                assigned_file_ids.append(secrets.token_hex(16))

        # Determine share ID (validated custom ID or freshly generated 128-bit random hex)
        if custom_share_id:
            if not validate_share_id(custom_share_id):
                raise InvalidIdentifierError("Invalid custom share ID format.")
            share_id = custom_share_id
        else:
            share_id = secrets.token_hex(16)

        final_dir = self.get_safe_share_dir(share_id)
        if os.path.exists(final_dir):
            raise CollectionCollisionError("A collection with this identifier already exists.")

        staging_token = secrets.token_hex(16)
        collection_staging_dir = os.path.join(self.staging_dir, staging_token)
        os.makedirs(collection_staging_dir, mode=0o700, exist_ok=True)

        file_records: List[Dict] = []
        total_collection_bytes = 0

        try:
            for (stream, _), file_id in zip(files, assigned_file_ids):
                dest_path = os.path.join(collection_staging_dir, f"{file_id}.enc")
                file_bytes_written = 0

                with open(dest_path, "wb") as dest:
                    while True:
                        chunk = stream.read(65536)
                        if not chunk:
                            break
                        file_bytes_written += len(chunk)

                        if file_bytes_written > self.max_file_size:
                            raise FileTooLargeError(
                                f"File exceeds maximum allowed size of {self.max_file_size} bytes."
                            )

                        if (total_collection_bytes + file_bytes_written) > self.max_collection_size:
                            raise CollectionTooLargeError(
                                f"Collection exceeds maximum allowed size of {self.max_collection_size} bytes."
                            )

                        dest.write(chunk)

                if file_bytes_written == 0:
                    raise EmptyFileError("File ciphertext cannot be empty.")

                try:
                    os.chmod(dest_path, 0o600)
                except OSError:
                    pass

                total_collection_bytes += file_bytes_written
                file_records.append({
                    "file_id": file_id,
                    "size": file_bytes_written,
                })

            # Check capacity and disk usage atomically under lock
            with self._lock:
                current_used = self.get_current_storage_usage()
                if (current_used + total_collection_bytes) > self.max_total_storage:
                    raise StorageFullError(
                        "Storage quota exceeded. Cannot accept new uploads."
                    )

                try:
                    free_disk = shutil.disk_usage(self.storage_dir).free
                    if free_disk < total_collection_bytes:
                        raise StorageFullError("Insufficient disk space on host storage.")
                except OSError as exc:
                    logger.warning("Could not check disk usage: %s", exc)

                # Final concurrency guard against race collision before promotion
                if os.path.exists(final_dir):
                    raise CollectionCollisionError("A collection with this identifier already exists.")

                # Write manifest file in staging directory
                manifest = {
                    "protocol_version": 2,
                    "share_id": share_id,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "file_count": len(file_records),
                    "total_size": total_collection_bytes,
                    "files": file_records,
                }

                manifest_path = os.path.join(collection_staging_dir, "manifest.json")
                with open(manifest_path, "w", encoding="utf-8") as mf:
                    json.dump(manifest, mf, indent=2)

                try:
                    os.chmod(manifest_path, 0o600)
                except OSError:
                    pass

                # Atomic promotion: move completed staging collection to final directory
                os.replace(collection_staging_dir, final_dir)

            return manifest

        except Exception:
            # Clean up temporary staging directory on any failure
            shutil.rmtree(collection_staging_dir, ignore_errors=True)
            raise

    def get_manifest(self, share_id: str) -> Dict:
        """Retrieve and validate the collection manifest."""
        share_dir = self.get_safe_share_dir(share_id)
        if not os.path.isdir(share_dir):
            raise CollectionNotFoundError("The requested collection was not found.")

        manifest_path = os.path.join(share_dir, "manifest.json")
        if not os.path.isfile(manifest_path):
            raise ManifestCorruptedError("Collection manifest is missing.")

        try:
            with open(manifest_path, "r", encoding="utf-8") as mf:
                manifest = json.load(mf)
        except (OSError, json.JSONDecodeError) as exc:
            raise ManifestCorruptedError("Failed to parse collection manifest.") from exc

        # Basic structural validation
        if not isinstance(manifest, dict) or "files" not in manifest:
            raise ManifestCorruptedError("Invalid manifest structure.")

        # Verify referenced ciphertext files exist
        for item in manifest.get("files", []):
            fid = item.get("file_id")
            if not fid:
                raise ManifestCorruptedError("Manifest contains file entry without file_id.")
            file_path = self.get_safe_file_path(share_dir, fid)
            if not os.path.isfile(file_path):
                raise ManifestCorruptedError(
                    f"Referenced ciphertext file for '{fid}' is missing."
                )

        return manifest

    def get_file_path(self, share_id: str, file_id: str) -> str:
        """Retrieve verified path to an individual ciphertext file."""
        # Manifest check ensures collection exists and file_id is genuine
        manifest = self.get_manifest(share_id)
        share_dir = self.get_safe_share_dir(share_id)

        valid_ids = {item["file_id"] for item in manifest.get("files", []) if "file_id" in item}
        if file_id not in valid_ids:
            raise FileNotFoundErrorInCollection("Requested file ID not found in collection.")

        file_path = self.get_safe_file_path(share_dir, file_id)
        if not os.path.isfile(file_path):
            raise FileNotFoundErrorInCollection("Referenced ciphertext file is missing.")

        return file_path

    def create_collection_zip(self, share_id: str) -> io.BytesIO:
        """Create an in-memory ZIP archive of the collection for transport."""
        manifest = self.get_manifest(share_id)
        share_dir = self.get_safe_share_dir(share_id)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            manifest_path = os.path.join(share_dir, "manifest.json")
            zf.write(manifest_path, arcname="manifest.json")
            for item in manifest.get("files", []):
                fid = item["file_id"]
                file_path = self.get_safe_file_path(share_dir, fid)
                zf.write(file_path, arcname=f"{fid}.enc")

        zip_buffer.seek(0)
        return zip_buffer

