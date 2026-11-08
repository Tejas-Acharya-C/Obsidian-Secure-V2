"""Comprehensive automated test suite for Obsidian Secure V2 Phase 2.

Covers:
- Basic routes (homepage, health, recipient)
- Upload API (valid single/multi, validation, limits, atomicity)
- Retrieval API (manifest, individual ciphertext, archive, error handling)
- Security (path traversal, allowlists, no plaintext/key leaks, concurrency)
"""

import concurrent.futures
import io
import json
import os
import shutil
import tempfile
import unittest
import zipfile

from app import app
from storage import StorageManager, StorageUnavailableError


class BackendTestCase(unittest.TestCase):
    """Test suite for Phase 2 backend functionality."""

    def setUp(self):
        # Create an isolated temporary storage directory outside source directory
        self.test_storage_dir = tempfile.mkdtemp(prefix="test_obsidian_storage_")

        # Initialize storage manager with custom test limits
        self.test_manager = StorageManager(
            storage_dir=self.test_storage_dir,
            max_file_size=1024 * 1024,        # 1 MB
            max_collection_size=2 * 1024 * 1024, # 2 MB
            max_file_count=5,
            max_total_storage=5 * 1024 * 1024,   # 5 MB
        )

        # Patch app storage manager with test manager
        import app as app_module
        self._orig_storage = app_module.storage
        app_module.storage = self.test_manager
        app_module.app.config["MAX_CONTENT_LENGTH"] = self.test_manager.max_collection_size + (1024 * 1024)

        self.client = app.test_client()

    def tearDown(self):
        # Restore original storage manager and clean up temporary storage
        import app as app_module
        app_module.storage = self._orig_storage
        shutil.rmtree(self.test_storage_dir, ignore_errors=True)

    # --- Basic Routes Tests ---

    def test_homepage(self):
        """Homepage returns HTTP 200 with HTML."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Obsidian Secure V2", resp.data)

    def test_health(self):
        """Health endpoint returns HTTP 200 with status healthy."""
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"status": "healthy"})

    def test_recipient_route(self):
        """Recipient template route loads successfully for valid share ID."""
        resp = self.client.get("/s/0123456789abcdef0123456789abcdef")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"0123456789abcdef0123456789abcdef", resp.data)

    # --- Upload API Tests ---

    def test_upload_single_file(self):
        """Upload a single encrypted file successfully."""
        opaque_ciphertext = b"CIPHERTEXT_OPAQUE_BYTES_1234567890"
        data = {
            "files": (io.BytesIO(opaque_ciphertext), "test.bin"),
        }
        resp = self.client.post("/api/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 201)
        res_json = resp.get_json()
        self.assertTrue(res_json["success"])
        self.assertEqual(res_json["file_count"], 1)
        self.assertEqual(res_json["total_size"], len(opaque_ciphertext))
        self.assertEqual(len(res_json["files"]), 1)
        self.assertEqual(res_json["files"][0]["size"], len(opaque_ciphertext))

        # Verify ciphertext matches byte-for-byte upon retrieval
        share_id = res_json["share_id"]
        file_id = res_json["files"][0]["file_id"]
        file_resp = self.client.get(f"/api/files/{share_id}/{file_id}")
        self.assertEqual(file_resp.status_code, 200)
        self.assertEqual(file_resp.data, opaque_ciphertext)
        self.assertEqual(file_resp.headers.get("X-Content-Type-Options"), "nosniff")
        file_resp.close()

    def test_upload_multiple_files(self):
        """Upload multiple files in one collection."""
        file1 = b"CIPHERTEXT_FILE_ONE"
        file2 = b"CIPHERTEXT_FILE_TWO"
        file3 = b"CIPHERTEXT_FILE_THREE"

        data = {
            "files": [
                (io.BytesIO(file1), "f1.enc"),
                (io.BytesIO(file2), "f2.enc"),
                (io.BytesIO(file3), "f3.enc"),
            ]
        }
        resp = self.client.post("/api/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 201)
        res_json = resp.get_json()
        self.assertEqual(res_json["file_count"], 3)
        self.assertEqual(res_json["total_size"], len(file1) + len(file2) + len(file3))

        # Check retrieval of all files
        share_id = res_json["share_id"]
        for idx, expected_bytes in enumerate([file1, file2, file3]):
            fid = res_json["files"][idx]["file_id"]
            d_resp = self.client.get(f"/api/files/{share_id}/{fid}")
            self.assertEqual(d_resp.data, expected_bytes)
            d_resp.close()

    def test_upload_with_custom_file_ids(self):
        """Upload with valid opaque custom file IDs."""
        data = {
            "files": [
                (io.BytesIO(b"data1"), "f1.bin"),
                (io.BytesIO(b"data2"), "f2.bin"),
            ],
            "file_ids": ["custom_id_alpha_1", "custom_id_beta_2"],
        }
        resp = self.client.post("/api/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 201)
        res_json = resp.get_json()
        self.assertEqual(res_json["files"][0]["file_id"], "custom_id_alpha_1")
        self.assertEqual(res_json["files"][1]["file_id"], "custom_id_beta_2")

    def test_upload_duplicate_custom_file_ids(self):
        """Upload rejects duplicate file IDs."""
        data = {
            "files": [
                (io.BytesIO(b"data1"), "f1.bin"),
                (io.BytesIO(b"data2"), "f2.bin"),
            ],
            "file_ids": ["duplicate_id_1", "duplicate_id_1"],
        }
        resp = self.client.post("/api/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["code"], "DUPLICATE_FILE_ID")

    def test_upload_invalid_content_type(self):
        """Upload rejects non-multipart requests."""
        resp = self.client.post("/api/upload", data=b"some bytes", content_type="application/octet-stream")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["code"], "INVALID_CONTENT_TYPE")

    def test_upload_empty_request(self):
        """Upload rejects request with no files."""
        resp = self.client.post("/api/upload", data={}, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["code"], "NO_FILES")

    def test_upload_empty_file_ciphertext(self):
        """Upload rejects 0-byte file ciphertext."""
        data = {
            "files": (io.BytesIO(b""), "empty.bin"),
        }
        resp = self.client.post("/api/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["code"], "EMPTY_FILE")

    def test_upload_too_many_files(self):
        """Upload rejects collections exceeding MAX_FILE_COUNT."""
        # Limit is 5
        data = {
            "files": [(io.BytesIO(b"data"), f"file_{i}.bin") for i in range(6)]
        }
        resp = self.client.post("/api/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 413)
        self.assertEqual(resp.get_json()["code"], "TOO_MANY_FILES")

    def test_upload_file_too_large(self):
        """Upload rejects individual file exceeding MAX_FILE_SIZE."""
        # Limit is 1 MB
        large_bytes = b"X" * (1024 * 1024 + 10)
        data = {
            "files": (io.BytesIO(large_bytes), "toolarge.bin"),
        }
        resp = self.client.post("/api/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 413)
        self.assertEqual(resp.get_json()["code"], "FILE_TOO_LARGE")

    def test_upload_collection_too_large(self):
        """Upload rejects collection exceeding MAX_COLLECTION_SIZE."""
        # Collection limit is 2 MB. Send 3 files of 800 KB each (2.4 MB)
        part = b"Y" * (800 * 1024)
        data = {
            "files": [
                (io.BytesIO(part), "p1.bin"),
                (io.BytesIO(part), "p2.bin"),
                (io.BytesIO(part), "p3.bin"),
            ]
        }
        resp = self.client.post("/api/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 413)
        self.assertEqual(resp.get_json()["code"], "COLLECTION_TOO_LARGE")

    def test_upload_storage_full(self):
        """Upload rejects when storage quota is exceeded."""
        # Set max_total_storage to 100 KB for this test
        self.test_manager.max_total_storage = 100 * 1024
        large_data = b"Z" * (60 * 1024)

        # First upload: 60 KB (succeeds)
        resp1 = self.client.post(
            "/api/upload",
            data={"files": (io.BytesIO(large_data), "f1.bin")},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp1.status_code, 201)

        # Second upload: 60 KB (exceeds 100 KB total storage)
        resp2 = self.client.post(
            "/api/upload",
            data={"files": (io.BytesIO(large_data), "f2.bin")},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp2.status_code, 507)
        self.assertEqual(resp2.get_json()["code"], "STORAGE_FULL")

    def test_atomic_failure_cleanup(self):
        """Failed upload cleans up all staging files and exposes no partial collection."""
        staging_dir = self.test_manager.staging_dir

        # Try an upload with an invalid second file (exceeds file size)
        valid_part = b"VALID_BYTES"
        invalid_part = b"X" * (1024 * 1024 + 10)
        data = {
            "files": [
                (io.BytesIO(valid_part), "valid.bin"),
                (io.BytesIO(invalid_part), "invalid.bin"),
            ]
        }
        resp = self.client.post("/api/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 413)

        # Verify staging directory is completely empty
        staging_contents = os.listdir(staging_dir)
        self.assertEqual(staging_contents, [])

        # Verify no published collection was created
        published_dirs = [
            d for d in os.listdir(self.test_storage_dir) if d != "_staging"
        ]
        self.assertEqual(published_dirs, [])

    # --- Retrieval API Tests ---

    def test_get_collection_manifest(self):
        """Retrieve collection manifest and verify metadata."""
        cdata = b"ENCRYPTED_PAYLOAD_ABC"
        upload_resp = self.client.post(
            "/api/upload",
            data={"files": (io.BytesIO(cdata), "secret.bin")},
            content_type="multipart/form-data",
        )
        share_id = upload_resp.get_json()["share_id"]

        resp = self.client.get(f"/api/files/{share_id}")
        self.assertEqual(resp.status_code, 200)
        res_json = resp.get_json()
        self.assertTrue(res_json["success"])
        self.assertEqual(res_json["share_id"], share_id)
        self.assertEqual(res_json["file_count"], 1)
        self.assertEqual(res_json["total_size"], len(cdata))
        self.assertIn("download_url", res_json["files"][0])

    def test_get_collection_archive(self):
        """Retrieve entire collection as a valid ZIP archive."""
        f1 = b"CIPHERTEXT_1"
        f2 = b"CIPHERTEXT_2"
        upload_resp = self.client.post(
            "/api/upload",
            data={"files": [(io.BytesIO(f1), "a.bin"), (io.BytesIO(f2), "b.bin")]},
            content_type="multipart/form-data",
        )
        share_id = upload_resp.get_json()["share_id"]

        resp = self.client.get(f"/api/files/{share_id}/archive")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("Content-Type"), "application/zip")

        # Verify ZIP contents
        zip_buf = io.BytesIO(resp.data)
        with zipfile.ZipFile(zip_buf, "r") as zf:
            namelist = zf.namelist()
            self.assertIn("manifest.json", namelist)
            enc_files = [n for n in namelist if n.endswith(".enc")]
            self.assertEqual(len(enc_files), 2)

    def test_get_missing_collection(self):
        """Request for nonexistent share ID returns 404."""
        missing_id = "0" * 32
        resp = self.client.get(f"/api/files/{missing_id}")
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.get_json()["code"], "COLLECTION_NOT_FOUND")

    def test_get_invalid_share_id(self):
        """Request with malformed share ID returns 400."""
        resp = self.client.get("/api/files/invalid-non-hex-id")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["code"], "INVALID_IDENTIFIER")

    def test_get_missing_file_in_collection(self):
        """Request for nonexistent file in existing collection returns 404."""
        upload_resp = self.client.post(
            "/api/upload",
            data={"files": (io.BytesIO(b"DATA"), "f.bin")},
            content_type="multipart/form-data",
        )
        share_id = upload_resp.get_json()["share_id"]

        resp = self.client.get(f"/api/files/{share_id}/nonexistent_file_id_123")
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.get_json()["code"], "FILE_NOT_FOUND")

    def test_corrupted_manifest_handling(self):
        """Corrupted manifest returns 500 error and does not crash."""
        upload_resp = self.client.post(
            "/api/upload",
            data={"files": (io.BytesIO(b"DATA"), "f.bin")},
            content_type="multipart/form-data",
        )
        share_id = upload_resp.get_json()["share_id"]

        # Corrupt manifest file on disk
        manifest_path = os.path.join(self.test_storage_dir, share_id, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write("NOT_VALID_JSON{;;;")

        resp = self.client.get(f"/api/files/{share_id}")
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(resp.get_json()["code"], "CORRUPTED_MANIFEST")

    def test_upload_invalid_custom_file_id(self):
        """Upload rejects invalid custom file ID formats."""
        data = {
            "files": (io.BytesIO(b"data"), "f.bin"),
            "file_ids": ["../invalid/traversal"],
        }
        resp = self.client.post("/api/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["code"], "INVALID_IDENTIFIER")

    def test_storage_unavailable_init(self):
        """StorageManager raises StorageUnavailableError if storage is unwritable."""
        unwritable_path = os.path.join(self.test_storage_dir, "non_dir_file")
        with open(unwritable_path, "wb") as f:
            f.write(b"blocking file")

        # Trying to use a file path as storage_dir fails initialization
        with self.assertRaises(StorageUnavailableError):
            StorageManager(storage_dir=unwritable_path)

    def test_missing_referenced_ciphertext_file(self):
        """Collection retrieval detects missing ciphertext file referenced by manifest."""
        upload_resp = self.client.post(
            "/api/upload",
            data={"files": (io.BytesIO(b"DATA"), "f.bin")},
            content_type="multipart/form-data",
        )
        share_id = upload_resp.get_json()["share_id"]
        file_id = upload_resp.get_json()["files"][0]["file_id"]

        # Delete the actual .enc file on disk
        enc_file_path = os.path.join(self.test_storage_dir, share_id, f"{file_id}.enc")
        os.remove(enc_file_path)

        resp = self.client.get(f"/api/files/{share_id}")
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(resp.get_json()["code"], "CORRUPTED_MANIFEST")

    # --- Security Tests ---

    def test_path_traversal_attempts(self):
        """Path traversal attempts are rejected."""
        # Traversal in share ID
        traversal_ids = [
            "../etc/passwd",
            "..\\windows\\system32",
            "....//....//etc",
            "../../secret",
        ]
        for tid in traversal_ids:
            resp = self.client.get(f"/api/files/{tid}")
            # Flask routing or regex validation rejects these
            self.assertIn(resp.status_code, [400, 404])

        # Traversal in file ID
        upload_resp = self.client.post(
            "/api/upload",
            data={"files": (io.BytesIO(b"DATA"), "f.bin")},
            content_type="multipart/form-data",
        )
        share_id = upload_resp.get_json()["share_id"]
        for bad_fid in ["../manifest", "..\\manifest.json", "sub/file"]:
            resp = self.client.get(f"/api/files/{share_id}/{bad_fid}")
            self.assertIn(resp.status_code, [400, 404])

    def test_no_keys_or_original_filenames_persisted(self):
        """Verify original filenames and keys are never saved in manifest or files."""
        secret_filename = "CONFIDENTIAL_PAYLOAD_2026.docx"
        cdata = b"RANDOM_CIPHERTEXT_BYTES"

        upload_resp = self.client.post(
            "/api/upload",
            data={"files": (io.BytesIO(cdata), secret_filename)},
            content_type="multipart/form-data",
        )
        self.assertEqual(upload_resp.status_code, 201)
        share_id = upload_resp.get_json()["share_id"]

        manifest_path = os.path.join(self.test_storage_dir, share_id, "manifest.json")
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest_content = f.read()

        self.assertNotIn("CONFIDENTIAL", manifest_content)
        self.assertNotIn(secret_filename, manifest_content)
        self.assertNotIn("key", manifest_content.lower())
        self.assertNotIn("nonce", manifest_content.lower())
        self.assertNotIn("iv", manifest_content.lower())

    def test_concurrent_uploads(self):
        """Concurrent uploads do not corrupt collections or leak files."""
        def do_upload(idx):
            content = f"CONCURRENT_CONTENT_{idx}".encode("utf-8")
            data = {"files": (io.BytesIO(content), f"f_{idx}.bin")}
            with app.test_client() as c:
                return c.post("/api/upload", data=data, content_type="multipart/form-data")

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(do_upload, i) for i in range(8)]
            results = [f.result() for f in futures]

        for resp in results:
            self.assertEqual(resp.status_code, 201)
            share_id = resp.get_json()["share_id"]
            # Verify each collection is intact
            m_resp = self.client.get(f"/api/files/{share_id}")
            self.assertEqual(m_resp.status_code, 200)

    # --- Collision and Boundary Regression Tests ---

    def test_upload_collection_collision_returns_409(self):
        """Uploading with an existing share ID returns HTTP 409 Conflict."""
        fixed_share_id = "a" * 32
        original_data = b"ORIGINAL_CIPHERTEXT_SAFE"
        colliding_data = b"MALICIOUS_OVERWRITE_ATTEMPT"

        # 1. First upload succeeds
        resp1 = self.client.post(
            "/api/upload",
            data={
                "files": (io.BytesIO(original_data), "orig.bin"),
                "share_id": fixed_share_id,
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(resp1.status_code, 201)
        self.assertEqual(resp1.get_json()["share_id"], fixed_share_id)
        file_id = resp1.get_json()["files"][0]["file_id"]

        # 2. Second upload with colliding share ID is rejected with 409
        resp2 = self.client.post(
            "/api/upload",
            data={
                "files": (io.BytesIO(colliding_data), "bad.bin"),
                "share_id": fixed_share_id,
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(resp2.status_code, 409)
        err_json = resp2.get_json()
        self.assertFalse(err_json["success"])
        self.assertEqual(err_json["code"], "COLLECTION_COLLISION")
        self.assertIn("already exists", err_json["error"])

        # 3. Verify staging directory is cleaned up
        self.assertEqual(os.listdir(self.test_manager.staging_dir), [])

        # 4. Verify original collection is preserved and unmodified
        orig_fetch = self.client.get(f"/api/files/{fixed_share_id}/{file_id}")
        self.assertEqual(orig_fetch.status_code, 200)
        self.assertEqual(orig_fetch.data, original_data)
        orig_fetch.close()

    def test_concurrent_share_id_collision(self):
        """Simultaneous uploads with the same share ID result in exactly one 201 and one 409."""
        colliding_id = "c" * 32

        def try_upload(tag):
            content = f"CONTENT_{tag}".encode("utf-8")
            data = {
                "files": (io.BytesIO(content), f"f_{tag}.bin"),
                "share_id": colliding_id,
            }
            with app.test_client() as c:
                return c.post("/api/upload", data=data, content_type="multipart/form-data")

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(try_upload, i) for i in range(2)]
            results = [f.result() for f in futures]

        status_codes = sorted([r.status_code for r in results])
        self.assertEqual(status_codes, [201, 409])

        # Verify staging directory is completely empty
        self.assertEqual(os.listdir(self.test_manager.staging_dir), [])

        # Verify collection exists and is valid
        m_resp = self.client.get(f"/api/files/{colliding_id}")
        self.assertEqual(m_resp.status_code, 200)

    def test_file_size_exact_boundaries(self):
        """Verify file size limit boundaries: 1 byte below, exactly at limit, and 1 byte above."""
        limit = self.test_manager.max_file_size  # 1 MB = 1048576 bytes

        # 1 byte below limit (allowed)
        below_data = b"A" * (limit - 1)
        resp1 = self.client.post(
            "/api/upload",
            data={"files": (io.BytesIO(below_data), "below.bin")},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp1.status_code, 201)

        # Exactly at limit (allowed)
        exact_data = b"B" * limit
        resp2 = self.client.post(
            "/api/upload",
            data={"files": (io.BytesIO(exact_data), "exact.bin")},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp2.status_code, 201)

        # 1 byte above limit (rejected with 413 FILE_TOO_LARGE)
        above_data = b"C" * (limit + 1)
        resp3 = self.client.post(
            "/api/upload",
            data={"files": (io.BytesIO(above_data), "above.bin")},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp3.status_code, 413)
        self.assertEqual(resp3.get_json()["code"], "FILE_TOO_LARGE")

        # Confirm no leftover staging files
        self.assertEqual(os.listdir(self.test_manager.staging_dir), [])

    def test_collection_size_exact_boundaries(self):
        """Verify collection size limit boundaries: combined size exactly at and exceeding limit."""
        col_limit = self.test_manager.max_collection_size  # 2 MB = 2097152 bytes

        # Exactly at collection limit: 2 files of 1 MB each (allowed)
        f_half = 1024 * 1024
        resp1 = self.client.post(
            "/api/upload",
            data={
                "files": [
                    (io.BytesIO(b"1" * f_half), "part1.bin"),
                    (io.BytesIO(b"2" * f_half), "part2.bin"),
                ]
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(resp1.status_code, 201)
        self.assertEqual(resp1.get_json()["total_size"], col_limit)

        # 1 byte below collection limit: 2 files totaling (col_limit - 1) (allowed)
        resp2 = self.client.post(
            "/api/upload",
            data={
                "files": [
                    (io.BytesIO(b"1" * f_half), "part1.bin"),
                    (io.BytesIO(b"2" * (f_half - 1)), "part2.bin"),
                ]
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(resp2.status_code, 201)
        self.assertEqual(resp2.get_json()["total_size"], col_limit - 1)

        # Combined collection exceeds limit with 3 files under individual limit (rejected 413)
        p_size = 750 * 1024  # 3 * 750 KB = 2250 KB > 2048 KB limit
        resp3 = self.client.post(
            "/api/upload",
            data={
                "files": [
                    (io.BytesIO(b"1" * p_size), "p1.bin"),
                    (io.BytesIO(b"2" * p_size), "p2.bin"),
                    (io.BytesIO(b"3" * p_size), "p3.bin"),
                ]
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(resp3.status_code, 413)
        self.assertEqual(resp3.get_json()["code"], "COLLECTION_TOO_LARGE")

        # Staging directory clean
        self.assertEqual(os.listdir(self.test_manager.staging_dir), [])

    def test_file_count_exact_boundaries(self):
        """Verify file count limit boundaries: exactly at limit (5) and 1 above (6)."""
        limit = self.test_manager.max_file_count  # 5 files

        # Exactly at limit (5 files allowed)
        resp1 = self.client.post(
            "/api/upload",
            data={"files": [(io.BytesIO(b"data"), f"f_{i}.bin") for i in range(limit)]},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp1.status_code, 201)
        self.assertEqual(resp1.get_json()["file_count"], limit)

        # 1 above limit (6 files rejected with 413 TOO_MANY_FILES)
        resp2 = self.client.post(
            "/api/upload",
            data={"files": [(io.BytesIO(b"data"), f"f_{i}.bin") for i in range(limit + 1)]},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp2.status_code, 413)
        self.assertEqual(resp2.get_json()["code"], "TOO_MANY_FILES")

        # Staging directory clean
        self.assertEqual(os.listdir(self.test_manager.staging_dir), [])


if __name__ == "__main__":
    unittest.main()
