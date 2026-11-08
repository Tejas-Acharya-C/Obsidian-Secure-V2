# Obsidian Secure V2

Minimal temporary encrypted multi-file sharing website.

## Technology Stack

- **Backend**: Python 3.11, Flask
- **Production Server**: Gunicorn
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Encryption**: Browser Web Crypto API (AES-256-GCM)
- **QR Generation**: Browser-side library (`qrcode.min.js`, David Shim, MIT License)
- **ZIP Creation**: Browser-side library (`jszip.min.js` v3.10.1, Stuart Knightley, MIT License)
- **Storage**: Ephemeral filesystem (no database)

## Cryptographic Architecture

- **Algorithm**: AES-256-GCM authenticated encryption via browser `window.crypto.subtle`.
- **Key Derivation**: Independent 256-bit cryptographically secure random key per file (`crypto.subtle.generateKey`).
- **Nonce/IV**: Fresh 96-bit (12-byte) random initialization vector per file (`crypto.getRandomValues`).
- **Authentication**: Strict 128-bit AES-GCM tag verification prior to releasing plaintext.
- **Zero-Knowledge Backend**: Flask server receives and stores only ciphertext and opaque IDs. Keys, nonces, and original filenames exist solely in the client-side URL fragment (`#<base64url_json_metadata>`).

## Environment Configuration

Copy `.env.example` to `.env` to customize settings:

| Variable | Description | Default |
|---|---|---|
| `STORAGE_DIR` | Directory for temporary collections | System temp (`obsidian_secure_v2_storage`) |
| `MAX_FILE_SIZE` | Max ciphertext size per file (bytes) | `26214400` (25 MB) |
| `MAX_COLLECTION_SIZE` | Max collection ciphertext size (bytes) | `52428800` (50 MB) |
| `MAX_FILE_COUNT` | Max files allowed per collection | `10` |
| `MAX_TOTAL_STORAGE` | Total ephemeral storage limit (bytes) | `262144000` (250 MB) |
| `SECRET_KEY` | Flask application secret key | Dev default |
| `PORT` | Local server port | `5000` |

### Temporary Storage Limitations

Storage availability operates under an `until_restart` model. Files are stored on Render Free's ephemeral filesystem and will be permanently cleared when the server restarts, sleeps, or redeploys. No persistent retention is guaranteed.

## Available Routes

| Method | Route | Description |
|---|---|---|
| `GET` | `/` | Web homepage (Sender interface) |
| `GET` | `/s/<share_id>` | Recipient collection view (Decryption interface) |
| `GET` | `/health` | Service health check |
| `POST` | `/api/upload` | Upload encrypted file collection |
| `GET` | `/api/files/<share_id>` | Get collection manifest & file list |
| `GET` | `/api/files/<share_id>/<file_id>` | Download individual ciphertext file |
| `GET` | `/api/files/<share_id>/archive` | Download ciphertext files as ZIP |

## API Contracts

### 1. Upload API (`POST /api/upload`)
- **Content-Type**: `multipart/form-data`
- **Form Fields**:
  - `files`: One or more binary ciphertext files (required).
  - `file_ids` (optional): Custom opaque IDs (alphanumeric, dash, underscore, 8-64 chars).
- **Response (201 Created)**:
  ```json
  {
    "success": true,
    "share_id": "32-char-hex-token",
    "created_at": "ISO-8601-UTC-timestamp",
    "file_count": 2,
    "total_size": 2048,
    "files": [
      {"file_id": "file-id-1", "size": 1024},
      {"file_id": "file-id-2", "size": 1024}
    ]
  }
  ```

### 2. Retrieval API (`GET /api/files/<share_id>`)
- **Response (200 OK)**:
  ```json
  {
    "success": true,
    "share_id": "32-char-hex-token",
    "created_at": "ISO-8601-UTC-timestamp",
    "file_count": 2,
    "total_size": 2048,
    "files": [
      {
        "file_id": "file-id-1",
        "size": 1024,
        "download_url": "/api/files/<share_id>/file-id-1"
      }
    ]
  }
  ```

### 3. Client-Side Share URL Structure
`https://<domain>/s/<share_id>#<base64url_encoded_metadata>`

Decryption metadata is stored strictly in the URL fragment (`#...`) and is never sent to the server in HTTP requests:
```json
{
  "v": 1,
  "share_id": "32-char-hex-token",
  "files": [
    {
      "file_id": "opaque-file-id",
      "name": "original-filename.ext",
      "type": "mime/type",
      "size": 12345,
      "key": "base64url-256bit-raw-aes-key",
      "iv": "base64url-96bit-nonce"
    }
  ]
}
```

## Local Setup and Testing

1. Setup environment and install dependencies:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate      # Windows (or: source .venv/bin/activate)
   pip install -r requirements.txt
   ```

2. Run automated backend tests:
   ```bash
   python -m unittest tests/test_backend.py
   ```

3. Run browser cryptography tests:
   ```bash
   node tests/test_crypto.js
   ```

4. Run local server:
   ```bash
   python app.py
   ```

## Production Deployment (Render Free Web Service)

1. Create a new **Web Service** on Render connected to this repository (or use `render.yaml` Blueprint).
2. Configure settings:
   - **Environment**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120`
   - **Health Check Path**: `/health`
3. Environment variables:
   - `PYTHON_VERSION`: `3.11.9`
   - `FLASK_DEBUG`: `0`
   - `SECRET_KEY`: `<generate-a-secure-random-secret>`
   - `STORAGE_DIR`: `/tmp/obsidian_storage`
4. **Concurrency and Process Model Notice**:
   Storage quota tracking and atomic collection promotion use Python in-process synchronization (`threading.Lock()`). Running with `--workers 1 --threads 4` ensures all concurrent requests are processed within a single worker process protected by this lock. Do not scale to multiple worker processes without external IPC/filesystem lock coordination.
5. **Storage Architecture Notice**:
   Render Free Web Services use an ephemeral filesystem. Uploaded ciphertext collections are stored temporarily and will be cleared upon instance restarts, redeployments, or sleeping. Recipients should download verified files promptly.

## Current Implementation Status

- **Phase 1: Foundation** (Completed)
- **Phase 2: Backend and Temporary Storage** (Completed)
- **Phase 3: Browser Encryption, Decryption & Sharing** (Completed)
- **Phase 4: Visual Design & Single-Screen Architecture** (Completed)
- **Phase 5: Integration & Cryptographic Audit** (Completed)
- **Phase 6A: Final Pre-Deployment Audit & Collision Resolution** (Completed)
  - Browser Web Crypto API integration (AES-256-GCM, independent keys, fresh 96-bit nonces).
  - Zero-knowledge client URL-fragment metadata format and validation.
  - Sender interface with drag-and-drop, individual file encryption, and upload.
  - Recipient interface with URL fragment parsing, manifest cross-checking, and local decryption.
  - Client-side decrypted ZIP packaging via JSZip with duplicate filename handling.
  - High-contrast client-side QR code generation and PNG export.
