"""Obsidian Secure V2 - Backend Application Entry Point.

Minimal temporary encrypted multi-file sharing backend.
Operates on opaque ciphertext using temporary filesystem storage.
"""

import logging
import os
from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    send_file,
)
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from storage import (
    CollectionCollisionError,
    CollectionNotFoundError,
    FileNotFoundErrorInCollection,
    InvalidIdentifierError,
    ManifestCorruptedError,
    PayloadTooLargeError,
    StorageError,
    StorageFullError,
    StorageManager,
    StorageUnavailableError,
    ValidationError,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("obsidian_secure.app")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "dev-secret-key-change-in-production"
)

# Initialize storage manager
storage = StorageManager()

# Limit request payload to collection size limit + 2MB envelope overhead
app.config["MAX_CONTENT_LENGTH"] = storage.max_collection_size + (2 * 1024 * 1024)


def make_json_error(message: str, code: str, status_code: int) -> Response:
    """Construct a uniform JSON error response with security headers."""
    resp = jsonify({
        "success": False,
        "error": message,
        "code": code,
    })
    resp.status_code = status_code
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store, private"
    return resp


@app.errorhandler(StorageError)
def handle_storage_error(exc: StorageError):
    """Handle domain-specific storage exceptions."""
    logger.warning("Storage operation failed: %s (code: %s)", exc, exc.code)
    return make_json_error(str(exc), exc.code, exc.status_code)


@app.errorhandler(RequestEntityTooLarge)
def handle_request_too_large(exc: RequestEntityTooLarge):
    """Handle Werkzeug request body limit exceeded."""
    return make_json_error(
        "Request payload exceeds maximum allowed size.",
        "COLLECTION_TOO_LARGE",
        413,
    )


@app.errorhandler(HTTPException)
def handle_http_exception(exc: HTTPException):
    """Handle generic HTTP errors for API endpoints."""
    if request.path.startswith("/api/"):
        return make_json_error(exc.description, "HTTP_ERROR", exc.code or 500)
    return exc


@app.errorhandler(Exception)
def handle_unexpected_exception(exc: Exception):
    """Safely catch unhandled errors without leaking tracebacks."""
    logger.error("Unhandled exception: %s", exc, exc_info=True)
    if request.path.startswith("/api/"):
        return make_json_error(
            "An internal error occurred. Please try again later.",
            "INTERNAL_ERROR",
            500,
        )
    return "Internal Server Error", 500


# --- Web Page Routes ---

@app.route("/")
def index():
    """Homepage route."""
    return render_template("index.html")


@app.route("/s/<share_id>")
def recipient(share_id: str):
    """Recipient route using share ID."""
    return render_template("recipient.html", share_id=share_id)


@app.route("/health")
def health():
    """Service health check endpoint."""
    return jsonify({"status": "healthy"}), 200


# --- API Routes ---

@app.route("/api/upload", methods=["POST"])
def upload():
    """Upload an encrypted file collection.

    Expects multipart/form-data with:
    - files: One or more binary ciphertext files
    - file_ids (optional): Custom opaque IDs for each file (order must match files)
    """
    if not request.content_type or "multipart/form-data" not in request.content_type:
        return make_json_error(
            "Content-Type must be multipart/form-data.",
            "INVALID_CONTENT_TYPE",
            400,
        )

    # Collect files from multipart form
    files = request.files.getlist("files")
    if not files:
        files = request.files.getlist("files[]")
    if not files:
        files = list(request.files.values())

    if not files:
        return make_json_error(
            "No files provided in upload request.",
            "NO_FILES",
            400,
        )

    # Collect optional custom file IDs
    custom_ids = request.form.getlist("file_ids")
    if not custom_ids:
        custom_ids = request.form.getlist("file_ids[]")

    if custom_ids and len(custom_ids) != len(files):
        return make_json_error(
            "Number of file_ids does not match number of files.",
            "INVALID_REQUEST",
            400,
        )

    # Prepare file tuples for storage manager
    file_items = []
    for idx, f in enumerate(files):
        cid = custom_ids[idx] if custom_ids else None
        file_items.append((f.stream, cid))

    custom_share_id = request.form.get("share_id")
    manifest = storage.store_collection(file_items, custom_share_id=custom_share_id)

    response_data = {
        "success": True,
        "share_id": manifest["share_id"],
        "created_at": manifest["created_at"],
        "file_count": manifest["file_count"],
        "total_size": manifest["total_size"],
        "files": manifest["files"],
    }
    resp = jsonify(response_data)
    resp.status_code = 201
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store, private"
    return resp


@app.route("/api/files/<share_id>", methods=["GET"])
def get_collection(share_id: str):
    """Retrieve collection manifest and file listing."""
    manifest = storage.get_manifest(share_id)

    files_list = [
        {
            "file_id": item["file_id"],
            "size": item["size"],
            "download_url": f"/api/files/{share_id}/{item['file_id']}",
        }
        for item in manifest.get("files", [])
    ]

    resp = jsonify({
        "success": True,
        "share_id": manifest["share_id"],
        "created_at": manifest["created_at"],
        "file_count": manifest["file_count"],
        "total_size": manifest["total_size"],
        "files": files_list,
    })
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store, private"
    return resp


@app.route("/api/files/<share_id>/<file_id>", methods=["GET"])
def download_file(share_id: str, file_id: str):
    """Download an individual ciphertext file."""
    file_path = storage.get_file_path(share_id, file_id)

    resp = send_file(
        file_path,
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=f"{file_id}.enc",
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store, private"
    return resp


@app.route("/api/files/<share_id>/archive", methods=["GET"])
def download_archive(share_id: str):
    """Download all ciphertext files in the collection as a transport ZIP."""
    zip_buffer = storage.create_collection_zip(share_id)

    resp = send_file(
        zip_buffer,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"obsidian_{share_id[:8]}_ciphertext.zip",
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store, private"
    return resp


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)
