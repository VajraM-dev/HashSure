# HashSure Project

A platform for document integrity verification using SHA256 and HMAC, featuring a Rust backend for hashing, a FastAPI server for API endpoints, and a Python client SDK.

---

## Project Structure

- `document_hasher_rust_server/`: Rust library for fast SHA256 and HMAC operations, exposed to Python via PyO3.
- `server-api/`: FastAPI server for document upload, verification, and database storage.
- `client-sdk/`: Python SDK for interacting with the server API.

---

## Setup Instructions

### 1. Rust Hasher Library

```sh
cargo new document_hasher_rust_server
cd document_hasher_rust_server
cargo add pyo3 sha2 hmac hex
maturin develop
```

### 2. Server API

```sh
uv init server-api
cd server-api
uv venv
uv sync
.venv\Scripts\activate
uv add maturin
uv run .\server-fastapi.py
```

- The server uses environment variables for secrets and database configuration, loaded via a `.env` file and HashiCorp Vault.
- The FastAPI server runs on port `9510` by default.

### 3. Client SDK

```sh
uv init client-sdk
cd client-sdk
uv venv
uv sync
.venv\Scripts\activate
uv run .\client_sdk.py
```

---

## Usage

1. **Start the Rust hasher library**  
   Run `maturin develop` in the `document_hasher_rust_server` directory to build and expose the Rust functions to Python.

2. **Run the FastAPI server**  
   Start the server with `uv run .\server-fastapi.py` from the `server-api` directory.  
   The server expects secrets (database URL, HMAC key) from Vault, configured via environment variables.

3. **Use the client SDK**  
   The Python SDK (`client-sdk/client_sdk.py`) allows you to register and verify documents with the server.

---

## Example: Registering and Verifying a Document

The client SDK demonstrates:

- Registering a PDF document (uploads file, stores hash and HMAC on server)
- Verifying the original document (checks hash and HMAC)
- Tampering with the document and verifying again (should fail verification)

Example usage is included in `client_sdk.py`.

---

## Security Notes

- HMAC secret keys and database URLs are managed securely using HashiCorp Vault.
- The Rust backend ensures fast and reliable cryptographic operations.
- The server verifies both the SHA256 hash and the HMAC tag for authenticity and integrity.

---

## Requirements

- Python 3.11+
- Rust toolchain
- [uv](https://github.com/astral-sh/uv) for Python environment management
- HashiCorp Vault for secret management
- PostgreSQL database

---

## License
Refer to the [LICENSE](./LICENSE) file for license details.