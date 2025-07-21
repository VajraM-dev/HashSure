# File Validation Project

This project provides a platform for document integrity verification using SHA256 and HMAC, with a Rust backend for hashing, a FastAPI server for API endpoints, and a Python client SDK.

## Project Structure

- `document_hasher_rust_server/`: Rust library for fast SHA256 and HMAC operations, exposed to Python via PyO3.
- `server-api/`: FastAPI server for document upload, verification, and database storage.
- `client-sdk/`: Python SDK for interacting with the server API.

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

### 3. Client SDK

```sh
uv init client-sdk
cd client-sdk
uv venv
uv sync
.venv\Scripts\activate
uv run .\client_sdk.py
```

## Usage

- Start the Rust hasher library with `maturin develop`.
- Run the FastAPI server as shown above.
- Use the client SDK to register and verify documents.