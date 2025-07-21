use pyo3::prelude::*;
use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use hex; // Required for hex encoding HMAC output

/// Calculates the SHA256 hash of a given byte array.
#[pyfunction]
fn calculate_sha256_bytes(data: &[u8]) -> PyResult<String> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash_result = hasher.finalize();
    Ok(format!("{:x}", hash_result))
}

/// Calculates the HMAC-SHA256 tag for a given message and secret key.
/// The secret_key and message should be provided as bytes.
/// Returns the HMAC tag as a hex-encoded string.
#[pyfunction]
fn calculate_hmac_sha256(secret_key_bytes: &[u8], message_bytes: &[u8]) -> PyResult<String> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret_key_bytes)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("HMAC key error: {}", e)))?;
    mac.update(message_bytes);
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    Ok(hex::encode(code_bytes))
}

/// A Python module implemented in Rust.
#[pymodule]
fn document_hasher_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(calculate_sha256_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(calculate_hmac_sha256, m)?)?;
    Ok(())
}