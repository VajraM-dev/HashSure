# client_sdk.py (No changes needed, still points to port 8000)
import hashlib
import requests
import os
import json

class DocumentIntegritySDK:
    def __init__(self, server_url="http://localhost:9510"): # Updated port for FastAPI
        self.server_url = server_url

    def _calculate_sha256_for_file_path(self, file_path):
        """Calculates SHA256 hash for a file at a given path."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found at: {file_path}")

        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def register_document(self, file_path):
        """
        Uploads a document to the server and registers its hash.
        Returns server's response.
        """
        try:
            with open(file_path, 'rb') as f:
                files = {'pdf': (os.path.basename(file_path), f, 'application/pdf')}
                response = requests.post(f"{self.server_url}/upload_document", files=files)
                response.raise_for_status() # Raise an exception for HTTP errors
                return response.json()
        except FileNotFoundError:
            print(f"Error: File not found at {file_path}")
            return {"error": "File not found"}
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Server response ({e.response.status_code}): {e.response.text}")
            return {"error": str(e)}

    def verify_document(self, file_path):
        """
        Calculates the local document hash and sends it to the server for verification.
        Returns server's verification response.
        """
        try:
            local_sha256 = self._calculate_sha256_for_file_path(file_path)
            print(f"Local SHA256 for '{os.path.basename(file_path)}': {local_sha256}")

            headers = {'Content-Type': 'application/json'}
            data = {'sha256_hash': local_sha256}
            response = requests.post(f"{self.server_url}/verify_document", json=data, headers=headers)
            
            # Handle different status codes appropriately
            if response.status_code == 200:
                # Document found and verified
                return response.json()
            elif response.status_code == 404:
                # Document not found (tampered or never registered)
                try:
                    return response.json()  # Return the detailed response
                except json.JSONDecodeError:
                    # Fallback if response isn't valid JSON
                    return {
                        "is_original": False,
                        "message": "Document hash not found. File may be tampered with or not registered.",
                        "status_code": 404
                    }
            else:
                # Other HTTP errors
                response.raise_for_status()
                
        except FileNotFoundError:
            print(f"Error: File not found at {file_path}")
            return {"error": "File not found"}
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Server response ({e.response.status_code}): {e.response.text}")
            return {"error": str(e)}

# --- Example Usage ---
if __name__ == "__main__":
    sdk = DocumentIntegritySDK()

    dummy_pdf_path = "Quotation.pdf"
    with open(dummy_pdf_path, "wb") as f:
        f.write(b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj 2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj 3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>endobj 4 0 obj<</Length 11>>stream\nBT /F1 12 Tf 72 712 Td (Hello World) Tj ET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f\n0000000009 00000 n\n0000000055 00000 n\n0000000109 00000 n\n0000000213 00000 n\ntrailer<</Size 5/Root 1 0 R>>startxref\n300\n%%EOF")
    print(f"Created dummy PDF: {dummy_pdf_path}")

    print("\n--- Registering a document ---")
    registration_result = sdk.register_document(dummy_pdf_path)
    print("Registration Result:", json.dumps(registration_result, indent=2))

    print("\n--- Verifying the original document ---")
    verification_result = sdk.verify_document(dummy_pdf_path)
    print("Verification Result:", json.dumps(verification_result, indent=2))

    print("\n--- Tampering with the document and verifying ---")
    with open(dummy_pdf_path, "ab") as f:
        f.write(b"tampered!")
    print("Document tampered!")
    tampered_verification_result = sdk.verify_document(dummy_pdf_path)
    print("Tampered Verification Result:", json.dumps(tampered_verification_result, indent=2))

    os.remove(dummy_pdf_path)
    print(f"\nRemoved dummy PDF: {dummy_pdf_path}")