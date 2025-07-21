import os
from datetime import datetime
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy.exc import IntegrityError
import document_hasher_rust # Our Rust module!
from dotenv import load_dotenv
import uvicorn
import hvac

load_dotenv()  # Load environment variables from .env file

app = FastAPI(
    title="Document Integrity Platform",
    description="API for hashing and verifying document integrity using SHA256 and HMAC.",
    version="1.0.0"
)

# Authentication
client = hvac.Client(
    url=os.environ.get('VAULT_ADDR'),
    token=os.environ.get('VAULT_TOKEN'),
)

if not client.is_authenticated():
    raise Exception("Vault authentication failed. Check your token and Vault server status.")

read_secret_result = client.secrets.kv.v2.read_secret_version(
            mount_point=os.environ.get('MOUNT_POINT'),
            path=os.environ.get('PATH'),
            raise_on_deleted_version=True
        )


# --- Configuration for PostgreSQL and HMAC Secret Key ---
DATABASE_URL = read_secret_result['data']['data']['DATABASE_URL']

# IMPORTANT: For production, generate a strong, random key and store it securely (e.g., in a secrets manager)
HMAC_SECRET_KEY = read_secret_result['data']['data']['HMAC_SECRET_KEY'].encode('utf-8')

if len(HMAC_SECRET_KEY) < 32: # HMAC keys should ideally be as long as the hash output (32 bytes for SHA256)
    print("WARNING: HMAC_SECRET_KEY is too short. Please use a key of at least 32 bytes for production.")

# SQLAlchemy setup
Engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=Engine)
Base = declarative_base()

# --- Database Model ---
class DocumentHash(Base):
    __tablename__ = "document_hashes"
    id = Column(Integer, primary_key=True, index=True)
    file_name = Column(String, nullable=False)
    sha256_hash = Column(String(64), unique=True, nullable=False, index=True) # Plain SHA256
    hmac_tag = Column(String(64), nullable=False) # HMAC-SHA256 tag for authenticity of the record
    uploaded_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<DocumentHash {self.file_name}: {self.sha256_hash[:10]}... (HMAC: {self.hmac_tag[:10]}...)>"

# --- Pydantic Models for API ---
class VerificationRequest(BaseModel):
    sha256_hash: str # Client still sends the plain SHA256

class DocumentUploadResponse(BaseModel):
    message: str
    file_name: str
    sha256_hash: str
    hmac_tag: str
    timestamp: datetime

class DocumentVerificationResponse(BaseModel):
    message: str
    is_original: bool
    file_name_on_record: str | None = None
    uploaded_at: datetime | None = None

# --- Dependency to get DB session ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Event to create tables on startup ---
@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=Engine)
    print("Database tables created (if they didn't exist).")

# --- API Endpoints ---

@app.post("/upload_document", response_model=DocumentUploadResponse, status_code=201)
async def upload_document(pdf: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Uploads a PDF document, calculates its SHA256 hash and HMAC-SHA256 tag (using Rust),
    and stores both in the database.
    """
    if not pdf.filename:
        raise HTTPException(status_code=400, detail="No selected file.")

    file_content = await pdf.read()
    
    # 1. Calculate plain SHA256 using Rust
    sha256 = document_hasher_rust.calculate_sha256_bytes(file_content)
    file_name = pdf.filename

    # 2. Calculate HMAC-SHA256 using Rust (message is the plain SHA256 hash)
    # The HMAC_tag authenticates that *this specific plain hash* was registered by *this server*
    hmac_tag = document_hasher_rust.calculate_hmac_sha256(HMAC_SECRET_KEY, sha256.encode('utf-8'))


    # Check if plain SHA256 hash already exists to prevent duplicate records for the same file
    existing_record = db.query(DocumentHash).filter_by(sha256_hash=sha256).first()
    if existing_record:
        # If it exists, we could optionally re-verify its HMAC here for extra paranoia
        # For simplicity, if plain hash matches, we assume it's the same file and return existing record.
        # In a very strict scenario, you might want to compare HMACs too.
        return DocumentUploadResponse(
            message="File with this SHA256 hash already exists.",
            file_name=existing_record.file_name,
            sha256_hash=existing_record.sha256_hash,
            hmac_tag=existing_record.hmac_tag,
            timestamp=existing_record.uploaded_at
        )

    new_doc_hash = DocumentHash(
        file_name=file_name,
        sha256_hash=sha256,
        hmac_tag=hmac_tag
    )
    try:
        db.add(new_doc_hash)
        db.commit()
        db.refresh(new_doc_hash)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"Database conflict: {e}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Server error during database commit: {e}")

    return DocumentUploadResponse(
        message="Document uploaded and hash stored successfully",
        file_name=file_name,
        sha256_hash=sha256,
        hmac_tag=hmac_tag,
        timestamp=new_doc_hash.uploaded_at
    )

@app.post("/verify_document", response_model=DocumentVerificationResponse)
async def verify_document(request: VerificationRequest, db: Session = Depends(get_db)):
    """
    Verifies if a given plain SHA256 hash exists in the database
    and its associated HMAC tag is also valid, indicating the document's
    originality and the record's authenticity.
    """
    client_sha256_hash = request.sha256_hash

    doc_hash_record = db.query(DocumentHash).filter_by(sha256_hash=client_sha256_hash).first()

    if doc_hash_record:
        # Recalculate the HMAC-SHA256 based on the stored plain hash and the server's secret key
        recalculated_hmac_tag = document_hasher_rust.calculate_hmac_sha256(
            HMAC_SECRET_KEY,
            doc_hash_record.sha256_hash.encode('utf-8')
        )

        if recalculated_hmac_tag == doc_hash_record.hmac_tag:
            return DocumentVerificationResponse(
                message="Document verified successfully. Integrity and record authenticity confirmed.",
                is_original=True,
                file_name_on_record=doc_hash_record.file_name,
                uploaded_at=doc_hash_record.uploaded_at
            )
        else:
            # This is a critical security alert! It means the plain hash matched,
            # but the HMAC tag stored in the database is invalid.
            # This suggests tampering with the database record itself.
            raise HTTPException(
                status_code=500, # Internal Server Error, as the server's own record is suspect
                detail={
                    "message": "Database record found, but HMAC tag is invalid. Possible server-side record tampering!",
                    "is_original": False
                }
            )
    else:
        raise HTTPException(
            status_code=404,
            detail={
                "message": "Document hash not found. File may be tampered with or not registered.",
                "is_original": False
            }
        )

# Example: Include for FastAPI setup
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9510)