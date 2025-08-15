"""
Secure File Upload Handler
Implements secure file upload handling with validation and sanitization
"""

import os
import re
import magic
import hashlib
from pathlib import Path
from typing import Optional, Tuple
from fastapi import UploadFile, HTTPException
from .secure_config import secure_settings
import logging
import aiofiles
import asyncio
import secrets

logger = logging.getLogger(__name__)

class SecureFileUpload:
    """Secure file upload handler with validation and sanitization"""
    
    def __init__(self):
        self.upload_dir = Path(secure_settings.upload.UPLOAD_DIR)
        self.max_size = secure_settings.upload.MAX_UPLOAD_SIZE
        self.allowed_extensions = secure_settings.upload.ALLOWED_EXTENSIONS
        self.content_types = secure_settings.upload.CONTENT_TYPE_WHITELIST
        
        # Ensure upload directory exists and is secure
        self._ensure_secure_upload_dir()
    
    def _ensure_secure_upload_dir(self):
        """Ensure upload directory exists and has secure permissions"""
        
        # Create directory if it doesn't exist
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        
        # Set secure permissions (700 - only owner can read/write/execute)
        try:
            os.chmod(self.upload_dir, 0o700)
        except Exception as e:
            logger.error(f"Failed to set secure permissions on upload directory: {e}")
            raise HTTPException(status_code=500, detail="Upload directory configuration error")
    
    async def save_upload(self, file: UploadFile) -> Tuple[str, str]:
        """
        Save uploaded file securely
        
        Returns:
            Tuple[str, str]: (secure_filename, file_hash)
        """
        
        try:
            # Validate file before processing
            await self._validate_upload(file)
            
            # Generate secure filename
            secure_filename = self._generate_secure_filename(file.filename)
            
            # Get full file path
            file_path = self.upload_dir / secure_filename
            
            # Save file securely
            file_hash = await self._save_file_secure(file, file_path)
            
            # Verify saved file
            await self._verify_saved_file(file_path, file_hash)
            
            return secure_filename, file_hash
            
        except Exception as e:
            logger.error(f"File upload error: {e}")
            raise HTTPException(status_code=400, detail=str(e))
    
    async def _validate_upload(self, file: UploadFile):
        """Validate uploaded file"""
        
        # Check file size
        size = 0
        chunk_size = 8192  # 8KB chunks
        
        while True:
            chunk = await file.read(chunk_size)
            if not chunk:
                break
            size += len(chunk)
            if size > self.max_size:
                raise HTTPException(status_code=400, detail="File too large")
        
        # Reset file position
        await file.seek(0)
        
        # Validate filename
        if not self._is_filename_safe(file.filename):
            raise HTTPException(status_code=400, detail="Invalid filename")
        
        # Validate extension
        ext = self._get_file_extension(file.filename)
        if ext not in self.allowed_extensions:
            raise HTTPException(status_code=400, detail="File type not allowed")
        
        # Validate content type
        content_type = await self._get_content_type(file)
        if not self._is_content_type_valid(content_type, ext):
            raise HTTPException(status_code=400, detail="Invalid file content")
    
    def _is_filename_safe(self, filename: str) -> bool:
        """Check if filename is safe"""
        if not filename:
            return False
        
        # Check length
        if len(filename) > secure_settings.upload.MAX_FILENAME_LENGTH:
            return False
        
        # Check for dangerous characters
        dangerous_chars = r'[<>:"/\\|?*\x00-\x1F]'
        if re.search(dangerous_chars, filename):
            return False
        
        # Check for common dangerous patterns
        dangerous_patterns = [
            r"\.\.+",  # Path traversal
            r"^\.+",   # Hidden files
            r"^~",     # Temp files
            r"^CON$|^PRN$|^AUX$|^NUL$|^COM\d$|^LPT\d$",  # Reserved names
        ]
        
        return not any(re.search(pattern, filename, re.I) for pattern in dangerous_patterns)
    
    def _get_file_extension(self, filename: str) -> str:
        """Get file extension in lowercase"""
        return Path(filename).suffix.lower()
    
    async def _get_content_type(self, file: UploadFile) -> str:
        """Get actual file content type using magic numbers"""
        chunk = await file.read(2048)  # Read first 2KB for magic number check
        await file.seek(0)  # Reset position
        
        mime = magic.Magic(mime=True)
        return mime.from_buffer(chunk)
    
    def _is_content_type_valid(self, content_type: str, extension: str) -> bool:
        """Validate content type matches extension"""
        allowed_extensions = self.content_types.get(content_type, [])
        return extension in allowed_extensions
    
    def _generate_secure_filename(self, original_filename: str) -> str:
        """Generate secure filename"""
        # Get extension
        ext = self._get_file_extension(original_filename)
        
        # Generate random filename
        random_name = secrets.token_hex(16)
        
        return f"{random_name}{ext}"
    
    async def _save_file_secure(self, file: UploadFile, file_path: Path) -> str:
        """Save file securely and return SHA-256 hash"""
        sha256_hash = hashlib.sha256()
        
        try:
            async with aiofiles.open(file_path, 'wb') as f:
                while chunk := await file.read(8192):  # 8KB chunks
                    sha256_hash.update(chunk)
                    await f.write(chunk)
            
            # Set secure permissions (600 - only owner can read/write)
            os.chmod(file_path, 0o600)
            
            return sha256_hash.hexdigest()
            
        except Exception as e:
            # Clean up on error
            if file_path.exists():
                file_path.unlink()
            raise HTTPException(status_code=500, detail="Failed to save file securely")
    
    async def _verify_saved_file(self, file_path: Path, expected_hash: str):
        """Verify saved file integrity"""
        sha256_hash = hashlib.sha256()
        
        try:
            async with aiofiles.open(file_path, 'rb') as f:
                while chunk := await f.read(8192):  # 8KB chunks
                    sha256_hash.update(chunk)
            
            if sha256_hash.hexdigest() != expected_hash:
                # Clean up corrupted file
                file_path.unlink()
                raise HTTPException(status_code=500, detail="File integrity check failed")
                
        except Exception as e:
            logger.error(f"File verification error: {e}")
            raise HTTPException(status_code=500, detail="Failed to verify file") 