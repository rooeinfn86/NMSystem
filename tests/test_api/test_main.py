import bcrypt
import logging

# Configure test logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Generate password hash for testing
password_hash = bcrypt.hashpw(b"Q!W@E#r4t5", bcrypt.gensalt()).decode()
logger.info(f"Generated password hash: {password_hash}")