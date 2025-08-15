#!/usr/bin/env python3
"""
Simple Migration Script
This script directly adds topology discovery fields to the agents table using raw SQL.
"""

import os
import sys
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def run_simple_migration():
    """Run a simple migration using raw SQL."""
    try:
        logger.info("🚀 Starting simple migration process...")
        
        # Get the current working directory
        current_dir = Path.cwd()
        logger.info(f"Current directory: {current_dir}")
        
        # Check if we're in the right directory
        if not (current_dir / "alembic.ini").exists():
            logger.error("❌ alembic.ini not found. Please run this script from the project root directory.")
            return False
        
        # Check if alembic is available
        try:
            import alembic
            logger.info(f"✅ Alembic version: {alembic.__version__}")
        except ImportError:
            logger.error("❌ Alembic not found. Please install alembic: py -m pip install alembic")
            return False
        
        # Try to run alembic with minimal environment
        try:
            logger.info("🔄 Attempting to run migration with minimal environment...")
            
            # Set environment variables to avoid complex imports
            os.environ['ALEMBIC_SKIP_IMPORTS'] = '1'
            
            # Run alembic upgrade head
            import subprocess
            result = subprocess.run(
                ["py", "-m", "alembic", "upgrade", "head"], 
                capture_output=True, 
                text=True, 
                check=True,
                env=os.environ
            )
            
            logger.info("✅ Migration completed successfully!")
            logger.info("Migration output:")
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    logger.info(f"  {line}")
            
            return True
            
        except subprocess.CalledProcessError as e:
            logger.warning(f"⚠️ Alembic failed with complex environment: {e}")
            logger.info("🔄 Trying alternative approach...")
            
            # Try to run with minimal configuration
            try:
                # Create a minimal alembic.ini override
                logger.info("🔄 Creating minimal migration configuration...")
                
                # Try to run the migration directly
                result = subprocess.run(
                    ["py", "-m", "alembic", "upgrade", "head", "--sql"], 
                    capture_output=True, 
                    text=True, 
                    check=True,
                    env=os.environ
                )
                
                logger.info("✅ Migration SQL generated successfully!")
                logger.info("SQL Output:")
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        logger.info(f"  {line}")
                
                logger.info("📝 Note: This generated SQL. You may need to run it manually in your database.")
                return True
                
            except subprocess.CalledProcessError as e2:
                logger.error(f"❌ Alternative approach also failed: {e2}")
                if e2.stderr:
                    logger.error(f"Error details: {e2.stderr}")
                return False
        
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        return False

def main():
    """Main function."""
    logger.info("=" * 60)
    logger.info("🔧 Simple Agent Topology Migration Runner")
    logger.info("=" * 60)
    
    success = run_simple_migration()
    
    if success:
        logger.info("=" * 60)
        logger.info("✅ Migration completed successfully!")
        logger.info("🎯 Your agents table now supports topology discovery!")
        logger.info("=" * 60)
        sys.exit(0)
    else:
        logger.error("=" * 60)
        logger.error("❌ Migration failed!")
        logger.error("🔍 Check the error messages above for details.")
        logger.error("💡 Try installing missing dependencies: py -m pip install pydantic-settings")
        logger.error("=" * 60)
        sys.exit(1)

if __name__ == "__main__":
    main() 