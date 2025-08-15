#!/usr/bin/env python3
"""
Migration Runner Script
This script runs the Alembic migration to add topology discovery fields to the agents table.
"""

import os
import sys
import subprocess
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def run_migration():
    """Run the Alembic migration to add topology fields."""
    try:
        logger.info("🚀 Starting migration process...")
        
        # Get the current working directory
        current_dir = Path.cwd()
        logger.info(f"Current directory: {current_dir}")
        
        # Check if we're in the right directory
        if not (current_dir / "alembic.ini").exists():
            logger.error("❌ alembic.ini not found. Please run this script from the project root directory.")
            return False
        
        # Check if alembic is available
        try:
            result = subprocess.run(
                ["alembic", "--version"], 
                capture_output=True, 
                text=True, 
                check=True
            )
            logger.info(f"✅ Alembic version: {result.stdout.strip()}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.error("❌ Alembic not found. Please install alembic: pip install alembic")
            return False
        
        # Check current migration status
        logger.info("📊 Checking current migration status...")
        result = subprocess.run(
            ["alembic", "current"], 
            capture_output=True, 
            text=True, 
            check=True
        )
        logger.info(f"Current migration: {result.stdout.strip()}")
        
        # Check available migrations
        logger.info("📋 Checking available migrations...")
        result = subprocess.run(
            ["alembic", "history", "--verbose"], 
            capture_output=True, 
            text=True, 
            check=True
        )
        logger.info("Available migrations:")
        for line in result.stdout.strip().split('\n'):
            if 'add_agent_topology_fields' in line:
                logger.info(f"  🎯 {line}")
        
        # Run the migration
        logger.info("🔄 Running migration: add_agent_topology_fields...")
        result = subprocess.run(
            ["alembic", "upgrade", "head"], 
            capture_output=True, 
            text=True, 
            check=True
        )
        
        logger.info("✅ Migration completed successfully!")
        logger.info("Migration output:")
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                logger.info(f"  {line}")
        
        # Verify the migration
        logger.info("🔍 Verifying migration...")
        result = subprocess.run(
            ["alembic", "current"], 
            capture_output=True, 
            text=True, 
            check=True
        )
        logger.info(f"New migration status: {result.stdout.strip()}")
        
        logger.info("🎉 Migration completed successfully! The agents table now has topology discovery fields.")
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Migration failed with error: {e}")
        if e.stderr:
            logger.error(f"Error details: {e.stderr}")
        return False
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        return False

def main():
    """Main function."""
    logger.info("=" * 60)
    logger.info("🔧 Agent Topology Migration Runner")
    logger.info("=" * 60)
    
    success = run_migration()
    
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
        logger.error("=" * 60)
        sys.exit(1)

if __name__ == "__main__":
    main() 