"""fix compliance timestamps

Revision ID: fix_compliance_timestamps
Revises: 20240505_fix_nist_timestamps
Create Date: 2024-05-05 19:15:00.000000

"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime
import pytz

# revision identifiers, used by Alembic.
revision = 'fix_compliance_timestamps'
down_revision = '20240505_fix_nist_timestamps'
branch_labels = None
depends_on = None

def upgrade():
    # First, ensure the columns are timezone-aware
    op.execute("""
        ALTER TABLE compliance_scans 
        ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE,
        ALTER COLUMN updated_at TYPE TIMESTAMP WITH TIME ZONE;
    """)
    
    op.execute("""
        ALTER TABLE compliance_findings 
        ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE,
        ALTER COLUMN updated_at TYPE TIMESTAMP WITH TIME ZONE;
    """)
    
    op.execute("""
        ALTER TABLE compliance_files 
        ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE,
        ALTER COLUMN updated_at TYPE TIMESTAMP WITH TIME ZONE;
    """)
    
    # Update existing timestamps to local timezone
    op.execute("""
        UPDATE compliance_scans 
        SET created_at = created_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Los_Angeles',
            updated_at = updated_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Los_Angeles';
    """)
    
    op.execute("""
        UPDATE compliance_findings 
        SET created_at = created_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Los_Angeles',
            updated_at = updated_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Los_Angeles';
    """)
    
    op.execute("""
        UPDATE compliance_files 
        SET created_at = created_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Los_Angeles',
            updated_at = updated_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Los_Angeles';
    """)
    
    # Set default values to use local timezone
    op.execute("""
        ALTER TABLE compliance_scans 
        ALTER COLUMN created_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'America/Los_Angeles'),
        ALTER COLUMN updated_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'America/Los_Angeles');
    """)
    
    op.execute("""
        ALTER TABLE compliance_findings 
        ALTER COLUMN created_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'America/Los_Angeles'),
        ALTER COLUMN updated_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'America/Los_Angeles');
    """)
    
    op.execute("""
        ALTER TABLE compliance_files 
        ALTER COLUMN created_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'America/Los_Angeles'),
        ALTER COLUMN updated_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'America/Los_Angeles');
    """)

def downgrade():
    # Revert back to UTC
    op.execute("""
        ALTER TABLE compliance_scans 
        ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE,
        ALTER COLUMN updated_at TYPE TIMESTAMP WITHOUT TIME ZONE,
        ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP,
        ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP;
    """)
    
    op.execute("""
        ALTER TABLE compliance_findings 
        ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE,
        ALTER COLUMN updated_at TYPE TIMESTAMP WITHOUT TIME ZONE,
        ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP,
        ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP;
    """)
    
    op.execute("""
        ALTER TABLE compliance_files 
        ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE,
        ALTER COLUMN updated_at TYPE TIMESTAMP WITHOUT TIME ZONE,
        ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP,
        ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP;
    """)
    
    # Convert existing timestamps back to UTC
    op.execute("""
        UPDATE compliance_scans 
        SET created_at = created_at AT TIME ZONE 'America/Los_Angeles' AT TIME ZONE 'UTC',
            updated_at = updated_at AT TIME ZONE 'America/Los_Angeles' AT TIME ZONE 'UTC';
    """)
    
    op.execute("""
        UPDATE compliance_findings 
        SET created_at = created_at AT TIME ZONE 'America/Los_Angeles' AT TIME ZONE 'UTC',
            updated_at = updated_at AT TIME ZONE 'America/Los_Angeles' AT TIME ZONE 'UTC';
    """)
    
    op.execute("""
        UPDATE compliance_files 
        SET created_at = created_at AT TIME ZONE 'America/Los_Angeles' AT TIME ZONE 'UTC',
            updated_at = updated_at AT TIME ZONE 'America/Los_Angeles' AT TIME ZONE 'UTC';
    """) 