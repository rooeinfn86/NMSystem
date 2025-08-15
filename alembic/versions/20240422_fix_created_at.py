"""fix created at

Revision ID: 20240422_fix_created_at
Revises: 
Create Date: 2024-04-22 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '20240422_fix_created_at'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Update the timestamp columns to be timezone-aware
    op.execute("""
        ALTER TABLE cis_compliance_reports 
        ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE,
        ALTER COLUMN updated_at TYPE TIMESTAMP WITH TIME ZONE;
    """)
    
    # Set default values to use local timezone
    op.execute("""
        ALTER TABLE cis_compliance_reports 
        ALTER COLUMN created_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'America/Los_Angeles'),
        ALTER COLUMN updated_at SET DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'America/Los_Angeles');
    """)
    
    # Convert existing timestamps to local timezone
    op.execute("""
        UPDATE cis_compliance_reports 
        SET created_at = created_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Los_Angeles',
            updated_at = updated_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Los_Angeles';
    """)

def downgrade():
    # Revert back to UTC
    op.execute("""
        ALTER TABLE cis_compliance_reports 
        ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE,
        ALTER COLUMN updated_at TYPE TIMESTAMP WITHOUT TIME ZONE,
        ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP,
        ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP;
    """)
    
    # Convert existing timestamps back to UTC
    op.execute("""
        UPDATE cis_compliance_reports 
        SET created_at = created_at AT TIME ZONE 'America/Los_Angeles' AT TIME ZONE 'UTC',
            updated_at = updated_at AT TIME ZONE 'America/Los_Angeles' AT TIME ZONE 'UTC';
    """) 