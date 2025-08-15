"""add_missing_columns_to_findings

Revision ID: ee9d33125eaf
Revises: c33b0a5ecdc9
Create Date: 2025-05-01 12:05:18.771704

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from datetime import datetime


# revision identifiers, used by Alembic.
revision: str = 'ee9d33125eaf'
down_revision: Union[str, None] = 'c33b0a5ecdc9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add mitigation column if it doesn't exist
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'cis_compliance_findings' 
                AND column_name = 'mitigation'
            ) THEN
                ALTER TABLE cis_compliance_findings ADD COLUMN mitigation TEXT;
            END IF;
        END
        $$;
    """)

    # Add last_updated column if it doesn't exist
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'cis_compliance_findings' 
                AND column_name = 'last_updated'
            ) THEN
                ALTER TABLE cis_compliance_findings ADD COLUMN last_updated TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP;
            END IF;
        END
        $$;
    """)


def downgrade() -> None:
    """Downgrade schema."""
    # Remove the columns if they exist
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'cis_compliance_findings' 
                AND column_name = 'mitigation'
            ) THEN
                ALTER TABLE cis_compliance_findings DROP COLUMN mitigation;
            END IF;
        END
        $$;
    """)

    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'cis_compliance_findings' 
                AND column_name = 'last_updated'
            ) THEN
                ALTER TABLE cis_compliance_findings DROP COLUMN last_updated;
            END IF;
        END
        $$;
    """)
