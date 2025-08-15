"""Dummy migration to restore Alembic chain

Revision ID: 20250127_add_compliance_tables
Revises: 1a1640fe7e37
Create Date: 2025-01-27 09:59:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '20250127_add_compliance_tables'
down_revision = '1a1640fe7e37'
branch_labels = None
depends_on = None

def upgrade():
    # This migration is intentionally left blank.
    pass

def downgrade():
    # This migration is intentionally left blank.
    pass 