"""add compliance_type column

Revision ID: add_compliance_type
Revises: 1a1640fe7e37
Create Date: 2024-05-01 05:30:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_compliance_type'
down_revision = '1a1640fe7e37'
branch_labels = None
depends_on = None

def column_exists(table_name, column_name):
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = [col['name'] for col in inspector.get_columns(table_name)]
    return column_name in columns

def upgrade():
    # Add compliance_type column to cis_compliance_reports table if it doesn't exist
    if not column_exists('cis_compliance_reports', 'compliance_type'):
        op.add_column('cis_compliance_reports', sa.Column('compliance_type', sa.String(50), nullable=True))

def downgrade():
    # Remove compliance_type column from cis_compliance_reports table if it exists
    if column_exists('cis_compliance_reports', 'compliance_type'):
        op.drop_column('cis_compliance_reports', 'compliance_type') 