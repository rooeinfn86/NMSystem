"""add missing columns v2

Revision ID: add_missing_columns_v2
Revises: add_missing_columns
Create Date: 2024-05-01 06:30:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_missing_columns_v2'
down_revision = 'add_missing_columns'
branch_labels = None
depends_on = None

def column_exists(table_name, column_name):
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = [col['name'] for col in inspector.get_columns(table_name)]
    return column_name in columns

def upgrade():
    # Add missing columns to cis_compliance_reports table if they don't exist
    if not column_exists('cis_compliance_reports', 'compliance_type'):
        op.add_column('cis_compliance_reports', sa.Column('compliance_type', sa.String(50), nullable=True))
    
    if not column_exists('cis_compliance_reports', 'export_path'):
        op.add_column('cis_compliance_reports', sa.Column('export_path', sa.String(512), nullable=True))
    
    if not column_exists('cis_compliance_reports', 'tags'):
        op.add_column('cis_compliance_reports', sa.Column('tags', sa.ARRAY(sa.String(50)), nullable=True))
    
    if not column_exists('cis_compliance_reports', 'version'):
        op.add_column('cis_compliance_reports', sa.Column('version', sa.Integer(), nullable=False, server_default='1'))
    
    if not column_exists('cis_compliance_reports', 'is_deleted'):
        op.add_column('cis_compliance_reports', sa.Column('is_deleted', sa.Boolean(), nullable=False, server_default='false'))
    
    if not column_exists('cis_compliance_reports', 'overall_score'):
        op.add_column('cis_compliance_reports', sa.Column('overall_score', sa.Float(), nullable=True))

def downgrade():
    # Remove columns from cis_compliance_reports table if they exist
    if column_exists('cis_compliance_reports', 'compliance_type'):
        op.drop_column('cis_compliance_reports', 'compliance_type')
    
    if column_exists('cis_compliance_reports', 'export_path'):
        op.drop_column('cis_compliance_reports', 'export_path')
    
    if column_exists('cis_compliance_reports', 'tags'):
        op.drop_column('cis_compliance_reports', 'tags')
    
    if column_exists('cis_compliance_reports', 'version'):
        op.drop_column('cis_compliance_reports', 'version')
    
    if column_exists('cis_compliance_reports', 'is_deleted'):
        op.drop_column('cis_compliance_reports', 'is_deleted')
    
    if column_exists('cis_compliance_reports', 'overall_score'):
        op.drop_column('cis_compliance_reports', 'overall_score') 