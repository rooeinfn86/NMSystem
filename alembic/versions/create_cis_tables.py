"""create cis tables

Revision ID: create_cis_tables
Revises: 
Create Date: 2024-05-01 07:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'create_cis_tables'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Create cis_compliance_reports table
    op.create_table(
        'cis_compliance_reports',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('company_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('report_name', sa.String(), nullable=False),
        sa.Column('original_filename', sa.String(), nullable=False),
        sa.Column('file_path', sa.String(), nullable=False),
        sa.Column('file_type', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('overall_score', sa.Float(), nullable=True),
        sa.Column('compliance_type', sa.String(50), nullable=True),
        sa.Column('export_path', sa.String(512), nullable=True),
        sa.Column('tags', sa.ARRAY(sa.String(50)), nullable=True),
        sa.Column('version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id')
    )

    # Create cis_benchmarks table
    op.create_table(
        'cis_benchmarks',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('benchmark_id', sa.String(), nullable=False),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('category', sa.String(), nullable=False),
        sa.Column('severity', sa.String(), nullable=False),
        sa.Column('recommendation', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('benchmark_id')
    )

    # Create cis_compliance_findings table
    op.create_table(
        'cis_compliance_findings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('report_id', sa.Integer(), nullable=False),
        sa.Column('benchmark_id', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('recommendation', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(20), nullable=True),
        sa.Column('evidence', sa.Text(), nullable=True),
        sa.Column('mitigation', sa.Text(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['benchmark_id'], ['cis_benchmarks.id'], ),
        sa.ForeignKeyConstraint(['report_id'], ['cis_compliance_reports.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create cis_compliance_report_history table
    op.create_table(
        'cis_compliance_report_history',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('report_id', sa.Integer(), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('changes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('created_by', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['report_id'], ['cis_compliance_reports.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create cis_compliance_history table
    op.create_table(
        'cis_compliance_history',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('company_id', sa.Integer(), nullable=False),
        sa.Column('report_id', sa.Integer(), nullable=False),
        sa.Column('benchmark_id', sa.Integer(), nullable=False),
        sa.Column('previous_status', sa.String(), nullable=True),
        sa.Column('current_status', sa.String(), nullable=False),
        sa.Column('change_date', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('change_reason', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['benchmark_id'], ['cis_benchmarks.id'], ),
        sa.ForeignKeyConstraint(['company_id'], ['companies.id'], ),
        sa.ForeignKeyConstraint(['report_id'], ['cis_compliance_reports.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

def downgrade():
    op.drop_table('cis_compliance_history')
    op.drop_table('cis_compliance_report_history')
    op.drop_table('cis_compliance_findings')
    op.drop_table('cis_benchmarks')
    op.drop_table('cis_compliance_reports') 