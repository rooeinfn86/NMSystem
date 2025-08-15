"""Add agent token management fields and audit log

Revision ID: 20250725_agent_token_audit
Revises: 20250127_add_agent_tables
Create Date: 2025-07-25 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20250725_agent_token_audit'
down_revision = '20250127_add_agent_tables'
branch_labels = None
depends_on = None

def upgrade():
    # Add new fields to agents table for token management
    op.add_column('agents', sa.Column('token_status', sa.String(), nullable=False, server_default='active'))
    op.add_column('agents', sa.Column('scopes', postgresql.JSON(astext_type=sa.Text()), nullable=True))
    op.add_column('agents', sa.Column('issued_at', sa.DateTime(), nullable=True))
    op.add_column('agents', sa.Column('expires_at', sa.DateTime(), nullable=True))
    op.add_column('agents', sa.Column('rotated_at', sa.DateTime(), nullable=True))
    op.add_column('agents', sa.Column('revoked_at', sa.DateTime(), nullable=True))
    op.add_column('agents', sa.Column('last_used_at', sa.DateTime(), nullable=True))
    op.add_column('agents', sa.Column('last_used_ip', sa.String(), nullable=True))
    op.add_column('agents', sa.Column('created_by', sa.Integer(), nullable=True))

    # Create agent_token_audit_logs table
    op.create_table(
        'agent_token_audit_logs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('agent_id', sa.Integer(), sa.ForeignKey('agents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('event', sa.String(), nullable=False),  # e.g., 'issued', 'used', 'rotated', 'revoked', 'failed_auth'
        sa.Column('timestamp', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('ip_address', sa.String(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('details', postgresql.JSON(astext_type=sa.Text()), nullable=True),
    )

def downgrade():
    op.drop_table('agent_token_audit_logs')
    op.drop_column('agents', 'token_status')
    op.drop_column('agents', 'scopes')
    op.drop_column('agents', 'issued_at')
    op.drop_column('agents', 'expires_at')
    op.drop_column('agents', 'rotated_at')
    op.drop_column('agents', 'revoked_at')
    op.drop_column('agents', 'last_used_at')
    op.drop_column('agents', 'last_used_ip')
    op.drop_column('agents', 'created_by') 