"""Add company API tokens

Revision ID: 20250127_add_company_api_tokens
Revises: 20250127_add_agent_tables
Create Date: 2025-01-27 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20250127_add_company_api_tokens'
down_revision = '20250127_add_agent_tables'
branch_labels = None
depends_on = None


def upgrade():
    # Create company_api_tokens table
    op.create_table('company_api_tokens',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('company_id', sa.Integer(), nullable=False),
        sa.Column('token_hash', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('created_by', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('last_used', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['company_id'], ['companies.id'], ),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_company_api_tokens_id'), 'company_api_tokens', ['id'], unique=False)
    
    # Create unique constraint on token_hash
    op.create_unique_constraint('uq_company_api_tokens_hash', 'company_api_tokens', ['token_hash'])


def downgrade():
    # Drop company_api_tokens table
    op.drop_constraint('uq_company_api_tokens_hash', 'company_api_tokens', type_='unique')
    op.drop_index(op.f('ix_company_api_tokens_id'), table_name='company_api_tokens')
    op.drop_table('company_api_tokens') 