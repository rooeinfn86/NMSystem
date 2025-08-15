"""Add agent tables

Revision ID: 20250127_add_agent_tables
Revises: 20250127_add_compliance_tables
Create Date: 2025-01-27 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20250127_add_agent_tables'
down_revision = '20250127_add_compliance_tables'
branch_labels = None
depends_on = None


def upgrade():
    # Create agents table
    op.create_table('agents',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('company_id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('agent_token', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=True),
        sa.Column('last_heartbeat', sa.DateTime(), nullable=True),
        sa.Column('capabilities', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('version', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['company_id'], ['companies.id'], ),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_agents_id'), 'agents', ['id'], unique=False)
    
    # Create unique constraint on agent_token
    op.create_unique_constraint('uq_agents_token', 'agents', ['agent_token'])
    
    # Create agent_network_access table
    op.create_table('agent_network_access',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('agent_id', sa.Integer(), nullable=False),
        sa.Column('network_id', sa.Integer(), nullable=False),
        sa.Column('company_id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['company_id'], ['companies.id'], ),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_agent_network_access_id'), 'agent_network_access', ['id'], unique=False)
    
    # Create unique constraint on agent_id and network_id
    op.create_unique_constraint('uq_agent_network', 'agent_network_access', ['agent_id', 'network_id'])


def downgrade():
    # Drop agent_network_access table
    op.drop_constraint('uq_agent_network', 'agent_network_access', type_='unique')
    op.drop_index(op.f('ix_agent_network_access_id'), table_name='agent_network_access')
    op.drop_table('agent_network_access')
    
    # Drop agents table
    op.drop_constraint('uq_agents_token', 'agents', type_='unique')
    op.drop_index(op.f('ix_agents_id'), table_name='agents')
    op.drop_table('agents') 