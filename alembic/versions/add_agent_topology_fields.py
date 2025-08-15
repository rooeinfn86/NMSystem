"""Add agent topology discovery fields

Revision ID: add_agent_topology_fields
Revises: 7fe6c3b4da6c
Create Date: 2025-01-27 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'add_agent_topology_fields'
down_revision = '7fe6c3b4da6c'
branch_labels = None
depends_on = None


def upgrade():
    # Add topology discovery fields to agents table
    op.add_column('agents', sa.Column('topology_discovery_status', sa.String(), nullable=True, server_default='idle'))
    op.add_column('agents', sa.Column('last_topology_discovery', sa.DateTime(), nullable=True))
    op.add_column('agents', sa.Column('topology_discovery_config', postgresql.JSON(astext_type=sa.Text()), nullable=True))
    op.add_column('agents', sa.Column('discovered_devices_count', sa.Integer(), nullable=True, server_default='0'))
    op.add_column('agents', sa.Column('topology_last_updated', sa.DateTime(), nullable=True))
    op.add_column('agents', sa.Column('topology_discovery_progress', sa.Integer(), nullable=True, server_default='0'))
    op.add_column('agents', sa.Column('topology_error_message', sa.Text(), nullable=True))


def downgrade():
    # Remove topology discovery fields from agents table
    op.drop_column('agents', 'topology_discovery_status')
    op.drop_column('agents', 'last_topology_discovery')
    op.drop_column('agents', 'topology_discovery_config')
    op.drop_column('agents', 'discovered_devices_count')
    op.drop_column('agents', 'topology_last_updated')
    op.drop_column('agents', 'topology_discovery_progress')
    op.drop_column('agents', 'topology_error_message') 