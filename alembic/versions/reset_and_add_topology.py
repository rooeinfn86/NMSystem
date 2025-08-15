"""reset and add topology tables

Revision ID: reset_and_add_topology
Revises: None
Create Date: 2024-03-19 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'reset_and_add_topology'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Drop existing alembic_version table if it exists
    op.execute('DROP TABLE IF EXISTS alembic_version')
    
    # Create new alembic_version table
    op.create_table(
        'alembic_version',
        sa.Column('version_num', sa.String(length=32), nullable=False),
        sa.PrimaryKeyConstraint('version_num')
    )
    
    # Insert current version
    op.execute("INSERT INTO alembic_version (version_num) VALUES ('reset_and_add_topology')")
    
    # Create device_topology table
    op.create_table(
        'device_topology',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('device_id', sa.Integer(), nullable=False),
        sa.Column('network_id', sa.Integer(), nullable=False),
        sa.Column('hostname', sa.String(), nullable=True),
        sa.Column('vendor', sa.String(), nullable=True),
        sa.Column('model', sa.String(), nullable=True),
        sa.Column('uptime', sa.Integer(), nullable=True),
        sa.Column('last_polled', sa.DateTime(), nullable=True),
        sa.Column('health_data', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_device_topology_id'), 'device_topology', ['id'], unique=False)

    # Create interface_topology table
    op.create_table(
        'interface_topology',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('device_id', sa.Integer(), nullable=False),
        sa.Column('interface_index', sa.Integer(), nullable=True),
        sa.Column('name', sa.String(), nullable=True),
        sa.Column('admin_status', sa.String(), nullable=True),
        sa.Column('oper_status', sa.String(), nullable=True),
        sa.Column('speed', sa.Integer(), nullable=True),
        sa.Column('mac_address', sa.String(), nullable=True),
        sa.Column('last_polled', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['device_id'], ['device_topology.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_interface_topology_id'), 'interface_topology', ['id'], unique=False)

    # Create neighbor_topology table
    op.create_table(
        'neighbor_topology',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('device_id', sa.Integer(), nullable=False),
        sa.Column('local_interface', sa.String(), nullable=True),
        sa.Column('neighbor_id', sa.String(), nullable=True),
        sa.Column('neighbor_port', sa.String(), nullable=True),
        sa.Column('neighbor_platform', sa.String(), nullable=True),
        sa.Column('discovery_protocol', sa.String(), nullable=True),
        sa.Column('last_polled', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['device_id'], ['device_topology.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_neighbor_topology_id'), 'neighbor_topology', ['id'], unique=False)

def downgrade():
    op.drop_index(op.f('ix_neighbor_topology_id'), table_name='neighbor_topology')
    op.drop_table('neighbor_topology')
    op.drop_index(op.f('ix_interface_topology_id'), table_name='interface_topology')
    op.drop_table('interface_topology')
    op.drop_index(op.f('ix_device_topology_id'), table_name='device_topology')
    op.drop_table('device_topology')
    op.drop_table('alembic_version') 