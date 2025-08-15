"""Add learning system tables

Revision ID: add_learning_tables
Revises: 
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import sqlite

# revision identifiers, used by Alembic.
revision = 'add_learning_tables'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Create learned_patterns table
    op.create_table('learned_patterns',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('vendor', sa.String(length=50), nullable=False),
        sa.Column('model', sa.String(length=100), nullable=False),
        sa.Column('data_category', sa.String(length=50), nullable=False),
        sa.Column('successful_oids', sa.JSON(), nullable=False),
        sa.Column('oid_patterns', sa.JSON(), nullable=True),
        sa.Column('success_rate', sa.Float(), nullable=True),
        sa.Column('discovery_count', sa.Integer(), nullable=True),
        sa.Column('last_successful', sa.DateTime(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_learned_patterns_data_category'), 'learned_patterns', ['data_category'], unique=False)
    op.create_index(op.f('ix_learned_patterns_id'), 'learned_patterns', ['id'], unique=False)
    op.create_index(op.f('ix_learned_patterns_model'), 'learned_patterns', ['model'], unique=False)
    op.create_index(op.f('ix_learned_patterns_vendor'), 'learned_patterns', ['vendor'], unique=False)

    # Create discovery_strategies table
    op.create_table('discovery_strategies',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('vendor', sa.String(length=50), nullable=False),
        sa.Column('model', sa.String(length=100), nullable=True),
        sa.Column('strategy_name', sa.String(length=50), nullable=False),
        sa.Column('data_category', sa.String(length=50), nullable=False),
        sa.Column('success_count', sa.Integer(), nullable=True),
        sa.Column('failure_count', sa.Integer(), nullable=True),
        sa.Column('avg_discovery_time', sa.Float(), nullable=True),
        sa.Column('last_used', sa.DateTime(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
        sa.Column('is_preferred', sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_discovery_strategies_data_category'), 'discovery_strategies', ['data_category'], unique=False)
    op.create_index(op.f('ix_discovery_strategies_id'), 'discovery_strategies', ['id'], unique=False)
    op.create_index(op.f('ix_discovery_strategies_model'), 'discovery_strategies', ['model'], unique=False)
    op.create_index(op.f('ix_discovery_strategies_strategy_name'), 'discovery_strategies', ['strategy_name'], unique=False)
    op.create_index(op.f('ix_discovery_strategies_vendor'), 'discovery_strategies', ['vendor'], unique=False)

    # Create device_capabilities table
    op.create_table('device_capabilities',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('device_ip', sa.String(length=45), nullable=False),
        sa.Column('vendor', sa.String(length=50), nullable=False),
        sa.Column('model', sa.String(length=100), nullable=False),
        sa.Column('sys_object_id', sa.String(length=200), nullable=True),
        sa.Column('sys_descr', sa.Text(), nullable=True),
        sa.Column('capabilities', sa.JSON(), nullable=False),
        sa.Column('discovered_sensors', sa.JSON(), nullable=True),
        sa.Column('last_discovery', sa.DateTime(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_device_capabilities_device_ip'), 'device_capabilities', ['device_ip'], unique=False)
    op.create_index(op.f('ix_device_capabilities_id'), 'device_capabilities', ['id'], unique=False)
    op.create_index(op.f('ix_device_capabilities_model'), 'device_capabilities', ['model'], unique=False)
    op.create_index(op.f('ix_device_capabilities_vendor'), 'device_capabilities', ['vendor'], unique=False)

    # Create discovery_history table
    op.create_table('discovery_history',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('device_ip', sa.String(length=45), nullable=False),
        sa.Column('vendor', sa.String(length=50), nullable=False),
        sa.Column('model', sa.String(length=100), nullable=False),
        sa.Column('data_category', sa.String(length=50), nullable=False),
        sa.Column('strategy_used', sa.String(length=50), nullable=False),
        sa.Column('oids_tried', sa.JSON(), nullable=True),
        sa.Column('successful_oids', sa.JSON(), nullable=True),
        sa.Column('discovery_time', sa.Float(), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('discovered_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_discovery_history_data_category'), 'discovery_history', ['data_category'], unique=False)
    op.create_index(op.f('ix_discovery_history_device_ip'), 'discovery_history', ['device_ip'], unique=False)
    op.create_index(op.f('ix_discovery_history_id'), 'discovery_history', ['id'], unique=False)
    op.create_index(op.f('ix_discovery_history_model'), 'discovery_history', ['model'], unique=False)
    op.create_index(op.f('ix_discovery_history_vendor'), 'discovery_history', ['vendor'], unique=False)

    # Create adaptive_learning_config table
    op.create_table('adaptive_learning_config',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('config_key', sa.String(length=100), nullable=False),
        sa.Column('config_value', sa.JSON(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('config_key')
    )
    op.create_index(op.f('ix_adaptive_learning_config_config_key'), 'adaptive_learning_config', ['config_key'], unique=True)
    op.create_index(op.f('ix_adaptive_learning_config_id'), 'adaptive_learning_config', ['id'], unique=False)


def downgrade():
    op.drop_index(op.f('ix_adaptive_learning_config_id'), table_name='adaptive_learning_config')
    op.drop_index(op.f('ix_adaptive_learning_config_config_key'), table_name='adaptive_learning_config')
    op.drop_table('adaptive_learning_config')
    op.drop_index(op.f('ix_discovery_history_vendor'), table_name='discovery_history')
    op.drop_index(op.f('ix_discovery_history_model'), table_name='discovery_history')
    op.drop_index(op.f('ix_discovery_history_id'), table_name='discovery_history')
    op.drop_index(op.f('ix_discovery_history_device_ip'), table_name='discovery_history')
    op.drop_index(op.f('ix_discovery_history_data_category'), table_name='discovery_history')
    op.drop_table('discovery_history')
    op.drop_index(op.f('ix_device_capabilities_vendor'), table_name='device_capabilities')
    op.drop_index(op.f('ix_device_capabilities_model'), table_name='device_capabilities')
    op.drop_index(op.f('ix_device_capabilities_id'), table_name='device_capabilities')
    op.drop_index(op.f('ix_device_capabilities_device_ip'), table_name='device_capabilities')
    op.drop_table('device_capabilities')
    op.drop_index(op.f('ix_discovery_strategies_vendor'), table_name='discovery_strategies')
    op.drop_index(op.f('ix_discovery_strategies_strategy_name'), table_name='discovery_strategies')
    op.drop_index(op.f('ix_discovery_strategies_model'), table_name='discovery_strategies')
    op.drop_index(op.f('ix_discovery_strategies_id'), table_name='discovery_strategies')
    op.drop_index(op.f('ix_discovery_strategies_data_category'), table_name='discovery_strategies')
    op.drop_table('discovery_strategies')
    op.drop_index(op.f('ix_learned_patterns_vendor'), table_name='learned_patterns')
    op.drop_index(op.f('ix_learned_patterns_model'), table_name='learned_patterns')
    op.drop_index(op.f('ix_learned_patterns_id'), table_name='learned_patterns')
    op.drop_index(op.f('ix_learned_patterns_data_category'), table_name='learned_patterns')
    op.drop_table('learned_patterns') 