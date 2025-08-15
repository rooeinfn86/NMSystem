"""make speed nullable

Revision ID: make_speed_nullable
Revises: add_topology_tables
Create Date: 2024-06-11 04:05:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'make_speed_nullable'
down_revision = 'add_topology_tables'
branch_labels = None
depends_on = None


def upgrade():
    # Make speed column nullable
    op.alter_column('interface_topology', 'speed',
                    existing_type=sa.Integer(),
                    nullable=True)


def downgrade():
    # Make speed column non-nullable again
    op.alter_column('interface_topology', 'speed',
                    existing_type=sa.Integer(),
                    nullable=False) 