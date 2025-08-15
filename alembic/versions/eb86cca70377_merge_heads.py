"""merge heads

Revision ID: eb86cca70377
Revises: e2aaca949d5c, make_speed_nullable, reset_and_add_topology
Create Date: 2025-06-10 21:04:51.951542

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'eb86cca70377'
down_revision: Union[str, None] = ('e2aaca949d5c', 'make_speed_nullable', 'reset_and_add_topology')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
