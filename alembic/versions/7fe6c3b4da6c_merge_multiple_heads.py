"""merge multiple heads

Revision ID: 7fe6c3b4da6c
Revises: add_learning_tables, eb86cca70377
Create Date: 2025-07-15 19:11:04.013032

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7fe6c3b4da6c'
down_revision: Union[str, None] = ('add_learning_tables', 'eb86cca70377')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
