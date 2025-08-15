"""add_compliance_feature

Revision ID: e2aaca949d5c
Revises: fix_compliance_timestamps
Create Date: 2025-05-19 11:42:44.037796

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e2aaca949d5c'
down_revision: Union[str, None] = 'fix_compliance_timestamps'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
