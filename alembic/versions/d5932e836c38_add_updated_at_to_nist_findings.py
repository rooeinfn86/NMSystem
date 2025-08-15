"""add_updated_at_to_nist_findings

Revision ID: d5932e836c38
Revises: ee9d33125eaf
Create Date: 2025-05-01 17:27:09.727810

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd5932e836c38'
down_revision: Union[str, None] = 'ee9d33125eaf'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
