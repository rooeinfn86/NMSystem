"""Merge company tokens and other branches

Revision ID: a2db2c08f75e
Revises: 20250127_add_company_api_tokens, 7fe6c3b4da6c
Create Date: 2025-07-22 13:13:54.456601

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a2db2c08f75e'
down_revision: Union[str, None] = ('20250127_add_company_api_tokens', '7fe6c3b4da6c')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
