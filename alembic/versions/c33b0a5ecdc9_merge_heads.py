"""merge heads

Revision ID: c33b0a5ecdc9
Revises: add_compliance_type, add_missing_columns_v2, create_cis_tables
Create Date: 2025-05-01 12:03:43.460952

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c33b0a5ecdc9'
down_revision: Union[str, None] = ('add_compliance_type', 'add_missing_columns_v2', 'create_cis_tables')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
