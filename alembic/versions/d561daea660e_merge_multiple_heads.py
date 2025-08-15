"""merge multiple heads

Revision ID: d561daea660e
Revises: 20250725_agent_token_audit, a2db2c08f75e
Create Date: 2025-07-24 18:47:20.175210

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd561daea660e'
down_revision: Union[str, None] = ('20250725_agent_token_audit', 'a2db2c08f75e')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
