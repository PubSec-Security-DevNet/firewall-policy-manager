"""Split rule port references into source and destination elements.

Revision ID: 20260920_0011
Revises: 20260920_0010
Create Date: 2026-09-20
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260920_0011"
down_revision: str | None = "20260920_0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint("ck_object_references_element_type", "object_references", type_="check")
    op.create_check_constraint(
        "ck_object_references_element_type",
        "object_references",
        "element_type IN ('UNSPECIFIED','SOURCE_NETWORK','DESTINATION_NETWORK','PORT_SERVICE',"
        "'SOURCE_PORT','DESTINATION_PORT','APPLICATION','URL','MEMBER')",
    )
    op.execute(
        "UPDATE object_references SET element_type = 'DESTINATION_PORT' "
        "WHERE element_type = 'PORT_SERVICE'"
    )


def downgrade() -> None:
    op.execute(
        "UPDATE object_references SET element_type = 'PORT_SERVICE' "
        "WHERE element_type IN ('SOURCE_PORT','DESTINATION_PORT')"
    )
    op.drop_constraint("ck_object_references_element_type", "object_references", type_="check")
    op.create_check_constraint(
        "ck_object_references_element_type",
        "object_references",
        "element_type IN ('UNSPECIFIED','SOURCE_NETWORK','DESTINATION_NETWORK','PORT_SERVICE',"
        "'APPLICATION','URL','MEMBER')",
    )
