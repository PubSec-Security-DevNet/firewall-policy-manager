"""Remove the unsupported read-only object grant permission."""

from alembic import op

revision = "20261005_0042"
down_revision = "20261005_0041"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DELETE FROM object_use_grants WHERE permission = 'read'")
    op.drop_constraint("ck_object_use_permission", "object_use_grants", type_="check")
    op.create_check_constraint(
        "ck_object_use_permission",
        "object_use_grants",
        "permission IN ('use','modify')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_object_use_permission", "object_use_grants", type_="check")
    op.create_check_constraint(
        "ck_object_use_permission",
        "object_use_grants",
        "permission IN ('read','use','modify')",
    )
