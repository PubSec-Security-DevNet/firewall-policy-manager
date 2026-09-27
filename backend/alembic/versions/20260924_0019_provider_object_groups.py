"""Allow imported port-service and URL group inventory."""

from alembic import op

revision = "20260924_0019"
down_revision = "20260924_0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("ck_firewall_objects_type", "firewall_objects", type_="check")
    op.create_check_constraint(
        "ck_firewall_objects_type",
        "firewall_objects",
        "object_type IN ('NETWORK','NETWORK_GROUP','PORT_SERVICE','PORT_SERVICE_GROUP',"
        "'URL','URL_GROUP','APPLICATION','APPLICATION_FILTER')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_firewall_objects_type", "firewall_objects", type_="check")
    op.create_check_constraint(
        "ck_firewall_objects_type",
        "firewall_objects",
        "object_type IN ('NETWORK','NETWORK_GROUP','PORT_SERVICE','URL',"
        "'APPLICATION','APPLICATION_FILTER')",
    )
