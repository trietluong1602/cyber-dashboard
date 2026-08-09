"""Load stage: persist model-ready records into the database."""

import logging

from django.db import transaction

from threats.models import Vulnerability

logger = logging.getLogger(__name__)


@transaction.atomic
def load_records(cleaned):
    """Upsert transformed records into Vulnerability.

    Idempotent: rerunning with the same input updates rather than duplicates.

    Returns:
        dict with created/updated counts.
    """
    created_count = 0
    updated_count = 0

    for row in cleaned:
        defaults = {k: v for k, v in row.items() if k != "cve_id"}

        obj, created = Vulnerability.objects.update_or_create(
            cve_id=row["cve_id"],
            defaults=defaults,
        )

        if created:
            created_count += 1
        else:
            updated_count += 1

    logger.info(
        "Loaded %d records: %d created, %d updated",
        len(cleaned), created_count, updated_count,
    )

    return {
        "created": created_count,
        "updated": updated_count,
        "total": len(cleaned),
    }