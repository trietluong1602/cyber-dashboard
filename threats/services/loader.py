"""Load stage: persist model-ready records into the database."""

import logging

from django.db import transaction

from threats.models import NvdEnrichment, Vulnerability

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


@transaction.atomic
def load_enrichments(cleaned):
    """Upsert transformed NVD records into NvdEnrichment.

    Each row is keyed by cve_id. If no Vulnerability exists yet for that
    CVE (an NVD-only CVE we've never seen from CISA), one is created with
    just the fields NVD gives us — the KEV-only fields stay null until/
    unless CISA reports it later.

    Idempotent: rerunning with the same input updates rather than duplicates.

    Returns:
        dict with created/updated counts, plus how many Vulnerability
        rows had to be created from scratch (nvd_only_created).
    """
    created_count = 0
    updated_count = 0
    nvd_only_created = 0

    for row in cleaned:
        cve_id = row["cve_id"]
        enrichment_fields = {k: v for k, v in row.items() if k != "cve_id"}

        vulnerability, vuln_created = Vulnerability.objects.get_or_create(
            cve_id=cve_id,
            defaults={
                "vendor": "",
                "product": "",
                "vulnerability_name": "",
                "description": enrichment_fields.get("nvd_description", ""),
            },
        )
        if vuln_created:
            nvd_only_created += 1
            logger.info("%s: no existing KEV row, created bare Vulnerability", cve_id)

        obj, created = NvdEnrichment.objects.update_or_create(
            vulnerability=vulnerability,
            defaults=enrichment_fields,
        )

        if created:
            created_count += 1
        else:
            updated_count += 1

    logger.info(
        "Loaded %d NVD enrichments: %d created, %d updated (%d Vulnerability rows created)",
        len(cleaned), created_count, updated_count, nvd_only_created,
    )

    return {
        "created": created_count,
        "updated": updated_count,
        "nvd_only_created": nvd_only_created,
        "total": len(cleaned),
    }