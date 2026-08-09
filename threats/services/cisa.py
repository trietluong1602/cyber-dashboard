"""Extract stage for the CISA Known Exploited Vulnerabilities catalog."""

import logging
from datetime import date, datetime, timezone

import requests

logger = logging.getLogger(__name__)

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
REQUEST_TIMEOUT = 30

class KEVExtractError(Exception):
    """Exception raised for errors during the CISA KEV extract stage."""
    pass

class KEVTransformError(Exception):
    """Raised when a KEV record cannot be converted to model fields."""
    pass

def fetch_kev_catalog(url=KEV_FEED_URL):
    """Fetch and validate the KEV feed.

    Returns:
        (records, metadata) where records is the list of vulnerability
        dicts and metadata carries provenance for the dashboard.

    Raises:
        KEVExtractError: on network failure or unusable structure.
    """
    fetched_at = datetime.now(timezone.utc)

    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        raise KEVExtractError(f"Could not retrieve KEV feed: {exc}") from exc
    except ValueError as exc:
        raise KEVExtractError(f"KEV feed was not a valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise KEVExtractError(
            f"Expected a JSON object at the top level, got {type(payload).__name__}"
        )

    if "vulnerabilities" not in payload:
        raise KEVExtractError(
            f"KEV payload has no 'vulnerabilities' key; found: {sorted(payload)}"
        )

    records = payload["vulnerabilities"]

    if not isinstance(records, list):
        raise KEVExtractError(
            f"Expected a list of vulnerabilities, got {type(records).__name__}"
        )

    metadata = {
        "fetched_at": fetched_at,
        "catalog_version": payload.get("catalogVersion"),
        "date_released": payload.get("dateReleased"),
        "count": payload.get("count"),      # CISA's claim; may be None
        "record_count": len(records),       # what we actually received
    }

    if metadata["count"] is None:
        logger.warning("KEV payload omitted 'count'; skipping integrity check")
    elif metadata["count"] != metadata["record_count"]:
        logger.warning(
            "KEV catalog 'count' (%d) does not match records received (%d)",
            metadata["count"],
            metadata["record_count"],
        )

    logger.info("Extracted %d KEV records", len(records))
    return records, metadata

def _clean_text(value):
    """Normalize a text field: None becomes empty string, whitespace trimmed."""
    return (value or "").strip()


def _parse_date(value, field_name, cve_id=""):
    """Parse an ISO date string. Empty or missing returns None."""
    value = _clean_text(value)
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise KEVTransformError(
            f"{cve_id or '<unknown CVE>'}: could not parse {field_name} {value!r}"
        ) from exc

def transform_record(record):
    """Convert one raw KEV record into Vulnerability field values.

    Returns a dict keyed by model field names, ready for update_or_create.
    Raises KEVTransformError if a required field is missing or unparseable.
    """
    cve_id = _clean_text(record.get("cveID"))
    if not cve_id:
        raise KEVTransformError("record is missing 'cveID'")

    date_added = _parse_date(record.get("dateAdded"), "dateAdded", cve_id)
    if date_added is None:
        raise KEVTransformError(f"{cve_id}: missing required 'dateAdded'")

    # TODO (CP2): 'notes' holds the NVD detail URL; 'cwes' is a list
    # and needs its own model. Both are intentionally dropped for v0.1.

    return {
        "cve_id": cve_id,
        "vendor": _clean_text(record.get("vendorProject")),
        "product": _clean_text(record.get("product")),
        "vulnerability_name": _clean_text(record.get("vulnerabilityName")),
        "date_added": date_added,
        "description": _clean_text(record.get("shortDescription")),
        "required_action": _clean_text(record.get("requiredAction")),
        "due_date": _parse_date(record.get("dueDate"), "dueDate", cve_id),
        "known_ransomware_use": _clean_text(record.get("knownRansomwareCampaignUse")) == "Known",
    }

def transform_records(records):
    """Transform a list of raw records, skipping unusable and duplicate ones.

    Returns (cleaned, errors) where errors is a list of (index, message).
    Guarantees every cve_id in `cleaned` is unique.
    """
    cleaned = []
    errors = []
    seen = set()

    for index, record in enumerate(records):
        try:
            row = transform_record(record)
        except KEVTransformError as exc:
            errors.append((index, str(exc)))
            logger.warning("Skipped record %d: %s", index, exc)
            continue

        # A CVE appearing twice means the source contradicts itself. Keep the
        # first occurrence and report the rest rather than letting
        # update_or_create silently overwrite.
        if row["cve_id"] in seen:
            message = f"{row['cve_id']}: duplicate CVE ID in source feed"
            errors.append((index, message))
            logger.warning("Skipped record %d: %s", index, message)
            continue

        seen.add(row["cve_id"])
        cleaned.append(row)

    logger.info("Transformed %d records, skipped %d", len(cleaned), len(errors))
    return cleaned, errors