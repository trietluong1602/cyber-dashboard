"""Extract stage for the CISA Known Exploited Vulnerabilities catalog."""

import logging
from datetime import datetime, timezone

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
