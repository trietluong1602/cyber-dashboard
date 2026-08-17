"""Extract/transform stage for NIST NVD CVE enrichment (CVSS, severity, CWE)."""

import logging
import time
from datetime import date, datetime

import requests

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 30

# NVD's public rate limit (no API key) is roughly 5 requests per 30s.
# Sleeping between calls keeps a full run from getting throttled/blocked.
REQUEST_DELAY_SECONDS = 6


class NVDExtractError(Exception):
    """Raised for errors during the NVD extract stage (network, HTTP, shape)."""
    pass


class NVDTransformError(Exception):
    """Raised when an NVD record cannot be converted to model fields."""
    pass


def fetch_cve(cve_id, api_key=None):
    """Fetch a single CVE record from the NVD API.

    Returns:
        The raw `cve` dict for this CVE.

    Raises:
        NVDExtractError: on network failure, bad status, or unusable structure.
    """
    headers = {"apiKey": api_key} if api_key else {}

    try:
        response = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id},
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        raise NVDExtractError(f"{cve_id}: could not retrieve NVD record: {exc}") from exc
    except ValueError as exc:
        raise NVDExtractError(f"{cve_id}: NVD response was not valid JSON: {exc}") from exc

    vulnerabilities = payload.get("vulnerabilities")
    if not vulnerabilities:
        raise NVDExtractError(f"{cve_id}: no NVD record found")

    return vulnerabilities[0]["cve"]


def _clean_text(value):
    return (value or "").strip()


def _parse_date(value):
    """NVD timestamps look like '2026-03-01T14:22:10.123'; keep only the date."""
    value = _clean_text(value)
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).date()
    except ValueError:
        return None


def _english(items, text_key="value"):
    """Pull the English-language entry out of an NVD lang-tagged list."""
    return next(
        (item[text_key] for item in items if item.get("lang") == "en"),
        None,
    )


def _extract_cvss(metrics):
    """NVD may publish several CVSS versions at once. Prefer the newest."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            cvss_data = entries[0]["cvssData"]
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity") or entries[0].get("baseSeverity")
            return score, severity
    return None, None


def transform_record(raw):
    """Convert one raw NVD `cve` dict into NvdEnrichment field values.

    Returns a dict keyed by model field names, ready for update_or_create.
    Raises NVDTransformError if the record has no usable CVE id.
    """
    cve_id = _clean_text(raw.get("id"))
    if not cve_id:
        raise NVDTransformError("record is missing 'id'")

    descriptions = raw.get("descriptions", [])
    nvd_description = _english(descriptions) or ""

    cvss_score, severity = _extract_cvss(raw.get("metrics", {}))

    weaknesses = raw.get("weaknesses", [])
    cwe_id = ""
    if weaknesses:
        cwe_id = _english(weaknesses[0].get("description", [])) or ""

    return {
        "cve_id": cve_id,
        "nvd_description": nvd_description,
        "cvss_score": cvss_score,
        "severity": severity or "",
        "cwe_id": cwe_id,
        "published_date": _parse_date(raw.get("published")),
        "modified_date": _parse_date(raw.get("lastModified")),
    }


def fetch_and_transform(cve_ids, api_key=None, delay=REQUEST_DELAY_SECONDS):
    """Fetch + transform NVD data for a list of CVE IDs, one request at a time.

    A single CVE failing (missing from NVD, malformed) is collected as an
    error rather than aborting the whole batch — matching the CISA
    importer's "one bad row shouldn't cost you the rest" behavior.

    Returns:
        (cleaned, errors) where cleaned is a list of field dicts (cve_id
        included) and errors is a list of (cve_id, message).
    """
    cleaned = []
    errors = []

    for i, cve_id in enumerate(cve_ids):
        try:
            raw = fetch_cve(cve_id, api_key=api_key)
            row = transform_record(raw)
        except (NVDExtractError, NVDTransformError) as exc:
            errors.append((cve_id, str(exc)))
            logger.warning("Skipped %s: %s", cve_id, exc)
        else:
            cleaned.append(row)

        if i < len(cve_ids) - 1:
            time.sleep(delay)

    logger.info("NVD: transformed %d records, skipped %d", len(cleaned), len(errors))
    return cleaned, errors