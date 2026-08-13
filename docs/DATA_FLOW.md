# Data Flow

How one vulnerability travels from a CISA JSON file to a rendered page. This
document follows a single record, `CVE-2026-20349`, through every stage.

```
CISA feed  ──▶  fetch_kev_catalog  ──▶  transform_records  ──▶  update_or_create  ──▶  views  ──▶  templates
   JSON            validate               normalize              upsert               query        render
```

---

## 0. Entry point

Everything starts with one command:

```bash
python manage.py import_cisa
```

The command lives in `threats/management/commands/import_cisa.py`. It owns the
command-line interface, the console output, and the exit code. It does not own
any parsing logic — that sits in `threats/services/cisa.py`, so it can be tested
without invoking Django's command machinery, and so a second data source can be
added as a sibling module rather than as a branch inside this one.

---

## 1. Extract

`fetch_kev_catalog()` requests the feed:

```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

Before any record is touched, four things are checked:

1. The request completed and returned a 2xx status (`raise_for_status`).
2. The body parsed as JSON.
3. The top level is an object, not a bare list.
4. That object contains a `vulnerabilities` key holding a list.

Any failure raises `KEVExtractError` with a message naming the specific problem.
The principle is that a changed or broken feed should stop the pipeline loudly,
rather than being parsed optimistically into an empty or malformed result.

Alongside the records, the extract stage returns provenance metadata:

| Key | Meaning |
|---|---|
| `fetched_at` | When this run retrieved the feed (UTC) |
| `catalog_version` | CISA's version string for the catalog |
| `date_released` | When CISA published this version |
| `count` | The record count CISA claims |
| `record_count` | The record count actually received |

The last two are compared. A mismatch is logged as a warning rather than raised,
because a truncated feed is worth knowing about but not necessarily worth
discarding.

Our record arrives from the feed looking like this:

```json
{
  "cveID": "CVE-2026-20349",
  "vendorProject": "Cisco",
  "product": "Secure Firewall Adaptive Security Appliance (ASA) and Secure Firewall Threat Defense (FTD) ",
  "vulnerabilityName": "Cisco Secure Firewall ... Heap Inspection Vulnerability",
  "dateAdded": "2026-08-11",
  "shortDescription": "... could allow an unauthenticated, remote attacker to cause the device to reload unexpectedly ...",
  "requiredAction": "Apply mitigations in accordance with vendor instructions ...",
  "dueDate": "2026-08-14",
  "knownRansomwareCampaignUse": "Unknown",
  "notes": "https://sec.cloudapps.cisco.com/... ; https://nvd.nist.gov/vuln/detail/CVE-2026-20349",
  "cwes": ["CWE-244"]
}
```

Three things about this raw record matter downstream:

- The keys are camelCase and do not match the model's field names.
- `product` carries a **trailing space** — real, unedited source messiness.
- `dateAdded` and `dueDate` are **strings**. JSON has no date type, and
  PostgreSQL will not accept a string into a `DateField`.

---

## 2. Transform

`transform_record()` converts one raw dict into model field values.

### Key mapping

| Source key | Model field |
|---|---|
| `cveID` | `cve_id` |
| `vendorProject` | `vendor` |
| `product` | `product` |
| `vulnerabilityName` | `vulnerability_name` |
| `dateAdded` | `date_added` |
| `shortDescription` | `description` |
| `requiredAction` | `required_action` |
| `dueDate` | `due_date` |
| `knownRansomwareCampaignUse` | `known_ransomware_use` |

`notes` and `cwes` are deliberately dropped at v0.1. `notes` holds the NVD
detail URL and `cwes` is a list requiring its own model — both belong to
Checkpoint 2, and the code carries a `TODO` saying so.

### Normalization

**Text** passes through `_clean_text()`, which turns a missing value into an
empty string and trims whitespace. This is what removes the trailing space on
`product`. Without it, `"FTD "` and `"FTD"` would be distinct values in every
vendor and product aggregation.

**Dates** pass through `_parse_date()`, which returns `None` for an empty or
absent value and otherwise calls `date.fromisoformat()`. An unparseable string
raises `KEVTransformError` naming both the field and the CVE, so a skipped
record is actionable rather than anonymous.

**The ransomware field** is reduced to `known_ransomware_use == "Known"`.
This is the one lossy conversion in the pipeline, and it is deliberate:

> CISA's `"Unknown"` means *undetermined*, not *no*. Collapsing to a boolean
> makes the dashboard's KPI query fast and simple, at the cost of conflating
> "not ransomware" with "not yet assessed." The interface compensates by
> labelling the metric **"Known ransomware use"** and rendering the false case
> as a neutral **"Unknown"** badge — never as a green "No."

Any unrecognized future value also maps to `False`, so a new CISA category can
never be silently read as *confirmed* exploitation. There is a test asserting
exactly this.

### Required fields

Two fields are mandatory. A record without a `cveID` has no upsert key and no
URL. A record without a valid `dateAdded` cannot be ordered or counted in the
recency metric. Either absence raises `KEVTransformError`.

### Batch behavior

`transform_records()` wraps the per-record function in a loop and makes a
different choice about failure: instead of propagating the exception, it
collects `(index, message)` into an `errors` list and continues.

This is the asymmetry that shapes the whole pipeline. **An extract failure is
fatal** — with no feed there is nothing to do. **A transform failure is
partial** — one malformed row should not cost you the other 1,661.

The loop also tracks CVE IDs it has already seen. A duplicate within a single
feed means the source contradicts itself, so the first occurrence is kept and
the rest are reported. This guarantees every `cve_id` in the output is unique,
which is precisely the invariant the load stage depends on.

Our record emerges as:

```python
{
    "cve_id": "CVE-2026-20349",
    "vendor": "Cisco",
    "product": "Secure Firewall Adaptive Security Appliance (ASA) and Secure Firewall Threat Defense (FTD)",
    "vulnerability_name": "Cisco Secure Firewall ... Heap Inspection Vulnerability",
    "date_added": datetime.date(2026, 8, 11),
    "description": "...",
    "required_action": "...",
    "due_date": datetime.date(2026, 8, 14),
    "known_ransomware_use": False,
}
```

Trailing space gone, strings now `date` objects, keys now model field names.
The dict is deliberately shaped to be passed straight into the ORM.

---

## 3. Load

Each cleaned dict becomes an upsert:

```python
Vulnerability.objects.update_or_create(
    cve_id=row.pop("cve_id"),
    defaults=row,
)
```

`cve_id` is the lookup; everything else is the payload. If the CVE exists its
fields are refreshed; if not, a row is created.

**Idempotency is enforced at two levels.** The application uses
`update_or_create`, and the database independently enforces `unique=True` on
`cve_id`. The second is what matters: even a buggy pipeline cannot create two
rows for one CVE, because PostgreSQL will refuse.

The observable proof is that a second consecutive run reports
`0 created, 1662 updated`. The command is therefore safe to schedule, safe to
retry, and safe to run twice by accident.

`source_updated_at` is not in the payload. It uses `auto_now`, so Django stamps
it on every save — making it a record of *when this row was last processed by
our pipeline*, distinct from `date_added`, which is CISA's own date. Confusing
those two is a bug the model deliberately prevents.

### Separation of concerns

Source data and user-created data are kept apart by design. Everything in
`Vulnerability` is owned by the ETL and may be overwritten on any run. Analyst
notes and watchlists, arriving at Checkpoint 4, will live in separate models
with foreign keys, so that a refresh can never destroy user work.

---

## 4. Query

`threats/views.py` reads the loaded data. Nothing in the views performs
extraction, transformation, or writes — by the time a request arrives, all the
data work is already done.

**Dashboard** (`threats:dashboard`) runs four aggregate queries: a total count,
a filtered count for confirmed ransomware use, a count of records added within
30 days, and `Max("source_updated_at")` for the freshness indicator.

**List** (`threats:vulnerability_list`) builds a queryset in layers. Search
applies `Q` objects OR'd across `cve_id`, `vendor`, `product`, and
`vulnerability_name` using case-insensitive substring matching. The optional
ransomware filter narrows further. The result is ordered by `-date_added` with
`cve_id` as a tiebreaker — a total ordering is required for stable pagination,
because rows tied on a non-unique sort key can otherwise appear on two pages or
none. `Paginator` then slices 25 rows, and `get_page()` (not `page()`) absorbs
out-of-range and non-integer input rather than raising.

Because querysets are lazy, this layering costs nothing: no SQL executes until
the count and the page slice are evaluated.

**Detail** (`threats:vulnerability_detail`) looks up a single record by
`cve_id` through `get_object_or_404`. The CVE ID is the URL segment rather than
the primary key, because it is stable across database rebuilds, meaningful to a
reader, and already carries the uniqueness constraint a URL lookup needs. An
unknown CVE returns 404, not 500 — a missing record is a missing page, not a
server fault.

---

## 5. Render

Templates extend `base.html` and receive only what the view put in the context.

Text from the feed is auto-escaped by Django. This matters more than it might
seem: descriptions and required actions are attacker-adjacent strings from an
external source that the project does not control. `|safe` is never applied to
ETL-sourced text.

Dates render through the `|date` filter. `source_updated_at` is stored in UTC
and localized in the browser via a `<time>` element carrying an ISO 8601 value,
with the server-rendered string left in place as a fallback.

---

## Failure modes

| Stage | Failure | Behavior |
|---|---|---|
| Extract | Network error, timeout, non-2xx | `KEVExtractError`; run aborts, non-zero exit |
| Extract | Feed is not JSON, or schema changed | `KEVExtractError` naming the structural problem |
| Extract | CISA's `count` disagrees with records received | Logged warning; run continues |
| Transform | Record missing `cveID` or `dateAdded` | Record skipped, error collected, run continues |
| Transform | Unparseable date | Record skipped, error collected, run continues |
| Transform | Duplicate CVE within one feed | First kept, rest reported |
| Load | Duplicate CVE reaches the database | Prevented by `unique=True` |
| View | Unknown CVE requested | HTTP 404 |
| View | Invalid `?page=` value | Clamped to a valid page |

Skipped-record counts are always reported. `--show-errors` prints the detail;
`--dry-run` exercises extract and transform without writing, which is the safe
way to check the pipeline against a changed feed.

---

## What Checkpoint 2 changes

NVD enrichment adds a second source joined on `cve_id`, bringing CVSS scores,
severity ratings, and CWE classifications.

The structure already accommodates it. NVD parsing gets its own module in
`threats/services/`, with its own exception types and its own management
command. The CISA path is not modified. The open design question is whether
CVSS fields belong on `Vulnerability` or in a related model — a question about
source ownership and refresh cadence, not about storage.
