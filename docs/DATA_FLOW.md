# Data Flow

How a vulnerability travels from source feeds to a rendered page. This
document follows two records — `CVE-2026-20349` through the CISA path, and
`CVE-2026-8037` through the NVD enrichment path — through every stage.

```
CISA feed  ──▶  fetch_kev_catalog  ──▶  transform_records  ──▶  load_records        ──┐
                   validate               normalize              upsert (Vulnerability) ├──▶ views ──▶ templates
NVD API    ──▶  fetch_and_transform ──▶  transform_record  ──▶  load_enrichments    ──┘
                   per-CVE lookup         normalize              upsert (NvdEnrichment)
```

---

## 0. Entry points

Two independent commands, each owning its own CLI, console output, and exit
code:

```bash
python manage.py import_cisa
python manage.py import_nvd --only-missing --show-errors
```

Neither command owns parsing logic — that sits in `threats/services/cisa.py`
and `threats/services/nvd.py` respectively, each with its own exception types
(`KEVExtractError`/`KEVTransformError` vs `NVDExtractError`/
`NVDTransformError`), so a schema change in one source can never surface as a
bug in the other. Both write through `threats/services/loader.py`, which holds
the two upsert functions (`load_records`, `load_enrichments`) side by side —
the load stage is shared infrastructure; extract and transform are not.

---

## 1. Extract — CISA

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

CISA's own `cwes` field is dropped, not read — Checkpoint 2 sources CWE data
from NVD instead, where it comes with an English-language description rather
than a bare code. See the NVD extract section below.

---

## 2. Transform — CISA

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

`notes` and `cwes` are deliberately dropped. `notes` holds the NVD detail URL,
which is not stored anywhere — a link can always be rebuilt from `cve_id`,
so keeping the raw URL would be redundant data with no independent value.

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

A CVE that only ever comes through NVD never runs through this function at
all, so `known_ransomware_use` stays `NULL` for it — a third state, distinct
from both `True` and `False`, meaning "CISA never evaluated this CVE."

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

## 3. Load — CISA

Each cleaned dict becomes an upsert, via `load_records()`:

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

`source_updated_at` is not in the payload. It uses `auto_now`, so Django stamps
it on every save — making it a record of *when this row was last processed by
this pipeline*, distinct from `date_added`, which is CISA's own date.

---

## 4. Extract — NVD

`import_nvd` does not fetch a bulk feed. It reads the CVE IDs already sitting
in the local database (from CISA, or from an earlier NVD run) and calls
`fetch_cve()` once per ID against:

```
https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<cve_id>
```

The response for `CVE-2026-8037` looks like:

```json
{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2026-8037",
        "published": "2026-06-04T13:15:10.123",
        "lastModified": "2026-08-10T09:22:41.000",
        "descriptions": [
          {"lang": "en", "value": "OS Command Injection Remote Code Execution ..."},
          {"lang": "es", "value": "..."}
        ],
        "metrics": {
          "cvssMetricV31": [
            {"baseSeverity": "CRITICAL", "cvssData": {"baseScore": 9.6, "baseSeverity": "CRITICAL"}}
          ],
          "cvssMetricV2": [
            {"baseSeverity": "HIGH", "cvssData": {"baseScore": 8.3}}
          ]
        },
        "weaknesses": [
          {"description": [{"lang": "en", "value": "CWE-77"}]}
        ]
      }
    }
  ]
}
```

Two structural realities shape the transform step:

- **Multiple CVSS versions can be present at once.** A CVE might carry
  `v2`, `v3.0`, and `v3.1` scores simultaneously, and they don't always agree.
- **Text fields are language-tagged lists**, not single strings — both
  `descriptions` and each weakness's `description` follow this shape.

A CVE with no NVD record at all, or a request that times out, raises
`NVDExtractError`, which `fetch_and_transform()` catches per-CVE — one CVE
failing to fetch does not abort the run against the other 1,000+.

---

## 5. Transform — NVD

`transform_record()` converts one raw `cve` dict into `NvdEnrichment` field
values.

**CVSS selection** tries `cvssMetricV31`, then `cvssMetricV30`, then
`cvssMetricV2`, in that order, and stops at the first one present. This is
the standard "prefer the newest schema" convention security tooling uses when
a CVE carries more than one score. For our record, `v3.1` wins: `9.6`,
`CRITICAL` — the `v2` score of `8.3`/`HIGH` is present in the source but never
reaches the database, by design.

**Description and CWE** are pulled from their respective lang-tagged lists by
filtering for `"lang": "en"`, discarding the Spanish variant and any others.

**Dates** are NVD timestamps with time-of-day
(`"2026-06-04T13:15:10.123"`), parsed with `datetime.fromisoformat()` and
truncated to just the date, since the model fields are `DateField`, not
`DateTimeField`. An unparseable value becomes `None` rather than raising —
missing precision here shouldn't cost the whole record, unlike a missing
`cve_id`, which does raise `NVDTransformError`.

Our record emerges as:

```python
{
    "cve_id": "CVE-2026-8037",
    "nvd_description": "OS Command Injection Remote Code Execution ...",
    "cvss_score": 9.6,
    "severity": "CRITICAL",
    "cwe_id": "CWE-77",
    "published_date": datetime.date(2026, 6, 4),
    "modified_date": datetime.date(2026, 8, 10),
}
```

---

## 6. Load — NVD

`load_enrichments()` upserts against `NvdEnrichment`, keyed on its
`OneToOneField` to `Vulnerability`:

```python
vulnerability, created = Vulnerability.objects.get_or_create(
    cve_id=row["cve_id"],
    defaults={"vendor": "", "product": "", "vulnerability_name": "", ...},
)
NvdEnrichment.objects.update_or_create(
    vulnerability=vulnerability,
    defaults=enrichment_fields,
)
```

For `CVE-2026-8037`, the `Vulnerability` row already exists from
`import_cisa`, so `get_or_create` finds it and only the `NvdEnrichment` row is
written.

If a CVE has no CISA KEV row at all — reachable only through NVD —
`get_or_create` creates a bare `Vulnerability` on the spot, with the
KEV-specific fields left at their nullable defaults. This is the concrete
consequence of a design decision made before any code was written:
`Vulnerability` represents *a CVE*, not *a KEV entry*. `NvdEnrichment` never
has to wait for a `Vulnerability` row to exist first.

**CISA-owned fields are never touched by this function**, and `load_records`
never touches `NvdEnrichment`. Refreshing one source cannot silently
overwrite data owned by the other — this is asserted directly in
`test_loader.py::test_does_not_touch_cisa_owned_fields`, the single most
important test in that file.

Both load functions are idempotent for the same underlying reason:
`update_or_create` plus a database-level uniqueness constraint
(`cve_id` on `Vulnerability`, the `OneToOneField` on `NvdEnrichment`).

---

## 7. Query

`threats/views.py` reads the loaded data. Nothing in the views performs
extraction, transformation, or writes — by the time a request arrives, all the
data work is already done.

**Dashboard** (`threats:dashboard`) runs four aggregate queries: a total count,
a filtered count for confirmed ransomware use, a count of records added within
30 days, and `Max("source_updated_at")` for the freshness indicator.

**List** (`threats:vulnerability_list`) builds a queryset in layers, always
starting from `select_related("nvd")` so that reading `vulnerability.nvd.*`
in the template costs no extra query per row.

*Search* applies `Q` objects OR'd across `cve_id`, `vendor`, `product`,
`vulnerability_name` — and, reaching across the join, `nvd__nvd_description`
and `nvd__cwe_id`. The last two exist specifically so a CVE known only
through NVD (empty vendor/product/name) is still findable — by its CWE
classification or NVD's own description text — rather than invisible to
search. `.distinct()` guards against the join producing duplicate rows in
the result, though the `OneToOneField` makes true duplication unlikely today;
it's there so the filter can grow without silently breaking pagination
counts later.

*Sort* accepts a `?sort=` value checked against a whitelist
(`SORT_OPTIONS`) before ever reaching `order_by()` — a raw pass-through of
user input into `order_by()` would let a request name an arbitrary or
expensive field. `cve_id` is always appended as a tiebreaker, so pagination
stays stable even when many rows share a sort value (e.g. the same
`date_added`).

*Ransomware filter* narrows to `known_ransomware_use=True` when requested.
Note this only ever matches the confirmed-`True` case — rows with `NULL`
(NVD-only CVEs, never evaluated by CISA) are excluded from this filter
entirely, which is correct: they were never confirmed, so they don't belong
in "known ransomware use."

`Paginator` then slices 25 rows, and `get_page()` (not `page()`) absorbs
out-of-range and non-integer input rather than raising.

**Detail** (`threats:vulnerability_detail`) looks up a single record by
`cve_id` through `get_object_or_404`, also with `select_related("nvd")`. The
CVE ID is the URL segment rather than the primary key, because it is stable
across database rebuilds, meaningful to a reader, and already carries the
uniqueness constraint a URL lookup needs. An unknown CVE returns 404, not
500 — a missing record is a missing page, not a server fault.

---

## 8. Render

Templates extend `base.html` and receive only what the view put in the context.

Text from the feed is auto-escaped by Django. This matters more than it might
seem: descriptions and required actions are attacker-adjacent strings from an
external source that the project does not control. `|safe` is never applied to
ETL-sourced text.

`{% if vulnerability.nvd %}` guards the entire NVD enrichment card on the
detail page, and `{% if v.nvd.severity %}` guards the severity badge on the
list page. Both rely on the same mechanism: Django's template engine treats
a `RelatedObjectDoesNotExist` (raised when the reverse `OneToOneField`
lookup finds nothing) as a silent, falsy value rather than propagating the
exception — so a not-yet-enriched CVE degrades to a clear fallback message
("has not yet been enriched... run `import_nvd`") instead of a broken page.

A bare NVD-only row — no `vulnerability_name`, `vendor`, or `product` —
falls back to NVD's own description (truncated) with a small "NVD only"
badge in the list view, so a viewer understands why that row looks different
rather than assuming it's a rendering bug.

Dates render through the `|date` filter. `source_updated_at` is stored in UTC
and localized in the browser via a `<time>` element carrying an ISO 8601 value,
with the server-rendered string left in place as a fallback.

---

## Failure modes

| Stage | Failure | Behavior |
|---|---|---|
| CISA extract | Network error, timeout, non-2xx | `KEVExtractError`; run aborts, non-zero exit |
| CISA extract | Feed is not JSON, or schema changed | `KEVExtractError` naming the structural problem |
| CISA extract | CISA's `count` disagrees with records received | Logged warning; run continues |
| CISA transform | Record missing `cveID` or `dateAdded` | Record skipped, error collected, run continues |
| CISA transform | Unparseable date | Record skipped, error collected, run continues |
| CISA transform | Duplicate CVE within one feed | First kept, rest reported |
| CISA load | Duplicate CVE reaches the database | Prevented by `unique=True` |
| NVD extract | CVE not found in NVD, or request times out | `NVDExtractError` for that CVE only; batch continues |
| NVD transform | Record missing `id` | `NVDTransformError`; batch continues |
| NVD transform | Unparseable `published`/`lastModified` | Field becomes `None`; record still loads |
| NVD load | CVE has no existing `Vulnerability` row | Bare row created automatically |
| View | Unknown CVE requested | HTTP 404 |
| View | Invalid `?page=` value | Clamped to a valid page |
| View | Invalid `?sort=` value | Falls back to `-date_added` |

Skipped-record counts are always reported for both pipelines. `--show-errors`
prints the detail; `--dry-run` exercises extract and transform without
writing, which is the safe way to check either pipeline against a changed
source.

---

## What Checkpoint 3 changes

Analytics MVP reads from the same two tables but adds no new ETL — it's a
query and presentation layer on top of data this checkpoint already loads.
Severity distribution, top vendors, and average CVSS all become aggregate
queries against `Vulnerability`/`NvdEnrichment` (e.g. `values("severity")
.annotate(count=Count("id"))`), rendered as charts rather than table rows.
The open design question is whether those aggregates belong in the view layer
as-is, or behind a small `analytics.py` service module — a question about
where query complexity should live as the dashboard adds more of it, not
about new data.
