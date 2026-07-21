import os
import json
import time
import zipfile
import requests
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import orjson
from packaging.version import Version, InvalidVersion
import pandas as pd
from urllib.parse import quote
import threading
import re
import matplotlib.pyplot as plt
import numpy as np
from cvss import CVSS3, CVSS2
from scipy.stats import wilcoxon, norm, kruskal
from itertools import combinations
import scikit_posthocs as sp

# =====================================
# Config & Constants
# =====================================

# All file paths are configurable and should be adjusted to the local environment.

# Path to the downloaded OSV full database archive (all.zip).
# The dataset can be obtained from the official OSV data dump:
# https://google.github.io/osv.dev/data/#full-database-download
OSV_PATH = "path/to/osv/all.zip"

# Path to the local cache file storing fetched release metadata
# (version-level timestamps retrieved from PyPI, npm, and Maven registries).
RELEASE_CACHE_PATH = "path/to/cache/release_cache.json"

# Path to the processed vulnerability cache that combines normalized
# OSV data with computed version-level vulnerability states and severity.
VULN_CACHE_PATH = "path/to/cache/vulnerability_cache.json"

ALLOWED_ECOSYSTEMS = {"PyPI", "npm", "Maven"}

_thread_local = threading.local()

MAX_WORKERS = {
    "PyPI": 8,
    "npm": 20,
    "Maven": 12
}

START_YEAR = 2015

FORCE_REBUILD_RELEASE_CACHE = False
FORCE_REBUILD_FINAL_CACHE = False

CVSS_RE = re.compile(r"^CVSS:(?P<ver>2\.0|3\.0|3\.1)/", re.IGNORECASE)

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)

# =====================================
# Utilities
# =====================================
def parse_version(v):
    """
    Parse a version string into a packaging.version.Version object.

    :param v: Version identifier as a string or other object convertible to string.
    :return: Parsed Version object if valid, otherwise None.
    """
    if not v:
        return None
    s = str(v).strip()
    if s.startswith("v") and len(s) > 1 and s[1].isdigit():
        s = s[1:]
    try:
        return Version(s)
    except InvalidVersion:
        return None

def sort_versions(version_strings):
    """
    Sort a list of version strings according to semantic version ordering.

    :param version_strings: Iterable of version identifiers as strings.
    :return: List of version strings sorted in ascending semantic order.
    """
    parsed = []
    for s in version_strings:
        v = parse_version(s)
        if v:
            parsed.append((v, s))
    parsed.sort(key=lambda x: x[0])
    return [s for _, s in parsed]

def severity_bucket(score):
    """
    Map a numeric CVSS severity score to a categorical severity bucket.

    :param score: Numeric CVSS severity score (float) or None.
    :return: Severity bucket as a string, or None if input is None.
    """
    if score is None:
        return None
    if score < 4:
        return "Low"
    if score < 7:
        return "Medium"
    if score < 9:
        return "High"
    return "Critical"

def cvss_vector_to_score(score_str):
    """
    Convert a CVSS score representation to a numeric severity score.

    :param score_str: CVSS score representation (string, numeric, or vector).
    :return: Numeric CVSS score as float, or None if parsing fails.
    """
    if score_str is None:
        return None

    try:
        return float(score_str)
    except Exception:
        pass

    s = str(score_str).strip()

    sev_map = {
        "LOW": 3.9,
        "MODERATE": 6.9,
        "MEDIUM": 6.9,
        "HIGH": 8.9,
        "CRITICAL": 9.8
    }
    key = s.upper()
    if key in sev_map:
        return float(sev_map[key])

    if not CVSS_RE.match(s):
        return None

    try:
        if s.upper().startswith("CVSS:3"):
            return float(CVSS3(s).scores()[0])
        if s.upper().startswith("CVSS:2"):
            return float(CVSS2(s).scores()[0])
    except Exception:
        return None

    return None

def parse_date_iso_z(s):
    """
    Parse an ISO-8601 timestamp string with an optional 'Z' (UTC) suffix.

    :param s: ISO-8601 formatted timestamp string (e.g., '2023-05-01T12:34:56Z').
    :return: timezone-aware datetime object, or None if parsing fails.
    """
    if not isinstance(s, str) or not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None

# =====================================
# OSV ingest
# =====================================
def load_osv_zip(zip_path):
    """
    Load and parse all OSV vulnerability JSON files from a ZIP archive.

    :param zip_path: Path to the OSV ZIP archive containing vulnerability records.
    :return: List of parsed OSV vulnerability objects as dictionaries.
    """
    vulns = []

    with zipfile.ZipFile(zip_path, "r") as z:
        files = [f.filename for f in z.infolist() if f.filename.endswith(".json")]

        def load_file(name):
            try:
                return orjson.loads(z.read(name))
            except:
                return None

        with ThreadPoolExecutor(max_workers=16) as ex:
            for res in tqdm(ex.map(load_file, files), total=len(files), desc="Loading OSV"):
                if res:
                    vulns.append(res)

    return vulns

def filter_ecosystem(vulns):
    """
    Filter OSV vulnerability records to include only selected ecosystems.

    :param vulns: List of OSV vulnerability objects.
    :return: List of vulnerabilities affecting at least one allowed ecosystem.
    """
    filtered = []
    for v in vulns:
        for a in v.get("affected", []):
            eco = a.get("package", {}).get("ecosystem")
            if eco in ALLOWED_ECOSYSTEMS:
                filtered.append(v)
                break
    return filtered

# =====================================
# Severity
# =====================================
def extract_best_severity(vuln, affected=None):
    """
    Determine the highest available severity score for a vulnerability entry.

    :param vuln: OSV vulnerability object containing global severity information.
    :param affected: Optional affected-package entry with package-specific severity data.
    :return: Tuple of (severity_score, severity_type, raw_severity_value, source_level),
             or (None, None, None, None) if no valid severity is found.
    """
    def iter_severities(obj):
        for sev in obj.get("severity", []) or []:
            t = sev.get("type")
            sc = sev.get("score")
            yield t, sc

    candidates = []

    if affected and isinstance(affected, dict) and affected.get("severity"):
        for t, sc in iter_severities(affected):
            score = cvss_vector_to_score(sc)
            if score is not None:
                candidates.append((score, t, sc, "affected"))

    if vuln.get("severity"):
        for t, sc in iter_severities(vuln):
            score = cvss_vector_to_score(sc)
            if score is not None:
                candidates.append((score, t, sc, "vuln"))

    ds = vuln.get("database_specific") or {}
    if isinstance(ds, dict) and ds:
        ds_sev = ds.get("severity")
        score = cvss_vector_to_score(ds_sev)
        if score is not None:
            candidates.append((score, "DATABASE_SPECIFIC", ds_sev, "db_specific"))

        cvss = ds.get("cvss")
        if isinstance(cvss, dict):
            ds_score = cvss.get("score")
            score2 = cvss_vector_to_score(ds_score)
            if score2 is not None:
                candidates.append((score2, "DB_CVSS_SCORE", ds_score, "db_specific"))

            ds_vec = cvss.get("vector")
            score3 = cvss_vector_to_score(ds_vec)
            if score3 is not None:
                candidates.append((score3, "DB_CVSS_VECTOR", ds_vec, "db_specific"))

    if not candidates:
        return (None, None, None, None)

    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0]

def extract_cve_aliases(vuln):
    """
    Extract CVE IDs from OSV 'aliases' field.
    """
    aliases = vuln.get("aliases") or []
    cves = [a for a in aliases if isinstance(a, str) and CVE_ID_RE.match(a.strip())]
    cves = sorted(set(c.upper() for c in cves))
    return cves

# =====================================
# Normalisation
# =====================================
def normalize_osv_entries(vulns):
    """
    Normalize raw OSV vulnerability records into a structured, version-based format.

    :param vulns: List of filtered OSV vulnerability objects.
    :return: List of normalized vulnerability entries with version ranges and severity metadata.
    """
    normalized = []

    for v in vulns:
        cve_ids = extract_cve_aliases(v)
        has_cve = len(cve_ids) > 0

        for aff in v.get("affected", []):
            pkg = aff.get("package", {})
            eco = pkg.get("ecosystem")
            name = pkg.get("name")

            if eco not in ALLOWED_ECOSYSTEMS:
                continue

            best_score, best_type, raw_value, sev_src = extract_best_severity(v, aff)

            versions = aff.get("versions", [])
            added = False

            for r in aff.get("ranges", []):
                current_intro = None
                for evt in r.get("events", []):
                    if "introduced" in evt:
                        current_intro = evt["introduced"]

                    elif "fixed" in evt and current_intro is not None:
                        normalized.append({
                            "ecosystem": eco,
                            "package_name": name,
                            "introduced_version": current_intro,
                            "fixed_version": evt["fixed"],
                            "vulnerable_versions": versions,
                            "severity_score": best_score,
                            "severity_type": best_type,
                            "severity_raw": raw_value,
                            "severity_source_level": sev_src,  # affected/vuln
                            "vuln_source": "range",
                            "has_cve": has_cve,
                            "cve_ids": cve_ids
                        })
                        added = True
                        current_intro = None

                    elif "limit" in evt and current_intro is not None:
                        lim = evt["limit"]
                        if isinstance(lim, str) and "*" in lim:
                            normalized.append({
                                "ecosystem": eco,
                                "package_name": name,
                                "introduced_version": current_intro,
                                "fixed_version": None,
                                "fixed_like_type": "open",
                                "vulnerable_versions": versions,
                                "severity_score": best_score,
                                "severity_type": best_type,
                                "severity_raw": raw_value,
                                "severity_source_level": sev_src,
                                "vuln_source": "range_open",
                                "has_cve": has_cve,
                                "cve_ids": cve_ids
                            })
                        else:
                            normalized.append({
                                "ecosystem": eco,
                                "package_name": name,
                                "introduced_version": current_intro,
                                "fixed_version": lim,  # treated as fixed-like boundary
                                "fixed_like_type": "limit",
                                "vulnerable_versions": versions,
                                "severity_score": best_score,
                                "severity_type": best_type,
                                "severity_raw": raw_value,
                                "severity_source_level": sev_src,
                                "vuln_source": "range",
                                "has_cve": has_cve,
                                "cve_ids": cve_ids
                            })
                        added = True
                        current_intro = None

                    elif "last_affected" in evt and current_intro is not None:
                        normalized.append({
                            "ecosystem": eco,
                            "package_name": name,
                            "introduced_version": current_intro,
                            "fixed_version": evt["last_affected"],  # marker, we’ll convert to next release later
                            "fixed_like_type": "last_affected",
                            "vulnerable_versions": versions,
                            "severity_score": best_score,
                            "severity_type": best_type,
                            "severity_raw": raw_value,
                            "severity_source_level": sev_src,
                            "vuln_source": "range"
                        })
                        added = True
                        current_intro = None

                if current_intro is not None:
                    normalized.append({
                        "ecosystem": eco,
                        "package_name": name,
                        "introduced_version": current_intro,
                        "fixed_version": None,
                        "vulnerable_versions": versions,
                        "severity_score": best_score,
                        "severity_type": best_type,
                        "severity_raw": raw_value,
                        "severity_source_level": sev_src,
                        "vuln_source": "range_open"
                    })
                    added = True

            if not added and len(versions) >= 2:
                normalized.append({
                    "ecosystem": eco,
                    "package_name": name,
                    "introduced_version": None,
                    "fixed_version": None,
                    "vulnerable_versions": versions,
                    "severity_score": best_score,
                    "severity_type": best_type,
                    "severity_raw": raw_value,
                    "severity_source_level": sev_src,
                    "vuln_source": "versions_list"
                })

    return normalized

def collect_unique_packages(normalized):
    """
    Collect unique package names per ecosystem from normalized vulnerability entries.

    :param normalized: List of normalized vulnerability entries.
    :return: Dictionary mapping ecosystems to sets of unique package names.
    """
    pkgs = {eco: set() for eco in ALLOWED_ECOSYSTEMS}
    for e in normalized:
        pkgs[e["ecosystem"]].add(e["package_name"])
    return pkgs

# =====================================
# Vuln version compute
# =====================================
def compute_vulnerable_versions(entry, all_versions):
    """
    Determine which package versions are vulnerable based on introduction and fix ranges.

    :param entry: Normalized vulnerability entry describing affected version ranges.
    :param all_versions: Sorted list of all known released versions of the package.
    :return: Set of version strings identified as vulnerable.
    """
    intro = entry.get("introduced_version")
    end = entry.get("fixed_version")
    fixed_like = entry.get("fixed_like_type")  # fixed / limit / last_affected / open

    vlist = entry.get("vulnerable_versions", [])
    vuln = set()

    intro_v = parse_version(intro)
    end_v = parse_version(end)

    if intro_v and end_v:
        for v in all_versions:
            vv = parse_version(v)
            if not vv:
                continue
            if fixed_like == "last_affected":
                if intro_v <= vv <= end_v:
                    vuln.add(v)
            else:
                if intro_v <= vv < end_v:
                    vuln.add(v)

    elif intro_v and end is None:
        for v in all_versions:
            vv = parse_version(v)
            if vv and vv >= intro_v:
                vuln.add(v)

    elif intro and intro_v is None and len(vlist) >= 2:
        for v in vlist:
            if parse_version(v):
                vuln.add(v)

    elif not intro and len(vlist) >= 2:
        for v in vlist:
            if parse_version(v):
                vuln.add(v)

    return vuln

# =====================================
# HTTP
# =====================================
def get_session():
    """
    Get or create a thread-local requests session for HTTP reuse across calls.

    :return: requests.Session instance stored in thread-local storage.
    """
    if not hasattr(_thread_local, "session"):
        _thread_local.session = requests.Session()
    return _thread_local.session

def http_get(url, retries=5, headers=None):
    """
    Perform an HTTP GET request with retries and exponential backoff for transient errors.

    :param url: URL to request.
    :param retries: Maximum number of retry attempts for transient failures.
    :param headers: Optional HTTP headers to include in the request.
    :return: requests.Response if a response is obtained, otherwise None.
    """
    for i in range(retries):
        try:
            r = get_session().get(url, timeout=10, headers=headers)

            if r.status_code in (429, 500, 502, 503, 504):
                time.sleep(min(2 ** i, 10))
                continue

            return r
        except:
            time.sleep(min(2 ** i, 10))
    return None

# =====================================
# Release fetchers
# =====================================
def fetch_pypi(pkg):
    """
    Fetch release timestamps for all versions of a PyPI package via the PyPI JSON API.

    :param pkg: PyPI package name.
    :return: Dictionary mapping version string to ISO-8601 release timestamp.
    """
    url = f"https://pypi.org/pypi/{pkg}/json"
    r = http_get(url)
    if not r or r.status_code != 200:
        return {}

    data = r.json()
    out = {}
    for v, files in data.get("releases", {}).items():
        times = [f.get("upload_time_iso_8601") for f in files if f.get("upload_time_iso_8601")]
        if times:
            out[v] = min(times)
    return out

def fetch_npm(pkg):
    """
    Fetch release timestamps for all versions of an npm package via the npm registry.

    :param pkg: npm package name (optionally scoped, e.g., '@scope/name').
    :return: Dictionary mapping version string to ISO-8601 release timestamp.
    """
    safe_pkg = quote(pkg, safe='@/')
    url = f"https://registry.npmjs.org/{safe_pkg}?format=light"

    headers = {
        "User-Agent": "Mozilla/5.0 (Academic research)"
    }

    r = http_get(url, retries=5, headers=headers)
    if not r or r.status_code != 200:
        return {}

    try:
        data = r.json()
    except:
        return {}

    time_map = data.get("time")
    if not isinstance(time_map, dict) or not time_map:
        return {}

    return {v: t for v, t in time_map.items() if v not in {"created", "modified"}}

def fetch_maven(package):
    """
    Fetch release timestamps for all versions of a Maven artifact using Maven Central search.

    :param package: Maven coordinate in the form 'groupId:artifactId'.
    :return: Dictionary mapping version string to ISO-8601 release timestamp (UTC).
    """
    if ":" not in package:
        return {}

    group, artifact = package.split(":", 1)

    base = "https://search.maven.org/solrsearch/select"
    headers = {
        "User-Agent": "Mozilla/5.0 (Academic research)"
    }

    rows = 500
    start = 0
    num_found = None

    result = {}

    while True:
        params = {
            "q": f"g:{group} AND a:{artifact}",
            "core": "gav",
            "rows": rows,
            "start": start,  # ✅ pagination
            "wt": "json"
        }

        try:
            resp = requests.get(
                base,
                params=params,
                headers=headers,
                timeout=10
            )
        except Exception:
            break

        if resp.status_code != 200:
            break

        try:
            data = resp.json()
        except Exception:
            break

        response = data.get("response", {})
        docs = response.get("docs", [])

        if num_found is None:
            num_found = response.get("numFound", 0)

        if not docs:
            break

        for d in docs:
            ver = d.get("v")
            ts = d.get("timestamp")
            if ver and ts:
                dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
                result[ver] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        start += rows

        if num_found is not None and start >= num_found:
            break

    return result

# =====================================
# Caches
# =====================================
def fetch_release_task(eco, pkg, fetcher):
    """
    Wrapper task to fetch release data for a single package and return a consistent tuple.

    :param eco: Ecosystem identifier (e.g., 'PyPI', 'npm', 'Maven').
    :param pkg: Package identifier within the ecosystem.
    :param fetcher: Callable that fetches release data for the given package.
    :return: Tuple (ecosystem, package, release_data_dict).
    """
    try:
        data = fetcher(pkg)
        return eco, pkg, data
    except:
        return eco, pkg, {}

def build_release_cache(unique_packages, path):
    """
    Build or update a release-date cache by fetching release metadata for unseen packages.

    :param unique_packages: Dictionary mapping ecosystems to sets of package names to fetch.
    :param path: File path where the release cache JSON is read from and written to.
    :return: Dictionary containing cached release timestamps per ecosystem and package.
    """
    try:
        with open(path) as f:
            cache = json.load(f)
    except:
        cache = {eco: {} for eco in ALLOWED_ECOSYSTEMS}

    fetchers = {
        "PyPI": fetch_pypi,
        "npm": fetch_npm,
        "Maven": fetch_maven
    }

    for eco in ALLOWED_ECOSYSTEMS:
        pkgs = unique_packages.get(eco, set())

        to_fetch = [
            pkg for pkg in pkgs
            if pkg not in cache.get(eco, {})
        ]

        if not to_fetch:
            continue

        print(f"\nFetching {eco}: {len(to_fetch)} packages")

        with ThreadPoolExecutor(max_workers=MAX_WORKERS[eco]) as ex:
            futures = {
                ex.submit(fetch_release_task, eco, pkg, fetchers[eco]): pkg
                for pkg in to_fetch
            }

            for fut in tqdm(
                    as_completed(futures),
                    total=len(futures),
                    desc=f"Fetching {eco}"
            ):
                eco_r, pkg_r, data = fut.result()
                cache.setdefault(eco_r, {})[pkg_r] = data

    with open(path, "w") as f:
        json.dump(cache, f, indent=2)

    return cache

def build_cache_file(normalized, release_cache, path):
    """
    Combine normalized vulnerability entries with release metadata into a final cache structure.

    :param normalized: List of normalized vulnerability entries.
    :param release_cache: Release metadata cache mapping ecosystems/packages to version timestamps.
    :param path: File path where the final cache JSON is written.
    :return: None.
    """
    final = {eco: {} for eco in ALLOWED_ECOSYSTEMS}

    for e in normalized:
        eco = e["ecosystem"]
        pkg = e["package_name"]

        releases = release_cache.get(eco, {}).get(pkg)
        if not releases:
            continue

        all_versions = sort_versions(releases.keys())
        vuln_versions = compute_vulnerable_versions(e, all_versions)
        if not vuln_versions:
            continue

        pkg_entry = final[eco].setdefault(pkg, {"versions": {}})

        for v in all_versions:
            status = "not_vulnerable"
            if v in vuln_versions:
                status = "vulnerable"
            fixed_like = e.get("fixed_like_type")
            end_v = parse_version(e.get("fixed_version"))

            fixed_target = None
            if fixed_like in {"fixed", "limit"}:
                fixed_target = e.get("fixed_version")

            elif fixed_like == "last_affected" and end_v is not None:
                for vv_str in all_versions:
                    vv = parse_version(vv_str)
                    if vv and vv > end_v:
                        fixed_target = vv_str
                        break

            if fixed_target == v:
                status = "fixed"

            existing = pkg_entry["versions"].get(v)
            if existing is None:
                existing = {"release_date": releases.get(v), "status": status}
                pkg_entry["versions"][v] = existing
            else:
                old = existing.get("status", "not_vulnerable")
                if status == "vulnerable":
                    existing["status"] = "vulnerable"
                elif status == "fixed":
                    if old != "vulnerable":
                        existing["status"] = "fixed"

            if existing["status"] == "vulnerable":
                if e.get("has_cve"):
                    existing["has_cve"] = True
                else:
                    existing.setdefault("has_cve", False)

                if "cve_ids" in e and isinstance(e["cve_ids"], list):
                    existing.setdefault("cve_ids", [])
                    existing["cve_ids"] = sorted(set(existing["cve_ids"]) | set(e["cve_ids"]))

                new_score = e.get("severity_score")
                old_score = existing.get("severity_score")

                if old_score is None and new_score is not None:
                    existing["severity_score"] = new_score
                    existing["severity_type"] = e.get("severity_type")
                    existing["severity_raw"] = e.get("severity_raw")
                    existing["severity_source_level"] = e.get("severity_source_level")

                elif old_score is not None and new_score is not None:
                    if new_score > old_score:
                        existing["severity_score"] = new_score
                        existing["severity_type"] = e.get("severity_type")
                        existing["severity_raw"] = e.get("severity_raw")
                        existing["severity_source_level"] = e.get("severity_source_level")

                bucket = severity_bucket(existing.get("severity_score"))
                existing["severity_bucket"] = bucket if bucket is not None else "Unknown"
                existing["vuln_source"] = e.get("vuln_source")

    with open(path, "w") as f:
        json.dump(final, f, indent=2)

# =====================================
# Exploratory analysis
# =====================================
def ecosystem_summary_table(final_cache):
    """
    Compute per-ecosystem counts of packages and vulnerable/non-vulnerable versions after START_YEAR.

    :param final_cache: Final cache structure mapping ecosystems and packages to version metadata.
    :return: pandas.DataFrame summarizing totals per ecosystem.
    """
    rows = []

    for eco, packages in final_cache.items():
        pkg_count = 0
        vulnerable_versions = 0
        non_vulnerable_versions = 0

        for pkg, pdata in packages.items():
            versions = pdata.get("versions", {})
            pkg_has_valid_version = False

            for v, vdata in versions.items():
                date_str = vdata.get("release_date")
                if not isinstance(date_str, str):
                    continue

                d = parse_date_iso_z(date_str)
                if not d or d.year < START_YEAR:
                    continue

                pkg_has_valid_version = True
                status = vdata.get("status")

                if status == "vulnerable":
                    vulnerable_versions += 1
                else:
                    non_vulnerable_versions += 1

            if pkg_has_valid_version:
                pkg_count += 1

        rows.append({
            "ecosystem": eco,
            "total_packages": pkg_count,
            "vulnerable_versions": vulnerable_versions,
            "non_vulnerable_versions": non_vulnerable_versions
        })

    return pd.DataFrame(rows)

def severity_distribution_table(final_cache):
    """
    Compute per-ecosystem distribution of vulnerable versions across severity buckets after START_YEAR.

    :param final_cache: Final cache structure mapping ecosystems and packages to version metadata.
    :return: pandas.DataFrame with severity-bucket counts per ecosystem.
    """
    rows = []

    for eco, packages in final_cache.items():
        counts = {
            "Low": 0,
            "Medium": 0,
            "High": 0,
            "Critical": 0,
            "Unknown": 0
        }

        for pkg, pdata in packages.items():
            for v, vdata in pdata.get("versions", {}).items():
                if vdata.get("status") != "vulnerable":
                    continue

                date_str = vdata.get("release_date")
                if not isinstance(date_str, str):
                    continue

                d = parse_date_iso_z(date_str)
                if not d or d.year < START_YEAR:
                    continue

                bucket = vdata.get("severity_bucket")
                if bucket in counts:
                    counts[bucket] += 1
                else:
                    counts["Unknown"] += 1

        rows.append({
            "ecosystem": eco,
            "Low": counts["Low"],
            "Medium": counts["Medium"],
            "High": counts["High"],
            "Critical": counts["Critical"],
            "Unknown": counts["Unknown"]
        })

    return pd.DataFrame(rows)

def cve_coverage_by_severity(final_cache, ecosystem="npm", END_YEAR=2025):
    """
    Summarize, per severity bucket, how often vulnerable versions have an associated CVE alias.
    """
    severity_order = ["Low", "Medium", "High", "Critical", "Unknown"]
    counts = {sev: {"N": 0, "HasCVE": 0} for sev in severity_order}

    for pkg, pdata in final_cache.get(ecosystem, {}).items():
        for v, vdata in pdata.get("versions", {}).items():
            if vdata.get("status") != "vulnerable":
                continue

            d = parse_date_iso_z(vdata.get("release_date"))
            if not d or not (START_YEAR <= d.year <= END_YEAR):
                continue

            sev = vdata.get("severity_bucket") or "Unknown"
            if sev not in counts:
                sev = "Unknown"

            counts[sev]["N"] += 1
            if vdata.get("has_cve") is True:
                counts[sev]["HasCVE"] += 1

    rows = []
    for sev in severity_order:
        N = counts[sev]["N"]
        H = counts[sev]["HasCVE"]
        pct = (H / N * 100.0) if N else None
        rows.append({"Ecosystem": ecosystem, "Severity": sev, "N_vuln_versions": N, "N_with_CVE": H, "Pct_with_CVE": pct})

    df = pd.DataFrame(rows)
    return df

# =====================================
# Core metrics
# =====================================
def print_average_update_time_table_extended(final_cache):
    """
    Compute per-ecosystem release interval statistics for vulnerable vs non-vulnerable intervals.

    :param final_cache: Final cache structure mapping ecosystems and packages to version metadata.
    :return: pandas.DataFrame containing mean/median/quantiles and sample sizes per ecosystem/status.
    """
    def round_half_up(x, ndigits=0):
        if x is None:
            return None
        factor = 10 ** ndigits
        return int(x * factor + 0.5) / factor

    def summarize_per_pkg_means(values):

        if not values:
            return {
                "Mean": None,
                "Median": None,
                "Q1": None,
                "Q2": None,
                "N": 0
            }

        arr = np.array(values, dtype=float)

        mean = float(arr.mean())
        median = float(np.median(arr))
        q1 = float(np.percentile(arr, 25))
        q3 = float(np.percentile(arr, 75))

        return {
            "Mean": round_half_up(mean, 2),
            "Median": round_half_up(median, 2),
            "Q1": round_half_up(q1, 2),
            "Q2": round_half_up(q3, 2),
            "N": int(len(arr))
        }

    ecosystems_order = ["PyPI", "npm", "Maven"]
    rows = []

    for eco in ecosystems_order:
        per_pkg_non_vuln_means = []
        per_pkg_vuln_means = []

        for pkg, pdata in final_cache.get(eco, {}).items():
            versions = pdata.get("versions", {})

            dated = []
            for vdata in versions.values():
                d = parse_date_iso_z(vdata.get("release_date"))
                if not d:
                    continue
                if d.year < START_YEAR:
                    continue
                dated.append((d, vdata.get("status")))

            dated.sort(key=lambda x: x[0])
            if len(dated) < 2:
                continue

            pkg_non_vuln_deltas = []
            pkg_vuln_deltas = []

            for i in range(1, len(dated)):
                prev_date, prev_status = dated[i - 1]
                curr_date, _ = dated[i]

                delta_days = (curr_date - prev_date).total_seconds() / 86400.0
                if delta_days < 0:
                    continue

                if prev_status == "vulnerable":
                    pkg_vuln_deltas.append(delta_days)
                else:
                    pkg_non_vuln_deltas.append(delta_days)

            if pkg_non_vuln_deltas:
                per_pkg_non_vuln_means.append(sum(pkg_non_vuln_deltas) / len(pkg_non_vuln_deltas))
            if pkg_vuln_deltas:
                per_pkg_vuln_means.append(sum(pkg_vuln_deltas) / len(pkg_vuln_deltas))

        stats_non = summarize_per_pkg_means(per_pkg_non_vuln_means)
        stats_vuln = summarize_per_pkg_means(per_pkg_vuln_means)

        rows.append({
            "Ecosystem": eco,
            "Status": "Non-vulnerable",
            **stats_non
        })
        rows.append({
            "Ecosystem": eco,
            "Status": "Vulnerable",
            **stats_vuln
        })

    df = pd.DataFrame(rows, columns=["Ecosystem", "Status", "Mean", "Median", "Q1", "Q2", "N"])

    with pd.option_context(
        "display.max_columns", None,
        "display.width", 200,
        "display.max_colwidth", None
    ):
        print("\n=== Release interval stats (days) per ecosystem (per-package weighted) ===")
        print(df.to_string(index=False))

    return df

def severity_update_speed_tables_per_ecosystem(final_cache, END_YEAR=2025):
    """
    Compute per-ecosystem update-speed statistics following vulnerable releases, grouped by severity.

    :param final_cache: Final cache structure mapping ecosystems and packages to version metadata.
    :param END_YEAR: Last year (inclusive) to include in the time window.
    :return: Dictionary mapping ecosystem name to pandas.DataFrame of severity-grouped statistics.
    """
    def round_half_up(x, ndigits=0):
        if x is None:
            return None
        factor = 10 ** ndigits
        return int(x * factor + 0.5) / factor

    def summarize(values):

        if not values:
            return {"Mean": None, "Median": None, "Q1": None, "Q3": None, "N": 0}

        arr = np.array(values, dtype=float)
        mean = float(arr.mean())
        median = float(np.median(arr))
        q1 = float(np.percentile(arr, 25))
        q3 = float(np.percentile(arr, 75))

        return {
            "Mean": round_half_up(mean, 2),
            "Median": round_half_up(median, 2),
            "Q1": round_half_up(q1, 2),
            "Q3": round_half_up(q3, 2),
            "N": int(len(arr))
        }

    severity_order = ["Low", "Medium", "High", "Critical", "Unknown"]
    ecosystems = ["PyPI", "npm", "Maven"]

    out_tables = {}

    for eco in ecosystems:
        per_sev_pkg_means = {sev: [] for sev in severity_order}

        for pkg, pdata in final_cache.get(eco, {}).items():
            versions = pdata.get("versions", {})

            dated = []
            for vdata in versions.values():
                d = parse_date_iso_z(vdata.get("release_date"))
                if not d or not (START_YEAR <= d.year <= END_YEAR):
                    continue

                status = vdata.get("status")
                sev = (vdata.get("severity_bucket") or "Unknown")
                if sev not in severity_order:
                    sev = "Unknown"

                dated.append((d, status, sev))

            dated.sort(key=lambda x: x[0])
            if len(dated) < 2:
                continue

            per_pkg_by_sev = {sev: [] for sev in severity_order}

            for i in range(1, len(dated)):
                prev_date, prev_status, prev_sev = dated[i - 1]
                curr_date, curr_status, _ = dated[i]

                if prev_status != "vulnerable":
                    continue

                if curr_status not in {"vulnerable", "fixed"}:
                    continue

                delta_days = (curr_date - prev_date).total_seconds() / 86400.0
                if delta_days < 0:
                    continue

                per_pkg_by_sev[prev_sev].append(delta_days)

            for sev in severity_order:
                if per_pkg_by_sev[sev]:
                    per_sev_pkg_means[sev].append(
                        sum(per_pkg_by_sev[sev]) / len(per_pkg_by_sev[sev])
                    )

        rows = []
        for sev in severity_order:
            stats = summarize(per_sev_pkg_means[sev])
            rows.append({
                "Ecosystem": eco,
                "Severity": sev,
                **stats
            })

        df = pd.DataFrame(rows, columns=["Ecosystem", "Severity", "Mean", "Median", "Q1", "Q3", "N"])
        out_tables[eco] = df

        with pd.option_context(
            "display.max_columns", None,
            "display.width", 200,
            "display.max_colwidth", None
        ):
            print(f"\n=== Update speed following vulnerable releases by severity ({eco}) "
                  f"(per-package weighted; {START_YEAR}-{END_YEAR}) ===")
            print(df.to_string(index=False))

    return out_tables

# =====================================
# Visualisation
# =====================================
def plot_quarterly_update_speed(final_cache, END_YEAR=2025):
    """
    Plot quarterly average update speed for vulnerable and non-vulnerable intervals per ecosystem
    in ONE figure. Colors stay consistent per ecosystem; vulnerable uses dashed lines.
    """

    def collect(vulnerable_flag):
        rows = []

        for eco in ["PyPI", "npm", "Maven"]:
            for pkg, pdata in final_cache.get(eco, {}).items():
                versions = pdata.get("versions", {})

                dated = []
                for vdata in versions.values():
                    d = parse_date_iso_z(vdata.get("release_date"))
                    if d and START_YEAR <= d.year <= END_YEAR:
                        dated.append((d, vdata.get("status")))

                dated.sort(key=lambda x: x[0])
                if len(dated) < 2:
                    continue

                per_quarter_deltas = {}

                for i in range(1, len(dated)):
                    prev_date, prev_status = dated[i - 1]
                    curr_date, _ = dated[i]

                    delta_days = (curr_date - prev_date).total_seconds() / 86400.0
                    if delta_days < 0:
                        continue

                    is_vuln_interval = (prev_status == "vulnerable")
                    if is_vuln_interval != vulnerable_flag:
                        continue

                    quarter = f"{curr_date.year}-Q{((curr_date.month - 1) // 3) + 1}"
                    per_quarter_deltas.setdefault(quarter, []).append(delta_days)

                for quarter, deltas in per_quarter_deltas.items():
                    rows.append({
                        "ecosystem": eco,
                        "quarter": quarter,
                        "pkg_mean_update_days": sum(deltas) / len(deltas),
                        "package": pkg
                    })

        df = pd.DataFrame(rows)
        if df.empty:
            return df

        df["quarter_dt"] = pd.PeriodIndex(df["quarter"], freq="Q").to_timestamp()

        out = (
            df.groupby(["ecosystem", "quarter_dt"])["pkg_mean_update_days"]
              .mean()
              .reset_index()
              .rename(columns={"pkg_mean_update_days": "update_days"})
        )
        return out

    df_non = collect(vulnerable_flag=False)
    df_vuln = collect(vulnerable_flag=True)

    if df_non.empty and df_vuln.empty:
        print("No data available for quarterly update speed plot.")
        return

    plt.figure()

    ecos = ["PyPI", "npm", "Maven"]

    for eco in ecos:
        eco_df = df_non[df_non["ecosystem"] == eco]
        if eco_df.empty:
            continue
        plt.plot(
            eco_df["quarter_dt"],
            eco_df["update_days"],
            label=f"{eco} (non-vulnerable)",
            linestyle="-"
        )

    for eco in ecos:
        eco_df = df_vuln[df_vuln["ecosystem"] == eco]
        if eco_df.empty:
            continue

        color = None
        for line in plt.gca().get_lines():
            if line.get_label() == f"{eco} (non-vulnerable)":
                color = line.get_color()
                break

        plt.plot(
            eco_df["quarter_dt"],
            eco_df["update_days"],
            label=f"{eco} (vulnerable)",
            linestyle="--",
            color=color
        )

    plt.xlabel("Time")
    plt.ylabel("Average update speed (days)")
    plt.title("")
    plt.legend()
    plt.tight_layout()
    plt.show()

def plot_update_speed_by_severity_per_ecosystem(final_cache, END_YEAR=2025):
    """
    Plot per-ecosystem distributions of update speed following vulnerable releases by severity bucket.

    :param final_cache: Final cache structure mapping ecosystems and packages to version metadata.
    :param END_YEAR: Last year (inclusive) to include in the time window.
    :return: None.
    """
    severity_order = ["Low", "Medium", "High", "Critical", "Unknown"]

    for eco in ["PyPI", "npm", "Maven"]:
        data = {sev: [] for sev in severity_order}

        for pkg, pdata in final_cache.get(eco, {}).items():
            versions = pdata.get("versions", {})

            dated = []
            for vdata in versions.values():
                d = parse_date_iso_z(vdata.get("release_date"))
                if d and START_YEAR <= d.year <= END_YEAR:
                    sev = vdata.get("severity_bucket") or "Unknown"
                    if sev not in severity_order:
                        sev = "Unknown"
                    dated.append((d, vdata.get("status"), sev))

            dated.sort(key=lambda x: x[0])
            if len(dated) < 2:
                continue

            per_pkg_by_sev = {sev: [] for sev in severity_order}

            for i in range(1, len(dated)):
                prev_date, prev_status, prev_sev = dated[i - 1]
                curr_date, curr_status, _ = dated[i]

                if prev_status != "vulnerable":
                    continue

                if curr_status not in {"vulnerable", "fixed"}:
                    continue

                delta_days = (curr_date - prev_date).total_seconds() / 86400.0
                if delta_days < 0:
                    continue

                per_pkg_by_sev[prev_sev].append(delta_days)

            for sev in severity_order:
                if per_pkg_by_sev[sev]:
                    data[sev].append(sum(per_pkg_by_sev[sev]) / len(per_pkg_by_sev[sev]))

        plot_data = [data[sev] for sev in severity_order if data[sev]]
        labels = [sev for sev in severity_order if data[sev]]

        if not plot_data:
            continue

        plt.figure()
        plt.boxplot(plot_data, tick_labels=labels, showfliers=False)
        plt.xlabel("Severity level")
        plt.ylabel("Update speed (days)")
        plt.title("")
        plt.tight_layout()
        plt.show()

# =====================================
# Statistical tests
# =====================================
def _parse_date_iso_z(s):
    """
    Parse an ISO-8601 timestamp string with optional 'Z' suffix into a datetime object.

    :param s: ISO-8601 formatted timestamp string.
    :return: datetime object in UTC, or None if parsing fails.
    """
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None

def plot_update_interval_histogram(final_cache, status="vulnerable", ecosystem=None, end_year=2025, bins=30, max_days=400):
    """
    Plot a histogram of update intervals (in days) to visually assess distribution shape
    and potential non-normality.

    :param final_cache: Final cache structure with version-level metadata.
    :param status: Release status to condition on ('vulnerable' or 'not_vulnerable').
    :param ecosystem: Optional ecosystem filter ('PyPI', 'npm', 'Maven', or None for all).
    :param end_year: Latest release year to include.
    :param bins: Number of histogram bins.
    """
    intervals = []
    ecosystems = [ecosystem] if ecosystem else ["PyPI", "npm", "Maven"]

    for eco in ecosystems:
        for pdata in final_cache.get(eco, {}).values():
            versions = pdata.get("versions", {})

            dated = []
            for vdata in versions.values():
                d = parse_date_iso_z(vdata.get("release_date"))
                if d and START_YEAR <= d.year <= end_year:
                    dated.append((d, vdata.get("status")))

            dated.sort(key=lambda x: x[0])
            if len(dated) < 2:
                continue

            for i in range(1, len(dated)):
                prev_date, prev_status = dated[i - 1]
                curr_date, _ = dated[i]

                if prev_status != status:
                    continue

                delta_days = (curr_date - prev_date).total_seconds() / 86400.0
                if 0 <= delta_days <= max_days:
                    intervals.append(delta_days)

    if not intervals:
        print("No data available for histogram.")
        return

    plt.figure()
    plt.hist(intervals, bins=bins, range=(0, max_days))
    plt.xlim(0, max_days)
    plt.xlabel("Update interval (days)")
    plt.ylabel("Frequency")

    title_status = "vulnerable" if status == "vulnerable" else "non-vulnerable"
    title_eco = ecosystem if ecosystem else "all ecosystems"
    plt.title(f"Distribution of update intervals ({title_status}, {title_eco})")

    plt.tight_layout()
    plt.show()

def _paired_pkg_means(final_cache, eco, start_year=START_YEAR, end_year=2025):
    """
    Compute paired package-level mean update intervals for vulnerable and non-vulnerable releases.

    :param final_cache: Final cache structure with version-level metadata.
    :param eco: Ecosystem identifier ('PyPI', 'npm', or 'Maven').
    :param start_year: Earliest release year to include.
    :param end_year: Latest release year to include.
    :return: Tuple of two NumPy arrays: (vulnerable_means, non_vulnerable_means).
    """
    vuln_means, non_means = [], []

    for _, pdata in final_cache.get(eco, {}).items():
        dated = []
        for vdata in pdata.get("versions", {}).values():
            d = _parse_date_iso_z(vdata.get("release_date"))
            if d and start_year <= d.year <= end_year:
                dated.append((d, vdata.get("status")))

        dated.sort(key=lambda x: x[0])
        if len(dated) < 2:
            continue

        vuln_d, non_d = [], []
        for i in range(1, len(dated)):
            (d0, s0), (d1, _) = dated[i - 1], dated[i]
            delta = (d1 - d0).total_seconds() / 86400.0
            if delta < 0:
                continue
            (vuln_d if s0 == "vulnerable" else non_d).append(delta)

        if vuln_d and non_d:
            vuln_means.append(np.mean(vuln_d))
            non_means.append(np.mean(non_d))

    return np.array(vuln_means), np.array(non_means)

def wilcoxon_presence_test(final_cache, end_year=2025):
    """
    Perform a Wilcoxon signed-rank test comparing update intervals following
    vulnerable versus non-vulnerable releases.

    :param final_cache: Final cache structure with version-level metadata.
    :param end_year: Latest release year to include.
    :return: None (results are printed to stdout).
    """
    print("\n=== Wilcoxon (paired): Update Interval After Vulnerable vs Non-Vulnerable Releases ===")
    for eco in ["PyPI", "npm", "Maven"]:
        vuln, non = _paired_pkg_means(final_cache, eco, START_YEAR, end_year)
        n = len(vuln)
        if n < 10:
            print(f"{eco}: N={n} (too small)")
            continue

        res = wilcoxon(vuln, non, alternative="two-sided")

        W = res.statistic if hasattr(res, "statistic") else res[0]
        p = res.pvalue if hasattr(res, "pvalue") else res[1]

        r = 1 - (2 * W) / (n * (n + 1))  # rank-biserial correlation

        print(
            f"{eco}: N={n} | median(vuln)={np.median(vuln):.2f}d "
            f"median(non)={np.median(non):.2f}d | W={W:.1f} p={p:.3g} r={r:.3f}"
        )

def jonckheere_terpstra_test(groups):
    """
    Compute the Jonckheere–Terpstra trend test statistic.

    :param groups: List of NumPy arrays ordered by increasing category level.
    :return: Tuple (JT_statistic, z_score, two-sided p_value).
    """
    J = 0
    n_total = sum(len(g) for g in groups)

    for i, j in combinations(range(len(groups)), 2):
        for x in groups[i]:
            for y in groups[j]:
                if x < y:
                    J += 1
                elif x == y:
                    J += 0.5

    mean_J = (n_total**2 - sum(len(g)**2 for g in groups)) / 4
    var_J = (n_total**2 * (2*n_total + 3)
             - sum(len(g)**2 * (2*len(g) + 3) for g in groups)) / 72

    z = (J - mean_J) / np.sqrt(var_J)
    p = 2 * (1 - norm.cdf(abs(z)))

    return J, z, p

def jonckheere_severity_test(final_cache, end_year=2025):
    """
    Perform a Jonckheere–Terpstra trend test to assess the relationship
    between vulnerability severity and update interval following
    vulnerable releases.

    :param final_cache: Final cache structure with version-level metadata.
    :param end_year: Latest release year to include.
    :return: None (results are printed to stdout).
    """
    print("\n=== Jonckheere–Terpstra: Severity vs Update Interval (Vulnerable Releases) ===")

    severity_order = ["Low", "Medium", "High", "Critical"]

    for eco in ["PyPI", "npm", "Maven"]:
        data = {sev: [] for sev in severity_order}

        for pdata in final_cache.get(eco, {}).values():
            versions = pdata.get("versions", {})

            dated = []
            for vdata in versions.values():
                d = parse_date_iso_z(vdata.get("release_date"))
                if d and START_YEAR <= d.year <= end_year:
                    dated.append((d, vdata.get("status"), vdata.get("severity_bucket")))

            dated.sort(key=lambda x: x[0])
            if len(dated) < 2:
                continue

            per_pkg = {sev: [] for sev in severity_order}

            for i in range(1, len(dated)):
                (d0, s0, sev0), (d1, _, _) = dated[i - 1], dated[i]
                if s0 != "vulnerable" or sev0 not in severity_order:
                    continue

                delta = (d1 - d0).total_seconds() / 86400.0
                if delta >= 0:
                    per_pkg[sev0].append(delta)

            for sev in severity_order:
                if per_pkg[sev]:
                    data[sev].append(np.mean(per_pkg[sev]))

        groups = [np.array(data[sev]) for sev in severity_order if len(data[sev]) > 0]

        if len(groups) < 3:
            print(f"{eco}: insufficient data for trend test")
            continue

        J, z, p = jonckheere_terpstra_test(groups)

        print(
            f"{eco}: JT={J:.1f} z={z:.2f} p={p:.3g} | "
            + " ".join(f"{sev}:N={len(data[sev])}" for sev in severity_order)
        )

def _pkg_means_by_status(final_cache, status, start_year=START_YEAR, end_year=2025):
    """
    Compute package-level mean update intervals for a given release status
    (vulnerable or non-vulnerable), grouped by ecosystem.

    :param final_cache: Final cache structure with version-level metadata.
    :param status: Release status to condition on ('vulnerable' or 'not_vulnerable').
    :param start_year: Earliest release year to include.
    :param end_year: Latest release year to include.
    :return: Dictionary mapping ecosystems to lists of package-level mean update intervals.
    """
    out = {"PyPI": [], "npm": [], "Maven": []}

    for eco in out:
        for pdata in final_cache.get(eco, {}).values():
            versions = pdata.get("versions", {})

            dated = []
            for vdata in versions.values():
                d = parse_date_iso_z(vdata.get("release_date"))
                if d and start_year <= d.year <= end_year:
                    dated.append((d, vdata.get("status")))

            dated.sort(key=lambda x: x[0])
            if len(dated) < 2:
                continue

            deltas = []
            for i in range(1, len(dated)):
                (d0, s0), (d1, _) = dated[i - 1], dated[i]
                if s0 != status:
                    continue

                delta = (d1 - d0).total_seconds() / 86400.0
                if delta >= 0:
                    deltas.append(delta)

            if deltas:
                out[eco].append(np.mean(deltas))

    return out

def kruskal_ecosystem_test(final_cache, end_year=2025):
    """
    Perform Kruskal–Wallis tests to assess differences in update intervals
    between ecosystems, separately for vulnerable and non-vulnerable releases.

    :param final_cache: Final cache structure with version-level metadata.
    :param end_year: Latest release year to include.
    :return: None (results are printed to stdout).
    """
    print("\n=== Kruskal–Wallis: Ecosystem Differences in Update Interval ===")

    for status in ["vulnerable", "not_vulnerable"]:
        data = _pkg_means_by_status(final_cache, status, START_YEAR, end_year)

        groups = [data["PyPI"], data["npm"], data["Maven"]]
        if any(len(g) < 10 for g in groups):
            print(f"{status}: insufficient data")
            continue

        H, p = kruskal(*groups)

        print(
            f"\nStatus: {status} | "
            f"PyPI:N={len(groups[0])} npm:N={len(groups[1])} Maven:N={len(groups[2])} "
            f"| H={H:.2f} p={p:.3g}"
        )

        if p < 0.05:
            df = pd.DataFrame({
                "update_days": np.concatenate(groups),
                "ecosystem": (
                    ["PyPI"] * len(groups[0]) +
                    ["npm"] * len(groups[1]) +
                    ["Maven"] * len(groups[2])
                )
            })

            posthoc = sp.posthoc_dunn(
                df,
                val_col="update_days",
                group_col="ecosystem",
                p_adjust="holm"
            )

            print("Post-hoc Dunn test (Holm-corrected p-values):")
            print(posthoc.round(4))

# =====================================
# Main
# =====================================
def main():
    """
    Entry point for the thesis research pipeline.

    1) Rebuild release cache + final cache (full rebuild)
    2) Rebuild final cache only (reuse existing release cache when available)
    3) Load final cache and run analysis / plotting
    """
    print("\n=== Thesis Research Pipeline ===\n")
    start = time.time()

    # -------------------------------------------------
    # 1) FULL REBUILD: Release cache + Final cache
    #    Use when you want to refresh EVERYTHING.
    # -------------------------------------------------
    if FORCE_REBUILD_RELEASE_CACHE and FORCE_REBUILD_FINAL_CACHE:
        # OSV ingest -> filter -> normalize
        vulns = load_osv_zip(OSV_PATH)
        filtered = filter_ecosystem(vulns)
        normalized = normalize_osv_entries(filtered)

        # Build release cache from scratch (fetch external registries)
        unique = collect_unique_packages(normalized)
        release_cache = build_release_cache(unique, RELEASE_CACHE_PATH)

        # Build final cache (merge normalized vulns + release dates)
        build_cache_file(normalized, release_cache, VULN_CACHE_PATH)

        print("✅ Caches rebuilt (release cache + final cache).")
        print(f"\n=== Done in {time.time() - start:.2f}s ===\n")
        return

    # -------------------------------------------------
    # 2) FINAL CACHE ONLY: Rebuild final cache
    #    Reuses release cache if it exists; otherwise builds it.
    # -------------------------------------------------
    if FORCE_REBUILD_FINAL_CACHE:
        # OSV ingest -> filter -> normalize
        vulns = load_osv_zip(OSV_PATH)
        filtered = filter_ecosystem(vulns)
        normalized = normalize_osv_entries(filtered)

        # Load release cache if available, otherwise create it
        if os.path.exists(RELEASE_CACHE_PATH):
            with open(RELEASE_CACHE_PATH) as f:
                release_cache = json.load(f)
        else:
            unique = collect_unique_packages(normalized)
            release_cache = build_release_cache(unique, RELEASE_CACHE_PATH)

        # Build final cache (merge normalized vulns + release dates)
        build_cache_file(normalized, release_cache, VULN_CACHE_PATH)

        print("✅ Final cache rebuilt (release cache reused when available).")
        print(f"\n=== Done in {time.time() - start:.2f}s ===\n")
        return

    # -------------------------------------------------
    # 3) ANALYSIS MODE: Load final cache and run analysis
    #    Default mode when no rebuild flags are enabled.
    # -------------------------------------------------
    if not FORCE_REBUILD_RELEASE_CACHE and not FORCE_REBUILD_FINAL_CACHE:
        # Safety check: final cache must exist
        if not os.path.exists(VULN_CACHE_PATH):
            print("thesis_cache_file.json is missing. Set FORCE_REBUILD_FINAL_CACHE=True to build it.")
            return

        # Load final cache
        with open(VULN_CACHE_PATH) as f:
            final_cache = json.load(f)

        # -----------------------------
        # 3A) Exploratory analysis (EDA)
        # -----------------------------
        df_summary = ecosystem_summary_table(final_cache)
        df_sev = severity_distribution_table(final_cache)

        print(f"=== Dataset summary per ecosystem after {START_YEAR} ===")
        print(df_summary)
        print(f"\n=== Severity distribution per ecosystem after {START_YEAR} ===")
        print(df_sev)
        df_cve_npm = cve_coverage_by_severity(final_cache, ecosystem="npm", END_YEAR=2025)
        print("\n=== npm: CVE coverage per severity bucket (vulnerable versions) ===")
        print(df_cve_npm.to_string(index=False))

        # -----------------------------
        # 3B) Core metrics (thesis results)
        # -----------------------------
        print_average_update_time_table_extended(final_cache)
        tables = severity_update_speed_tables_per_ecosystem(final_cache, END_YEAR=2025)
        df_pypi = tables["PyPI"]
        df_npm = tables["npm"]
        df_maven = tables["Maven"]

        # -----------------------------
        # 3C) Visualisations (figures)
        # -----------------------------
        plot_quarterly_update_speed(final_cache, END_YEAR=2025)
        plot_update_speed_by_severity_per_ecosystem(final_cache, END_YEAR=2025)

        # -----------------------------
        # 3D) Statistical tests
        # -----------------------------
        plot_update_interval_histogram(final_cache, status="vulnerable", ecosystem="PyPI", max_days=200)
        plot_update_interval_histogram(final_cache, status="vulnerable", ecosystem="npm", max_days= 200)
        plot_update_interval_histogram(final_cache, status="vulnerable", ecosystem="Maven")
        wilcoxon_presence_test(final_cache, end_year=2025)
        jonckheere_severity_test(final_cache, end_year=2025)
        kruskal_ecosystem_test(final_cache, end_year=2025)

        print(f"\n=== Done in {time.time() - start:.2f}s ===\n")
        return

if __name__ == "__main__":
    main()
