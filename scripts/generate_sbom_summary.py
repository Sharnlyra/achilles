#!/usr/bin/env python3
"""
Reads a SCANOSS raw scan result file (scanoss-raw.json), builds a condensed,
deterministic statistical summary of it (components, licenses, dependencies),
then asks the Claude API to turn that summary into a readable Markdown
SBOM summary report.

Env vars expected:
  ANTHROPIC_API_KEY    - required, Claude API key
  SCANOSS_RESULT_FILE  - path to the SCANOSS raw JSON results file
  REPO_NAME            - e.g. "my-org/my-repo"           (optional, for header)
  REPO_REF             - e.g. "main"                     (optional, for header)
  COMMIT_SHA           - e.g. "abc1234..."                (optional, for header)
  CLAUDE_MODEL         - override model id (default: claude-sonnet-5)
  REPORT_DETAIL        - "concise" | "standard" | "detailed" (default: standard)
"""

import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

import requests

MAX_COMPONENTS_IN_PROMPT = 60
MAX_SNIPPETS_IN_PROMPT = 40
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"

# Deterministic license risk classification, so the report doesn't rely on
# the model guessing from a license name string. Names are matched
# case-insensitively against SPDX-style identifiers/aliases.
STRONG_COPYLEFT = {
    "gpl-2.0", "gpl-2.0-only", "gpl-2.0-or-later",
    "gpl-3.0", "gpl-3.0-only", "gpl-3.0-or-later",
    "agpl-3.0", "agpl-3.0-only", "agpl-3.0-or-later",
    "sspl-1.0", "osl-3.0", "eupl-1.2",
}
WEAK_COPYLEFT = {
    "lgpl-2.1", "lgpl-2.1-only", "lgpl-2.1-or-later",
    "lgpl-3.0", "lgpl-3.0-only", "lgpl-3.0-or-later",
    "mpl-2.0", "mpl-1.1", "epl-1.0", "epl-2.0", "cddl-1.0", "cddl-1.1",
}
PERMISSIVE = {
    "mit", "apache-2.0", "bsd-2-clause", "bsd-3-clause", "isc",
    "0bsd", "unlicense", "cc0-1.0", "python-2.0", "zlib",
}


def classify_license(name: str) -> str:
    if not name:
        return "unknown"
    key = name.strip().lower()
    if key in STRONG_COPYLEFT:
        return "strong_copyleft"
    if key in WEAK_COPYLEFT:
        return "weak_copyleft"
    if key in PERMISSIVE:
        return "permissive"
    return "unknown"


def worst_risk(risks: list) -> str:
    order = ["strong_copyleft", "weak_copyleft", "unknown", "permissive"]
    for level in order:
        if level in risks:
            return level
    return "unknown"


def load_scan_results(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _extract_license_names(raw_licenses, license_counter=None):
    names = []
    for lic in raw_licenses or []:
        name = lic.get("name") if isinstance(lic, dict) else str(lic)
        if name:
            names.append(name)
            if license_counter is not None:
                license_counter[name] += 1
    return names


def _extract_vulnerabilities(raw_vulns):
    """
    Defensive extraction: SCANOSS only returns vulnerability data when the
    scan is run against an API tier / integration that provides it (e.g.
    Dependency Track). Most default scans will have no 'vulnerabilities'
    key at all - that's different from "zero vulnerabilities found".
    """
    out = []
    for v in raw_vulns or []:
        if not isinstance(v, dict):
            continue
        out.append({
            "id": v.get("id") or v.get("CVE") or v.get("cve") or "UNKNOWN",
            "severity": v.get("severity", "unknown"),
            "source": v.get("source", ""),
        })
    return out


def summarize(results: dict) -> dict:
    """
    SCANOSS raw results are keyed by scanned file path, each holding a list
    of match objects. This walks the structure defensively since fields can
    vary slightly by scan mode (snippet vs dependency matches).
    """
    total_files = len(results)
    matched_files = 0
    components = {}
    dependency_components = {}
    license_counter = Counter()
    snippet_matches = []
    vulnerability_field_seen = False
    all_vulnerabilities = {}  # vuln id -> {id, severity, source, affected: set}

    for filepath, matches in results.items():
        if not matches:
            continue
        for match in matches:
            match_type = match.get("id", "none")  # "file" | "snippet" | "none"
            if match_type and match_type != "none":
                matched_files += 1

            purls = match.get("purl") or []
            purl = purls[0] if purls else None
            vendor = match.get("vendor", "")
            component_name = match.get("component", "")
            version = match.get("version", "")
            license_names = _extract_license_names(
                match.get("licenses") or match.get("license"), license_counter
            )

            if "vulnerabilities" in match:
                vulnerability_field_seen = True
            match_vulns = _extract_vulnerabilities(match.get("vulnerabilities"))

            key = purl or f"{vendor}/{component_name}@{version}"

            if key and match_type != "none" and (purl or component_name or vendor):
                risk_levels = [classify_license(n) for n in license_names] or ["unknown"]
                entry = components.setdefault(key, {
                    "purl": purl,
                    "vendor": vendor,
                    "component": component_name,
                    "version": version,
                    "licenses": set(),
                    "license_risk": "unknown",
                    "vulnerabilities": {},
                    "match_types": set(),
                    "files_matched": 0,
                })
                entry["licenses"].update(license_names)
                entry["license_risk"] = worst_risk(
                    [entry["license_risk"]] + risk_levels
                )
                entry["match_types"].add(match_type)
                entry["files_matched"] += 1
                for v in match_vulns:
                    entry["vulnerabilities"][v["id"]] = v
                    rec = all_vulnerabilities.setdefault(v["id"], {**v, "affected": set()})
                    rec["affected"].add(component_name or purl or key)

            # Snippet-level detail (file/line-range matches worth surfacing individually)
            if match_type == "snippet":
                snippet_matches.append({
                    "file": filepath,
                    "component": component_name,
                    "version": version,
                    "purl": purl,
                    "matched_pct": match.get("matched", ""),
                    "target_lines": match.get("lines", ""),
                    "oss_lines": match.get("oss_lines", ""),
                    "oss_url": match.get("url", ""),
                })

            # Dependency-scanner entries (when dependencies.enabled: true)
            for dep in match.get("dependencies", []) or []:
                dep_purl = dep.get("purl", "")
                dep_version = dep.get("version", "")
                dep_license_names = _extract_license_names(dep.get("licenses"), license_counter)
                if "vulnerabilities" in dep:
                    vulnerability_field_seen = True
                dep_vulns = _extract_vulnerabilities(dep.get("vulnerabilities"))

                dkey = dep_purl or f"{dep.get('component','')}@{dep_version}"
                if dkey:
                    dep_risk_levels = [classify_license(n) for n in dep_license_names] or ["unknown"]
                    dep_entry = dependency_components.setdefault(dkey, {
                        "purl": dep_purl or None,
                        "component": dep.get("component", ""),
                        "version": dep_version,
                        "licenses": set(),
                        "license_risk": "unknown",
                        "vulnerabilities": {},
                    })
                    dep_entry["licenses"].update(dep_license_names)
                    dep_entry["license_risk"] = worst_risk(
                        [dep_entry["license_risk"]] + dep_risk_levels
                    )
                    for v in dep_vulns:
                        dep_entry["vulnerabilities"][v["id"]] = v
                        rec = all_vulnerabilities.setdefault(v["id"], {**v, "affected": set()})
                        rec["affected"].add(dep.get("component", "") or dep_purl or dkey)

    def finalize(entry):
        return {
            **{k: v for k, v in entry.items() if k not in ("licenses", "match_types", "vulnerabilities")},
            "licenses": sorted(entry["licenses"]),
            "match_types": sorted(entry.get("match_types", [])) if "match_types" in entry else None,
            "vulnerabilities": list(entry["vulnerabilities"].values()),
            "vulnerability_count": len(entry["vulnerabilities"]),
        }

    finalized_components = {k: finalize(v) for k, v in components.items()}
    finalized_dependencies = {k: finalize(v) for k, v in dependency_components.items()}

    all_items = list(finalized_components.values()) + list(finalized_dependencies.values())
    risk_counts = Counter(item["license_risk"] for item in all_items)
    flagged_copyleft = [
        {
            "component": item["component"] or item.get("purl"),
            "version": item["version"],
            "purl": item.get("purl"),
            "licenses": item["licenses"],
            "license_risk": item["license_risk"],
        }
        for item in all_items
        if item["license_risk"] in ("strong_copyleft", "weak_copyleft")
    ]

    vulnerable_components = [
        {
            "component": item["component"] or item.get("purl"),
            "version": item["version"],
            "purl": item.get("purl"),
            "vulnerabilities": item["vulnerabilities"],
        }
        for item in all_items
        if item["vulnerability_count"] > 0
    ]

    severity_counts = Counter(v.get("severity", "unknown") for v in all_vulnerabilities.values())

    # Sort snippets by lowest match percentage first (most interesting to review),
    # falling back to original order when percentage isn't parseable.
    def _pct(sm):
        try:
            return float(str(sm.get("matched_pct", "")).rstrip("%"))
        except ValueError:
            return 100.0

    snippet_matches.sort(key=_pct)

    return {
        "total_files_scanned": total_files,
        "matched_files": matched_files,
        "unmatched_files": total_files - matched_files,
        "unique_components_count": len(finalized_components),
        "unique_dependency_components_count": len(finalized_dependencies),
        "license_breakdown": license_counter.most_common(),
        "risk_counts": dict(risk_counts),
        "flagged_copyleft_components": flagged_copyleft,
        "vulnerability_data_present": vulnerability_field_seen,
        "vulnerability_severity_counts": dict(severity_counts),
        "vulnerable_components": vulnerable_components[:MAX_COMPONENTS_IN_PROMPT],
        "components": list(finalized_components.values())[:MAX_COMPONENTS_IN_PROMPT],
        "dependency_components": list(finalized_dependencies.values())[:MAX_COMPONENTS_IN_PROMPT],
        "components_truncated": len(finalized_components) > MAX_COMPONENTS_IN_PROMPT,
        "dependency_components_truncated": len(finalized_dependencies) > MAX_COMPONENTS_IN_PROMPT,
        "snippet_matches": snippet_matches[:MAX_SNIPPETS_IN_PROMPT],
        "snippet_matches_total": len(snippet_matches),
        "snippet_matches_truncated": len(snippet_matches) > MAX_SNIPPETS_IN_PROMPT,
    }


def call_claude(summary: dict, repo_name: str, repo_ref: str, commit_sha: str) -> str:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY is not set.", file=sys.stderr)
        sys.exit(1)

    model = os.environ.get("CLAUDE_MODEL", "claude-sonnet-5")
    detail = os.environ.get("REPORT_DETAIL", "standard").strip().lower()
    detail_instructions = {
        "concise": "Keep the whole report under ~250 words. Use short bullet points, minimal tables, no filler.",
        "standard": "Aim for a thorough but skimmable report, roughly 400-700 words plus tables.",
        "detailed": "Be comprehensive: cover every component group, explain risk reasoning, and don't compress the component table.",
    }.get(detail, "Aim for a thorough but skimmable report, roughly 400-700 words plus tables.")

    system_prompt = (
        "You are a software supply chain security analyst. You will be given a "
        "condensed, pre-aggregated JSON summary of a SCANOSS SCA/SBOM scan. "
        "The JSON already contains a deterministic license risk classification "
        "per component (license_risk: strong_copyleft | weak_copyleft | permissive | "
        "unknown), a pre-filtered list of copyleft-flagged components "
        "(flagged_copyleft_components), pre-extracted vulnerability records per "
        "component (vulnerable_components, vulnerability_severity_counts), and "
        "pre-extracted snippet-level match detail (snippet_matches: file, "
        "component, version, purl, matched_pct, target_lines, oss_lines, oss_url). "
        "Do NOT reclassify or second-guess the risk labels, do NOT invent "
        "components, licenses, versions, purls, CVEs, or numbers that are not "
        "present in the JSON.\n\n"
        "IMPORTANT: vulnerability_data_present tells you whether this scan run "
        "actually collected vulnerability data at all (it requires a Dependency "
        "Track integration or premium API tier). If vulnerability_data_present "
        "is false, you MUST say vulnerability data was not collected in this "
        "scan and must NOT imply that zero vulnerabilities were found — those "
        "are different things. Only report 'no vulnerabilities found' if "
        "vulnerability_data_present is true and vulnerable_components is empty.\n\n"
        "Write the report in Markdown using EXACTLY this section order and these "
        "headings (omit a section only if the underlying data is completely empty):\n"
        "## Executive Summary\n"
        "## Risk Highlights\n"
        "## Scan Coverage\n"
        "## License Breakdown\n"
        "## Third-Party Components\n"
        "## Dependencies\n"
        "## Vulnerabilities\n"
        "## Snippet Matches\n"
        "## Recommendations\n\n"
        "Section guidance:\n"
        "- Executive Summary: 2-4 sentences, plain language, for a non-specialist reader.\n"
        "- Risk Highlights: a short bulleted callout of anything in "
        "flagged_copyleft_components, vulnerable_components, or risk_counts.unknown "
        "that needs human review. If there's nothing to flag in a category, say so plainly.\n"
        "- Scan Coverage: the file/match stats as a compact list.\n"
        "- License Breakdown: a Markdown table of license name, count, and risk level.\n"
        "- Third-Party Components: a Markdown table with columns Component | Version | "
        "PURL | License(s) | Risk | Vulns, one row per entry in `components`. Use the "
        "vulnerability_count field for the Vulns column (or '-' if 0). If "
        "components_truncated is true, note the list was capped and the full list is "
        "in the raw scan artifact.\n"
        "- Dependencies: same table style, from `dependency_components`, only if "
        "that list is non-empty.\n"
        "- Vulnerabilities: if vulnerability_data_present is false, state plainly "
        "that vulnerability scanning was not part of this run and how to enable it "
        "(Dependency Track integration). If true, summarize vulnerability_severity_counts "
        "and list each entry in vulnerable_components with its CVE id(s) and severity.\n"
        "- Snippet Matches: a Markdown table (File | Component | Version | Matched % | "
        "Target Lines | OSS Lines | OSS URL) from `snippet_matches`, which is already "
        "sorted lowest-match-percentage-first (the ones most worth a human look). If "
        "snippet_matches_truncated is true, note the total count and that the list was capped.\n"
        "- Recommendations: a short, prioritized bullet list of concrete follow-ups.\n\n"
        f"Length/detail target: {detail_instructions}"
    )

    user_content = (
        f"Repository: {repo_name}\n"
        f"Ref: {repo_ref}\n"
        f"Commit: {commit_sha}\n\n"
        f"Scan summary JSON:\n```json\n{json.dumps(summary, indent=2)}\n```"
    )

    max_tokens = {"concise": 1200, "standard": 3000, "detailed": 5000}.get(detail, 3000)

    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_content}],
    }

    response = requests.post(
        ANTHROPIC_API_URL,
        headers={
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        },
        json=payload,
        timeout=120,
    )

    if response.status_code != 200:
        print(f"ERROR: Claude API call failed ({response.status_code}): {response.text}",
              file=sys.stderr)
        sys.exit(1)

    data = response.json()
    text_parts = [block["text"] for block in data.get("content", []) if block.get("type") == "text"]
    return "\n".join(text_parts).strip()


def main() -> None:
    result_file = os.environ.get("SCANOSS_RESULT_FILE", "scanoss-raw.json")
    repo_name = os.environ.get("REPO_NAME", "unknown/unknown")
    repo_ref = os.environ.get("REPO_REF", "unknown")
    commit_sha = os.environ.get("COMMIT_SHA", "unknown")

    if not os.path.exists(result_file):
        print(f"ERROR: SCANOSS result file not found: {result_file}", file=sys.stderr)
        sys.exit(1)

    results = load_scan_results(result_file)
    summary = summarize(results)
    report_body = call_claude(summary, repo_name, repo_ref, commit_sha)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    header = (
        f"# SBOM Summary Report\n\n"
        f"- **Repository:** {repo_name}\n"
        f"- **Ref:** {repo_ref}\n"
        f"- **Commit:** {commit_sha}\n"
        f"- **Generated:** {generated_at}\n\n---\n\n"
    )

    with open("sbom-summary-report.md", "w", encoding="utf-8") as f:
        f.write(header + report_body + "\n")

    print("Wrote sbom-summary-report.md")


if __name__ == "__main__":
    main()
