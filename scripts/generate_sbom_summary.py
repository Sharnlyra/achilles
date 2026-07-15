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


def summarize(results: dict) -> dict:
    """
    SCANOSS raw results are keyed by scanned file path, each holding a list
    of match objects. This walks the structure defensively since fields can
    vary slightly by scan mode (snippet vs dependency matches).
    """
    total_files = len(results)
    matched_files = 0
    components = {}  # purl -> {vendor, component, version, license_names:set}
    license_counter = Counter()
    dependency_components = {}

    for filepath, matches in results.items():
        if not matches:
            continue
        for match in matches:
            match_id = match.get("id", "none")
            if match_id and match_id != "none":
                matched_files += 1

            purls = match.get("purl") or []
            vendor = match.get("vendor", "")
            component_name = match.get("component", "")
            version = match.get("version", "")
            licenses = match.get("licenses") or match.get("license") or []

            license_names = []
            for lic in licenses:
                if isinstance(lic, dict):
                    name = lic.get("name")
                else:
                    name = str(lic)
                if name:
                    license_names.append(name)
                    license_counter[name] += 1

            key = purls[0] if purls else f"{vendor}/{component_name}@{version}"
            if key and key not in components:
                risk_levels = [classify_license(n) for n in license_names] or ["unknown"]
                components[key] = {
                    "purl": purls[0] if purls else None,
                    "vendor": vendor,
                    "component": component_name,
                    "version": version,
                    "licenses": sorted(set(license_names)),
                    "license_risk": worst_risk(risk_levels),
                }

            # Dependency-scanner entries (when dependencies.enabled: true)
            for dep in match.get("dependencies", []) or []:
                dep_purl = dep.get("purl", "")
                dep_version = dep.get("version", "")
                dep_licenses = dep.get("licenses") or []
                dep_license_names = [
                    lic.get("name") if isinstance(lic, dict) else str(lic)
                    for lic in dep_licenses
                    if lic
                ]
                dkey = dep_purl or f"{dep.get('component','')}@{dep_version}"
                if dkey and dkey not in dependency_components:
                    dep_risk_levels = [classify_license(n) for n in dep_license_names] or ["unknown"]
                    dependency_components[dkey] = {
                        "purl": dep_purl or None,
                        "component": dep.get("component", ""),
                        "version": dep_version,
                        "licenses": sorted(set(dep_license_names)),
                        "license_risk": worst_risk(dep_risk_levels),
                    }

    all_items = list(components.values()) + list(dependency_components.values())
    risk_counts = Counter(item["license_risk"] for item in all_items)
    flagged_copyleft = [
        {
            "component": item["component"] or item.get("purl"),
            "version": item["version"],
            "licenses": item["licenses"],
            "license_risk": item["license_risk"],
        }
        for item in all_items
        if item["license_risk"] in ("strong_copyleft", "weak_copyleft")
    ]

    return {
        "total_files_scanned": total_files,
        "matched_files": matched_files,
        "unmatched_files": total_files - matched_files,
        "unique_components_count": len(components),
        "unique_dependency_components_count": len(dependency_components),
        "license_breakdown": license_counter.most_common(),
        "risk_counts": dict(risk_counts),
        "flagged_copyleft_components": flagged_copyleft,
        "components": list(components.values())[:MAX_COMPONENTS_IN_PROMPT],
        "dependency_components": list(dependency_components.values())[
            :MAX_COMPONENTS_IN_PROMPT
        ],
        "components_truncated": len(components) > MAX_COMPONENTS_IN_PROMPT,
        "dependency_components_truncated": len(dependency_components)
        > MAX_COMPONENTS_IN_PROMPT,
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
        "unknown) and a pre-filtered list of copyleft-flagged components "
        "(flagged_copyleft_components). Do NOT reclassify or second-guess these "
        "risk labels yourself, and do not invent components, licenses, or "
        "numbers that are not present in the JSON.\n\n"
        "Write the report in Markdown using EXACTLY this section order and these "
        "headings (omit a section only if the underlying data is completely empty):\n"
        "## Executive Summary\n"
        "## Risk Highlights\n"
        "## Scan Coverage\n"
        "## License Breakdown\n"
        "## Third-Party Components\n"
        "## Dependencies\n"
        "## Recommendations\n\n"
        "Section guidance:\n"
        "- Executive Summary: 2-4 sentences, plain language, for a non-specialist reader.\n"
        "- Risk Highlights: a short bulleted callout of anything in "
        "flagged_copyleft_components or risk_counts.unknown that needs human "
        "review. If there are zero copyleft/unknown items, say so plainly.\n"
        "- Scan Coverage: the file/match stats as a compact list.\n"
        "- License Breakdown: a Markdown table of license name, count, and risk level.\n"
        "- Third-Party Components: a Markdown table (component, version, license, risk). "
        "If components_truncated is true, note that the list was capped and the full "
        "list is in the raw scan artifact.\n"
        "- Dependencies: same table style as above for dependency_components, only "
        "if that list is non-empty.\n"
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
