#!/usr/bin/env python3
"""
Burp Suite XML -> Xacta JSON Converter (v2 - Multi-Host)

Follows the Telos "Converting to External Data to Xacta JSON Using Python (v4.0)"
pattern by using config.ini for input/output configuration.

Changes from v1:
- Groups issues by normalized hostname, producing one asset per unique host
- Extracts IP addresses from <host ip="..."> into netAdapters
- Aligns resultData as object (key-value pairs) per XIO JSON Template v4.0
- Adds solution field to testResults
- Adds severity, riskFactor per latest template fields

Purpose:
- Convert Burp Suite XML output into Xacta® JSON
- Intended for FedRAMP RA-5 / CA-7 DAST evidence
- NOT SCAP, NOT OpenSCAP, NOT compliance automation
"""

import os
import sys
import json
import time
import hashlib
import logging
import configparser
import xml.etree.ElementTree as ET
from datetime import datetime
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse
from typing import List, Dict, Optional, Any, Tuple
from collections import defaultdict

# Optional dependency
try:
    from jsonschema import validate
    from jsonschema.exceptions import ValidationError
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False

# -----------------------------
# Logging
# -----------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)


# -----------------------------
# Constants
# -----------------------------

DATA_SOURCE_NAME = "Burp Suite Professional"

SEVERITY_MAP = {
    "High": "High",
    "Medium": "Moderate",
    "Low": "Low",
    "Information": "Low"
}

REQUIRED_ROOT_TAG = "issues"
REQUIRED_ISSUE_FIELDS = ["name", "severity"]

# Minimal Xacta JSON schema
XACTA_JSON_SCHEMA = {
    "type": "object",
    "required": ["assets"],
    "properties": {
        "assets": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["hostName", "scanDate"]
            }
        }
    }
}

ALLOWED_ASSET_FIELDS = {
    "hostName",
    "scanDate",
    "dataSource",
    "systemName",
    "scannerVersion",
    "netAdapters",
    "softwares",
    "testResults"
}

ALLOWED_TEST_RESULT_FIELDS = {
    "testName",
    "description",
    "notes",
    "result",
    "rawResult",
    "protocol",
    "vendorId",
    "solution",
    "port",
    "contents",
    "runTime",
    "riskFactor",
    "severity",
    "resultData",
    "testData",
    "scannedWithCredentialsFlag",
    "errorRunningTestFlag"
}

MAX_EVIDENCE_SNIPPET_CHARS = 100
AUDIT_BLOCK_BEGIN = "[AUDIT_SOURCE_BURP_V1_BEGIN]"
AUDIT_BLOCK_END = "[AUDIT_SOURCE_BURP_V1_END]"


# -----------------------------
# Helpers
# -----------------------------

def text_or_none(elem: Optional[ET.Element]) -> Optional[str]:
    if elem is None or elem.text is None:
        return None
    return elem.text.strip()


def map_severity(severity: Optional[str]) -> str:
    return SEVERITY_MAP.get(severity, "Low")


def scanner_result_from_severity(severity: Optional[str]) -> str:
    if severity and severity.strip().lower() in ("pass", "n/a"):
        return severity.strip().title()
    return "Fail"


def parse_port_from_host_or_path(host: Optional[str], path: Optional[str]) -> Optional[int]:
    for value in (host, path):
        if not value:
            continue
        candidate = value.strip()
        if "://" not in candidate:
            candidate = f"//{candidate}"
        parsed = urlparse(candidate)
        try:
            if parsed.port is not None:
                return parsed.port
        except ValueError:
            continue
    return None


def parse_protocol_from_host(host: Optional[str]) -> Optional[str]:
    if not host:
        return None
    parsed = urlparse(host.strip())
    if parsed.scheme:
        return parsed.scheme.upper()
    return None


def infer_vendor_id(issue: ET.Element, name: Optional[str], host: Optional[str], path: Optional[str]) -> Optional[str]:
    issue_type = text_or_none(issue.find("type"))
    if issue_type:
        return issue_type
    serial_number = text_or_none(issue.find("serialNumber"))
    if serial_number:
        return serial_number
    if name:
        return f"{name}|{host or ''}|{path or ''}"
    return None


def normalize_hostname(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    hostname = parsed.hostname
    if not hostname:
        return None
    return hostname.lower().strip(".")


def build_test_data(host: Optional[str], path: Optional[str]) -> Optional[str]:
    if host and path:
        if host.endswith("/") and path.startswith("/"):
            return f"{host[:-1]}{path}"
        if (not host.endswith("/")) and (not path.startswith("/")):
            return f"{host}/{path}"
        return f"{host}{path}"
    if host:
        return f"host={host}"
    if path:
        return f"path={path}"
    return None


def parse_export_time_to_epoch_ms(export_time: Optional[str]) -> Optional[int]:
    if not export_time:
        return None
    text = export_time.strip()
    try:
        dt = parsedate_to_datetime(text)
        return int(dt.timestamp() * 1000)
    except Exception:
        pass
    for fmt in ("%a %b %d %H:%M:%S %Z %Y", "%a %b %d %H:%M:%S %Y"):
        try:
            dt = datetime.strptime(text, fmt)
            return int(dt.timestamp() * 1000)
        except ValueError:
            continue
    return None


def parse_export_time_to_iso8601(export_time: Optional[str]) -> Optional[str]:
    if not export_time:
        return None
    text = export_time.strip()
    try:
        dt = parsedate_to_datetime(text)
        return dt.isoformat()
    except Exception:
        return None


def extract_asset_ip_from_host_attr(issue: ET.Element) -> Optional[str]:
    """Extract IP from the <host ip='...'> attribute (preferred over URL parsing)."""
    host_elem = issue.find("host")
    if host_elem is None:
        return None
    ip = host_elem.attrib.get("ip", "").strip()
    if not ip:
        return None
    # Validate it looks like an IPv4 address
    octets = ip.split(".")
    if len(octets) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in octets):
        return ip
    return None


def extract_asset_ip_from_host_text(host: Optional[str]) -> Optional[str]:
    """Fallback: extract IP from host URL text if it's an IP-based URL."""
    if not host:
        return None
    candidate = host.strip()
    if "://" not in candidate:
        candidate = f"//{candidate}"
    parsed = urlparse(candidate)
    host_name = parsed.hostname
    if not host_name:
        return None
    octets = host_name.split(".")
    if len(octets) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in octets):
        return host_name
    return None


def remove_empty_structures(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            reduced = remove_empty_structures(item)
            if reduced is None:
                continue
            if isinstance(reduced, (dict, list)) and not reduced:
                continue
            cleaned[key] = reduced
        return cleaned or None
    if isinstance(value, list):
        cleaned_items = []
        for item in value:
            reduced = remove_empty_structures(item)
            if reduced is None:
                continue
            if isinstance(reduced, (dict, list)) and not reduced:
                continue
            cleaned_items.append(reduced)
        return cleaned_items or None
    if isinstance(value, str):
        return value if value.strip() else None
    return value


def truncate_text(value: Optional[str], limit: int = MAX_EVIDENCE_SNIPPET_CHARS) -> Optional[str]:
    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    if len(normalized) <= limit:
        return normalized
    return f"{normalized[:limit]}..."


def sanitize_notes_text(notes_text: Optional[str]) -> Optional[str]:
    if not notes_text:
        return None
    text = notes_text.strip()
    if not text:
        return None

    audit_block = None
    audit_start = text.find(AUDIT_BLOCK_BEGIN)
    audit_end = text.find(AUDIT_BLOCK_END)
    if audit_start != -1 and audit_end != -1 and audit_end >= audit_start:
        audit_end_with_marker = audit_end + len(AUDIT_BLOCK_END)
        audit_block = text[audit_start:audit_end_with_marker]
        text = (text[:audit_start] + text[audit_end_with_marker:]).strip()

    sanitized_lines: List[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("Request Snippet:"):
            snippet = truncate_text(line.split(":", 1)[1].strip())
            if snippet:
                sanitized_lines.append(f"Request Snippet: {snippet}")
            continue
        if line.startswith("Response Snippet:"):
            snippet = truncate_text(line.split(":", 1)[1].strip())
            if snippet:
                sanitized_lines.append(f"Response Snippet: {snippet}")
            continue
        sanitized_lines.append(line)

    rendered_parts: List[str] = []
    if sanitized_lines:
        rendered_parts.append("\n".join(sanitized_lines))
    if audit_block:
        rendered_parts.append(audit_block)

    if not rendered_parts:
        return None
    return "\n\n".join(rendered_parts)


def validate_scan_date(scan_date: Any) -> bool:
    if not isinstance(scan_date, str):
        return False
    try:
        datetime.fromisoformat(scan_date.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def extract_request_response(issue: ET.Element) -> Dict[str, Optional[str]]:
    request = None
    response = None
    http_method = None
    response_redirected = None
    requestresponse = issue.find("requestresponse")
    if requestresponse is not None:
        request_elem = requestresponse.find("request")
        response_elem = requestresponse.find("response")
        redirected_elem = requestresponse.find("responseRedirected")
        if request_elem is not None:
            request = (request_elem.text or "").strip() or None
            http_method = request_elem.attrib.get("method")
        if response_elem is not None:
            response = (response_elem.text or "").strip() or None
        if redirected_elem is not None:
            response_redirected = (redirected_elem.text or "").strip() or None
    return {
        "request": request,
        "response": response,
        "request_snippet": truncate_text(request),
        "response_snippet": truncate_text(response),
        "http_method": http_method,
        "response_redirected": response_redirected
    }


def build_audit_source_record(
    issue: ET.Element,
    scanner_source: str,
    scanner_version: Optional[str],
    scan_date_value: Optional[str]
) -> Dict[str, str]:
    host = text_or_none(issue.find("host"))
    path = text_or_none(issue.find("path"))
    severity = text_or_none(issue.find("severity"))
    confidence = text_or_none(issue.find("confidence"))
    issue_background = text_or_none(issue.find("issueBackground"))
    issue_detail = text_or_none(issue.find("issueDetail"))
    remediation_background = text_or_none(issue.find("remediationBackground"))
    remediation_detail = text_or_none(issue.find("remediationDetail"))
    references = text_or_none(issue.find("references"))
    vulnerability_classifications = text_or_none(issue.find("vulnerabilityClassifications"))
    location = text_or_none(issue.find("location"))
    source_type = text_or_none(issue.find("type"))
    serial_number = text_or_none(issue.find("serialNumber"))
    static_analysis = text_or_none(issue.find("staticAnalysis"))
    request_response_data = extract_request_response(issue)

    weakness_parts = []
    cwe_id = text_or_none(issue.find("cweid"))
    if vulnerability_classifications:
        weakness_parts.append(vulnerability_classifications)
    if cwe_id:
        weakness_parts.append(f"CWE-{cwe_id}")

    asset_ip = extract_asset_ip_from_host_attr(issue) or extract_asset_ip_from_host_text(host)

    return {
        "External ID": serial_number or source_type or "",
        "Title": text_or_none(issue.find("name")) or "",
        "Source Type": source_type or "",
        "Severity": severity or "",
        "Scanner Severity (Original)": severity or "",
        "Scanner Confidence": confidence or "",
        "Asset Hostname": host or "",
        "Asset IP Address": asset_ip or "",
        "Affected Resource": path or "",
        "Finding Location": location or "",
        "Description": issue_background or "",
        "Technical Details": issue_detail or "",
        "Remediation Rationale": remediation_background or "",
        "Recommended Remediation": remediation_detail or "",
        "References": references or "",
        "Weakness Classification": " | ".join(weakness_parts),
        "Evidence Request": request_response_data["request_snippet"] or "",
        "Evidence Response": request_response_data["response_snippet"] or "",
        "HTTP Method": request_response_data["http_method"] or "",
        "Scan Date": scan_date_value or "",
        "Scanner Source": scanner_source or "",
        "Evidence Hash": "",
        "Scanner Version": scanner_version or "",
        "Scan Type": static_analysis or ""
    }


def append_audit_block(notes_text: str, audit_record: Dict[str, str]) -> str:
    serialized = json.dumps(audit_record, separators=(",", ":"), ensure_ascii=False)
    block = (
        "[AUDIT_SOURCE_BURP_V1_BEGIN]\n"
        f"{serialized}\n"
        "[AUDIT_SOURCE_BURP_V1_END]"
    )
    if notes_text:
        return f"{notes_text}\n\n{block}"
    return block


def evidence_hash_from_record(audit_record: Dict[str, str]) -> str:
    serialized = json.dumps(audit_record, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


# -----------------------------
# Burp XML validation
# -----------------------------

def validate_burp_xml_structure(root: ET.Element) -> None:
    if root.tag != REQUIRED_ROOT_TAG:
        raise RuntimeError(
            f"Expected <{REQUIRED_ROOT_TAG}> root, found <{root.tag}>"
        )
    issues = root.findall(".//issue")
    if not issues:
        raise RuntimeError("No <issue> elements found in Burp XML")
    for idx, issue in enumerate(issues, start=1):
        for field in REQUIRED_ISSUE_FIELDS:
            if issue.find(field) is None:
                raise RuntimeError(
                    f"Issue #{idx} missing required <{field}> element"
                )


# -----------------------------
# Parse Burp issues (grouped by host)
# -----------------------------

def parse_burp_issues_by_host(
    root: ET.Element,
    scanner_source: str,
    scanner_version: Optional[str],
    scan_date_epoch_ms: int,
    scan_date_value: Optional[str]
) -> Dict[str, Dict[str, Any]]:
    """
    Parse all issues and group them by normalized hostname.

    Returns a dict keyed by normalized hostname, each value containing:
      - test_results: list of test result dicts
      - ips: set of IP addresses seen for this host
    """
    host_groups: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"test_results": [], "ips": set()}
    )

    for issue in root.findall(".//issue"):
        name = text_or_none(issue.find("name"))
        severity = text_or_none(issue.find("severity"))
        confidence = text_or_none(issue.find("confidence"))
        background = text_or_none(issue.find("issueBackground")) or name
        detail = text_or_none(issue.find("issueDetail"))
        location = text_or_none(issue.find("location"))
        remediation_background = text_or_none(issue.find("remediationBackground"))
        remediation_detail = text_or_none(issue.find("remediationDetail"))
        references = text_or_none(issue.find("references"))
        vulnerability_classifications = text_or_none(issue.find("vulnerabilityClassifications"))
        host = text_or_none(issue.find("host"))
        path = text_or_none(issue.find("path"))
        cwe_id = text_or_none(issue.find("cweid"))
        vendor_id = infer_vendor_id(issue, name, host, path)
        port = parse_port_from_host_or_path(host, path)
        protocol = parse_protocol_from_host(host)
        test_data = build_test_data(host, path)
        request_response_data = extract_request_response(issue)

        # Determine which host group this issue belongs to
        normalized_host = normalize_hostname(host)
        if not normalized_host:
            normalized_host = "unknown.local"

        # Collect IP from the <host ip="..."> attribute
        asset_ip = extract_asset_ip_from_host_attr(issue) or extract_asset_ip_from_host_text(host)
        if asset_ip:
            host_groups[normalized_host]["ips"].add(asset_ip)

        # Build notes
        notes = []
        if host:
            notes.append(f"Host: {host}")
        if asset_ip:
            notes.append(f"Asset IP Address: {asset_ip}")
        if path:
            notes.append(f"Path: {path}")
        if location:
            notes.append(f"Finding Location: {location}")
        if confidence:
            notes.append(f"Confidence: {confidence}")
        if references:
            notes.append(f"References: {references}")
        if remediation_background:
            notes.append(f"Remediation Rationale: {remediation_background}")
        if remediation_detail:
            notes.append(f"Recommended Remediation: {remediation_detail}")
        if request_response_data["response_redirected"]:
            notes.append(f"Response Redirected: {request_response_data['response_redirected']}")
        if request_response_data["request_snippet"]:
            notes.append(f"Request Snippet: {request_response_data['request_snippet']}")
        if request_response_data["response_snippet"]:
            notes.append(f"Response Snippet: {request_response_data['response_snippet']}")
        if detail:
            notes.append(detail)

        # Build resultData as object (key-value pairs per XIO template)
        result_data_obj: Dict[str, str] = {}
        source_type = text_or_none(issue.find("type"))
        serial_number = text_or_none(issue.find("serialNumber"))
        result_data_obj["Source Type"] = source_type or ""
        result_data_obj["External ID"] = serial_number or source_type or ""
        if severity:
            result_data_obj["Severity"] = severity
        if confidence:
            result_data_obj["Confidence"] = confidence
        if request_response_data["http_method"]:
            result_data_obj["HTTP Method"] = request_response_data["http_method"]
        if scan_date_value:
            result_data_obj["Scan Date"] = scan_date_value
        result_data_obj["Scanner Source"] = scanner_source
        if scanner_version:
            result_data_obj["Scanner Version"] = scanner_version

        if request_response_data["http_method"]:
            method = request_response_data["http_method"]
            if test_data:
                test_data = f"{method} {test_data}"
            else:
                test_data = f"method={method}"

        # Build description
        description_parts = [p for p in (background, detail) if p]
        description = "\n\n".join(description_parts) if description_parts else None

        # Build solution from remediation fields
        solution_parts = []
        if remediation_background:
            solution_parts.append(remediation_background)
        if remediation_detail:
            solution_parts.append(remediation_detail)
        solution = "\n\n".join(solution_parts) if solution_parts else None

        # Build audit record
        audit_record = build_audit_source_record(
            issue=issue,
            scanner_source=scanner_source,
            scanner_version=scanner_version,
            scan_date_value=scan_date_value
        )
        audit_record["Evidence Hash"] = evidence_hash_from_record(audit_record)

        entry: Dict[str, Any] = {
            "vendorId": vendor_id,
            "testName": name,
            "description": description or background,
            "notes": append_audit_block("\n".join(notes), audit_record),
            "result": scanner_result_from_severity(severity),
            "rawResult": scanner_result_from_severity(severity),
            "riskFactor": map_severity(severity),
            "severity": severity or "Information",
            "runTime": scan_date_epoch_ms,
            "scannedWithCredentialsFlag": False,
            "errorRunningTestFlag": False
        }

        if solution:
            entry["solution"] = solution
        if result_data_obj:
            entry["resultData"] = result_data_obj
        if test_data:
            entry["testData"] = test_data
        if protocol:
            entry["protocol"] = protocol
        if port is not None:
            entry["port"] = port
        if cwe_id:
            entry["contents"] = [
                {"name": f"CWE-{cwe_id}", "type": "CWE"}
            ]
        if vulnerability_classifications:
            entry.setdefault("contents", []).append(
                {"name": vulnerability_classifications, "type": "CWE"}
            )

        if entry["vendorId"] and entry["testName"]:
            host_groups[normalized_host]["test_results"].append(entry)
        else:
            logging.warning("Skipping issue with missing vendorId or testName")

    return dict(host_groups)


# -----------------------------
# Render & validate
# -----------------------------

def render_xacta_payload(assets: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(assets, list):
        raise RuntimeError("Renderer expected a list of assets")

    rendered_assets: List[Dict[str, Any]] = []
    hostnames_seen = set()

    for raw_asset in assets:
        raw_host_name = raw_asset.get("hostName")
        hostname = normalize_hostname(raw_host_name) if raw_host_name else raw_host_name
        if not hostname:
            raise RuntimeError("Asset hostName must be a valid hostname value")

        scan_date = raw_asset.get("scanDate")
        if not validate_scan_date(scan_date):
            raise RuntimeError("Asset scanDate must be a valid ISO-8601 string")

        sanitized_asset = {
            key: raw_asset[key]
            for key in ALLOWED_ASSET_FIELDS
            if key in raw_asset
        }
        sanitized_asset["hostName"] = hostname
        sanitized_asset["scanDate"] = scan_date

        test_results = sanitized_asset.get("testResults")
        if test_results is not None:
            if not isinstance(test_results, list):
                raise RuntimeError("testResults must be an array when provided")
            if "dataSource" not in sanitized_asset or not str(sanitized_asset["dataSource"]).strip():
                raise RuntimeError("dataSource is required when testResults exists")

            sanitized_tests: List[Dict[str, Any]] = []
            for result in test_results:
                if not isinstance(result, dict):
                    continue
                cleaned_result = {
                    key: result[key]
                    for key in ALLOWED_TEST_RESULT_FIELDS
                    if key in result
                }
                if "notes" in cleaned_result:
                    cleaned_result["notes"] = sanitize_notes_text(cleaned_result.get("notes"))
                cleaned_result = remove_empty_structures(cleaned_result) or {}
                if cleaned_result:
                    sanitized_tests.append(cleaned_result)
            if sanitized_tests:
                sanitized_asset["testResults"] = sanitized_tests
            else:
                sanitized_asset.pop("testResults", None)

        sanitized_asset = remove_empty_structures(sanitized_asset)
        if not sanitized_asset:
            raise RuntimeError("Asset became empty after sanitization")

        host_value = sanitized_asset.get("hostName")
        if not host_value:
            raise RuntimeError("Asset hostName is required")
        if host_value in hostnames_seen:
            raise RuntimeError(f"Duplicate hostName detected: {host_value}")
        hostnames_seen.add(host_value)

        if "scanDate" not in sanitized_asset or not validate_scan_date(sanitized_asset["scanDate"]):
            raise RuntimeError("Asset scanDate validation failed")

        rendered_assets.append(sanitized_asset)

    if not rendered_assets:
        raise RuntimeError("No valid assets to render")

    return {"assets": rendered_assets}


def validate_xacta_json(data: Dict[str, Any]) -> None:
    if not JSONSCHEMA_AVAILABLE:
        logging.warning("jsonschema not installed; skipping Xacta JSON validation")
        return
    validate(instance=data, schema=XACTA_JSON_SCHEMA)
    logging.info("Xacta JSON schema validation passed")


# -----------------------------
# Main
# -----------------------------

def main() -> None:
    config = configparser.ConfigParser()
    config.read("config.ini")

    if "BURP-IOJSON" not in config:
        logging.error("Missing [BURP-IOJSON] section in config.ini")
        sys.exit(1)

    input_dir = config["BURP-IOJSON"].get("INPUT_FOLDER")
    output_dir = config["BURP-IOJSON"].get("OUTPUT_FOLDER")
    app_name = config["BURP-IOJSON"].get("APPLICATION_NAME")
    scanner_version = config["BURP-IOJSON"].get("SCANNER_VERSION")
    system_name = config["BURP-IOJSON"].get("SYSTEM_NAME")

    if not input_dir or not output_dir or not app_name:
        logging.error("config.ini missing required values")
        sys.exit(1)

    if not os.path.isdir(input_dir):
        logging.error("Input folder does not exist: %s", input_dir)
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    for filename in os.listdir(input_dir):
        if not filename.lower().endswith(".xml"):
            continue

        input_path = os.path.join(input_dir, filename)
        output_path = os.path.join(
            output_dir,
            filename.replace(".xml", "-xacta.json")
        )

        logging.info("Processing %s", filename)

        try:
            tree = ET.parse(input_path)
            root = tree.getroot()
            validate_burp_xml_structure(root)
        except Exception as e:
            logging.error("Skipping %s: %s", filename, e)
            continue

        scan_date_value = root.attrib.get("exportTime")
        scan_date_epoch_ms = parse_export_time_to_epoch_ms(scan_date_value) or int(time.time() * 1000)
        scan_date_iso8601 = parse_export_time_to_iso8601(scan_date_value)
        effective_scanner_version = scanner_version or root.attrib.get("burpVersion")
        system_name_value = (system_name or "").strip() or app_name

        # --- v2: group issues by host ---
        host_groups = parse_burp_issues_by_host(
            root=root,
            scanner_source=DATA_SOURCE_NAME,
            scanner_version=effective_scanner_version,
            scan_date_epoch_ms=scan_date_epoch_ms,
            scan_date_value=scan_date_value
        )

        if not host_groups:
            logging.warning("No issues parsed from %s", filename)
            continue

        # Build one asset per unique host
        asset_candidates: List[Dict[str, Any]] = []
        for hostname, group_data in sorted(host_groups.items()):
            asset: Dict[str, Any] = {
                "hostName": hostname,
                "dataSource": DATA_SOURCE_NAME,
                "scanDate": scan_date_iso8601,
                "systemName": system_name_value,
                "testResults": group_data["test_results"]
            }

            if effective_scanner_version:
                asset["scannerVersion"] = effective_scanner_version

            # Populate netAdapters from collected IPs
            if group_data["ips"]:
                asset["netAdapters"] = [
                    {"ipAddress": ip}
                    for ip in sorted(group_data["ips"])
                ]

            asset_candidates.append(asset)

        logging.info(
            "Built %d asset(s) from %d host group(s) for %s",
            len(asset_candidates), len(host_groups), filename
        )

        try:
            rendered_payload = render_xacta_payload(asset_candidates)
            validate_xacta_json(rendered_payload)
        except Exception as e:
            logging.error("Validation failed for %s: %s", filename, e)
            continue

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(rendered_payload, f, indent=2)

        logging.info("Wrote %s (%d assets)", output_path, len(asset_candidates))


if __name__ == "__main__":
    main()
