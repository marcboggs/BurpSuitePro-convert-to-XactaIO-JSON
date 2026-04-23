# Burp Suite XML to Xacta.io JSON Converter

Converts Burp Suite Professional XML export files into Xacta® JSON format for import into Xacta.io. Intended for FedRAMP RA-5 / CA-7 DAST evidence workflows.

## Scripts

| Script | Description |
|---|---|
| `burp_xml_to_xacta_json.py` | Original converter (v1). Produces a single asset per file. |
| `burp_xml_to_xacta_json_v2.py` | Multi-host converter (v2). Groups findings by hostname, producing one asset per unique host. |

### v2 Improvements Over v1

- Groups issues by normalized hostname — one Xacta asset per unique host in the scan
- Extracts IP addresses from `<host ip="...">` into `netAdapters`
- Populates the `solution` field from Burp remediation data
- Uses object format for `resultData` (key-value pairs per XIO JSON Template v4.0)
- Preserves raw `severity` on each test result

## Requirements

- Python 3.8+
- No external dependencies required

Optional:
- `jsonschema` — enables output validation against the Xacta JSON schema

```bash
pip install jsonschema
```

## Project Structure

```
├── config.ini                      # Configuration file (input/output paths, app name)
├── burp_xml_to_xacta_json.py       # v1 converter (single-host)
├── burp_xml_to_xacta_json_v2.py    # v2 converter (multi-host)
├── compare_run.py                  # Runs both v1 and v2 for side-by-side comparison
├── input/                          # Place Burp XML export files here
├── output/                         # Converted Xacta JSON files written here
├── logs/                           # Log directory
├── docs/                           # Telos XIO reference PDFs
└── Xacta io Documentation/         # XIO JSON template, data dictionary, mapping guide
```

## Configuration

Edit `config.ini` before running:

```ini
[BURP-IOJSON]
INPUT_FOLDER = input
OUTPUT_FOLDER = output
APPLICATION_NAME = Burp-Suite-Pro
SCANNER_VERSION = 2025.4
SYSTEM_NAME = Burp-WebApp-Boundary
LOG_LEVEL = INFO
```

| Setting | Required | Description |
|---|---|---|
| `INPUT_FOLDER` | Yes | Directory containing Burp XML files to convert |
| `OUTPUT_FOLDER` | Yes | Directory where Xacta JSON files will be written |
| `APPLICATION_NAME` | Yes | Application name used as fallback for `systemName` |
| `SCANNER_VERSION` | No | Overrides the `burpVersion` attribute from the XML |
| `SYSTEM_NAME` | No | Xacta accreditation boundary name. Falls back to `APPLICATION_NAME` |
| `LOG_LEVEL` | No | Logging verbosity (not yet wired — defaults to INFO) |

## Usage

1. Export scan results from Burp Suite Professional as XML
2. Place the `.xml` file(s) in the `input/` directory
3. Run the converter:

```bash
# Recommended (v2 - multi-host support)
python burp_xml_to_xacta_json_v2.py

# Original (v1 - single asset per file)
python burp_xml_to_xacta_json.py
```

4. Output files are written to `output/` as `<original-filename>-xacta.json`

### Comparing v1 and v2 Output

```bash
python compare_run.py
```

This runs both scripts and saves output as `-v1.json` and `-v2.json` for comparison.

## Output Format

The output follows the Xacta® JSON schema documented in the [XIO JSON Data Dictionary v2.0](Xacta%20io%20Documentation/xio-json-data-dictionary-2.0.md).

### v2 Output Structure

```json
{
  "assets": [
    {
      "hostName": "app.example.com",
      "dataSource": "Burp Suite Professional",
      "scanDate": "2025-12-04T08:13:50-05:00",
      "systemName": "Burp-WebApp-Boundary",
      "scannerVersion": "2025.4",
      "netAdapters": [
        { "ipAddress": "10.0.1.50" }
      ],
      "testResults": [
        {
          "vendorId": "5243392",
          "testName": "TLS cookie without secure flag set",
          "description": "...",
          "notes": "...",
          "solution": "...",
          "result": "Fail",
          "rawResult": "Fail",
          "riskFactor": "Low",
          "severity": "Information",
          "protocol": "HTTPS",
          "port": 443,
          "resultData": {
            "Source Type": "5243392",
            "External ID": "2537829868855771136",
            "Severity": "Information",
            "Scanner Source": "Burp Suite Professional"
          },
          "contents": [
            { "name": "CWE-614", "type": "CWE" }
          ],
          "runTime": 1764854030000,
          "scannedWithCredentialsFlag": false,
          "errorRunningTestFlag": false
        }
      ]
    }
  ]
}
```

## Field Mapping (Burp XML → Xacta JSON)

| Xacta.io Field | Burp XML Source |
|---|---|
| `hostName` | `<host>` element (normalized, one asset per unique host) |
| `scanDate` | `exportTime` attribute on `<issues>` root |
| `dataSource` | Hardcoded: "Burp Suite Professional" |
| `systemName` | `SYSTEM_NAME` from config.ini |
| `scannerVersion` | `SCANNER_VERSION` from config or `burpVersion` attribute |
| `netAdapters.ipAddress` | `ip` attribute on `<host>` element |
| `testResults.vendorId` | `<type>` or `<serialNumber>` element |
| `testResults.testName` | `<name>` element |
| `testResults.description` | `<issueBackground>` + `<issueDetail>` |
| `testResults.solution` | `<remediationBackground>` + `<remediationDetail>` |
| `testResults.notes` | Composite: host, path, location, confidence, references, remediation, request/response snippets, audit block |
| `testResults.result` | Severity-based: non-pass/n/a → "Fail" |
| `testResults.rawResult` | Same as `result` |
| `testResults.riskFactor` | High→High, Medium→Moderate, Low/Information→Low |
| `testResults.severity` | Raw Burp severity value |
| `testResults.protocol` | Parsed from host URL scheme |
| `testResults.port` | Parsed from host/path URL |
| `testResults.contents` | `<cweid>` → CWE, `<vulnerabilityClassifications>` → CWE |
| `testResults.runTime` | `exportTime` as epoch milliseconds |
| `testResults.resultData` | Object with Source Type, External ID, Severity, Confidence, HTTP Method, Scan Date, Scanner Source/Version |

## Notes

- Request/response bodies are truncated to 100 characters in the `notes` field. Full payloads are not included in the output.
- Burp Suite is a DAST tool — fields like `osList`, `softwares`, `cloudInfo`, `endpointData`, and `cpus` are not applicable and are omitted.
- The `scannedWithCredentialsFlag` is set to `false` since Burp does not provide credential scan metadata.
- Findings with missing `vendorId` or `testName` are skipped with a warning.

## Reference Documentation

- [XIO Mapping Guide v4.0](docs/xio-mapping-guide-4.0.pdf)
- [XIO JSON Data Dictionary v2.0](Xacta%20io%20Documentation/xio-json-data-dictionary-2.0.pdf)
- [Converting to Xacta JSON Using Python v4.0](docs/xio-converting-to-xacta-json-using-python-4.0.pdf)
- [XIO JSON Template](Xacta%20io%20Documentation/XIO%20JSON%20Template.json)
