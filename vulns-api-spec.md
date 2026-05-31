These are new endpoints to add to the vulnerabilities API.

## Get information about a Vulnerability
For a given CVE, this returns information from the KB.

### Request Schema
{
group*: string
Default: Vulnerabilities
action*: string
Default: get_information
data*: {
Request

username*: string
Username of the api user

key*: string
Key of the user

cve*: string
CVE id to query

}
}

### Response Schema
{
operation: string
Default: vulnerabilities_get_information
status: string
data: {
cve: [{
id: integer
cve: string
cvss_version: string
base_score: integer
severity: string
attack_vector: string
attack_complexity: string
availability_impact: string
rejected: integer
cpes: [string]
}]
component_vulnerability_in_scans: [{
id: integer
scan_id: integer
component_id: integer
cve: string
status: null or string
justification: null or string
response: null or string
details: null or string
created_by: integer
updated_by: null or integer
created: string
updated: string
code: string
}]
}
}

### Sample Response
{
  "operation": "vulnerabilities_get_information",
  "status": "1",
  "data": {
    "cve": [
      {
        "id": 25218,
        "cve": "CVE-2021-20089",
        "cvss_version": "3.1",
        "base_score": "8.8",
        "severity": "HIGH",
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "availability_impact": "PARTIAL",
        "rejected": 0,
        "cpes": [
          "cpe:2.3:a:purl_project:purl:2.3.2:*:*:*:*:*:*:*"
        ]
      }
    ],
    "component_vulnerability_in_scans": [
      {
        "id": 96,
        "scan_id": 387,
        "component_id": 1909,
        "cve": "CVE-2021-20089",
        "status": "not_affected",
        "justification": "code_not_reachable",
        "response": "will_not_fix",
        "details": "",
        "created_by": 1,
        "updated_by": 1,
        "created": "2024-10-11 10:45:35",
        "updated": "2024-10-11 10:50:37",
        "code": "scan_code"
      }
    ]
  }
}

## Create Vulnerability Exploitability
For a given CVE in a Scan, this creates the VEX Statements.

### Request Schema
{
group*: string
Default: Vulnerabilities
action*: string
Default: vulnerability_exploitability_create
data*: {
Request

username*: string
Username of the api user

key*: string
Key of the user

cve*: string
CVE id to create VEX for

component_id*: integer
Id of Component to create VEX for

scan_code*: string
Scan code to create VEX for

vuln_exp_status: null or string
vuln_exp_justification: null or string
vuln_exp_response: null or string
vuln_exp_details: null or string
}
}
### Response Schema
{
operation: string
Default: vulnerabilities_vulnerability_exploitability_create
status: string
data: {
id: integer
}
message: string
}
### Sample Response
{
"operation": "vulnerabilities_vulnerability_exploitability_create",
"status": "1",
"data": {
"id": 140
},
"message": "Vulnerability exploitability has been created"
}

## Update Vulnerability Exploitability
This operation updates a VEX statement in a Scan

### Request Schema
{
group*: string
Default: Vulnerabilities
action*: string
Default: vulnerability_exploitability_update
data*: {
Request

username*: string
Username of the api user

key*: string
Key of the user

vuln_exp_id*: integer
VEX id to update

vuln_exp_status: null or string
vuln_exp_justification: null or string
vuln_exp_response: null or string
vuln_exp_details: null or string
}
}

### Response Schema
{
operation: string
Default: vulnerabilities_vulnerability_exploitability_update
status: string
data: null
message: string
}
### Sample Response
{
"operation": "vulnerabilities_vulnerability_exploitability_update",
"status": "1",
"data": null
"message": "Vulnerability exploitability has been updated"
}

## Import Vulnerability Exploitability from scan
This operation reuses VEX from one scan into another by providing the source and destination scan codes
.
### Request Schema
{
group*: string
Default: Vulnerabilities
action*: string
Default: import_vulnerability_exploitability_from_scan
data*: {
Request

username*: string
Username of the api user

key*: string
Key of the user

scan_code_from*: string
The source scan to read the VEX information from

scan_code_to*: string
The destination scan to import the VEX information into

override_vex: string
Optional, boolean (0 default, 1). Set to 1 to override the VEX information from the destination scan with the information from the source scan

}
}
### Response Schema
{
operation: string
Default: vulnerabilities_import_vulnerability_exploitability_from_scan
status: string
data [ ]
message: string
}
### Sample Response
{
"operation": "vulnerabilities_import_vulnerability_exploitability_from_scan",
"status": "1",
"data": [ ],
"message": "Vulnerability exploitability import finished, 1 matching components found, 1 vulnerability exploitability records imported"
}