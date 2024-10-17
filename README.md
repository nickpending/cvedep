![image](https://github.com/user-attachments/assets/94c98b51-9d71-465c-b1c2-94bd2348d059)

# CVEDEP: CVE Dependencies Dataset

> A structured dataset documenting the real-world dependencies and conditions required for exploiting Common Vulnerabilities and Exposures (CVEs).

## Why CVEDEP?

Security teams are bombarded daily with vulnerability scanner outputs flagging "critical" CVEs without proper context. While many of these vulnerabilities are legitimately severe, their actual exploitability often depends on specific conditions that may not exist in your environment.

CVEDEP helps security teams by:
- Documenting specific exploitation dependencies and conditions
- Clarifying what features or configurations must be present
- Providing verified technical references
- Enabling better prioritization of remediation efforts

## Schema Structure

Each CVE entry contains:

```json
{
  "id": "CVE ID",
  "nvd_link": "Link to NVD entry",
  "description": "Vulnerability description",
  "known_exploited": true,
  "dependencies": {
    "features": ["list of required features"],
    "conditions": ["list of required conditions"],
    "configuration": ["specific configs needed"],
    "notes": ["Additional context"]
  },
  "resources": {
    "official_advisory": "link",
    "poc": "link",
    "patches": "link"
  },
  "metadata": {
    "date_added": "YYYY-MM-DD",
    "last_updated": "YYYY-MM-DD",
    "contributor": "github_username"
  }
}
```

## Usage

Query the dataset using standard JSON tools. Here are common scenarios and their queries:

```bash
# Find "truly critical" CVEs - known exploited with no dependencies
jq '
.vulnerabilities[] | 
select(
  .known_exploited == true and 
  (.dependencies.features | length == 0) and
  (.dependencies.conditions | length == 0) and
  (.dependencies.configuration | length == 0)
)' cvedep.json

# Find CVEs requiring specific features
jq '.vulnerabilities[] | select(.dependencies.features[] | contains("proxy"))' cvedep.json

# List known exploited vulnerabilities by CVSS score (highest first)
jq -r '
.vulnerabilities[] | 
select(.known_exploited==true) | 
[.id, .cvss_score, .description] | 
@tsv' cvedep.json | sort -rnk2

# Find CVEs with complex dependency chains (requiring multiple conditions)
jq '.vulnerabilities[] | 
select(
  (.dependencies.features | length > 1) or
  (.dependencies.conditions | length > 1)
)' cvedep.json

# Search for CVEs affecting a specific configuration
jq '.vulnerabilities[] | 
select(.dependencies.configuration[] | 
contains("ProxyPass"))' cvedep.json

# Export a simple report of high-risk CVEs (known exploited, CVSS >= 7.0)
jq -r '
.vulnerabilities[] | 
select(.known_exploited==true and .cvss_score >= 7.0) | 
"CVE: \(.id)\nCVSS: \(.cvss_score)\nDescription: \(.description)\nDependencies: \(.dependencies.notes)\n"
' cvedep.json

# Count CVEs by dependency type
jq -r '
.vulnerabilities | 
group_by(.dependencies.features | length) | 
map({dep_count: .[0].dependencies.features | length, count: length}) | 
.[] | [.dep_count, .count] | @tsv
' cvedep.json

# Find CVEs missing key information (for maintenance)
jq '.vulnerabilities[] | 
select(
  .nvd_link == null or 
  .cvss_score == null or 
  .dependencies.notes == ""
) | .id' cvedep.json
```

Example output for "truly critical" CVEs (known exploited, no dependencies):
```json
{
  "id": "CVE-2023-XXXXX",
  "nvd_link": "https://nvd.nist.gov/vuln/detail/CVE-2023-XXXXX",
  "description": "Remote Code Execution in default configuration",
  "known_exploited": true,
  "dependencies": {
    "features": [],
    "conditions": [],
    "configuration": [],
    "notes": ["Exploitable in default configuration without additional requirements"]
  },
  "resources": {
    "official_advisory": "https://example.com/advisory",
    "poc": "https://github.com/example/poc",
    "patches": "https://github.com/example/patch"
  }
}
```

## Contributing

### Guidelines
1. Verify all dependencies and conditions through testing
2. Include links to official advisories when available
3. Document clear reproduction conditions
4. Provide accurate technical references

### Process
1. Fork the repository
2. Add new CVE entries following the schema
3. Test and verify conditions
4. Submit a pull request

### Pull Request Requirements
- Follow the exact JSON schema
- Include relevant references
- Test dependencies and conditions
- Add meaningful notes

## Installation

```bash
# Clone the repository
git clone https://github.com/username/cvedep
cd cvedep

# Install jq if you haven't already
# macOS
brew install jq

# Linux
sudo apt-get install jq

# Windows (using Chocolatey)
choco install jq
```

## Automated Validation

The repository includes a simple validation script to ensure JSON schema compliance:

```bash
# Validate your entries
./validate.sh
```

## Contributing Data Sources

If you have access to datasets that could enrich CVEDEP, please:
1. Ensure you have rights to share the data
2. Convert it to match our schema
3. Submit a pull request with the new entries
4. Include source attribution in metadata

## License

MIT License

## Acknowledgments

Thanks to all security researchers and contributors who help maintain and verify this dataset.

---

**Note**: This project focuses solely on documenting exploitation requirements and conditions. For mitigation strategies, please refer to official advisories and security documentation for your specific systems.
