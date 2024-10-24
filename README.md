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

I'll help clean up and restructure this section to make it clearer and more impactful.

### How is this different from CVSS or EPSS?

While both CVSS and EPSS are valuable approaches to vulnerability assessment, they don't address dependencies or preconditions. As stated by EPSS:

> EPSS is a measure of threat – it estimates the probability that a vulnerability will experience exploitation activity in the wild.

It's crucial to understand the distinction here: We think EPSS predicts the probability of experiencing an *attempted* exploitation, not a *successful* one. These are fundamentally different events. While EPSS can estimate the likelihood of an attempt, it cannot determine the probability of success.

Consider CVE-2021-40438 as an example. This vulnerability has an EPSS score of 0.96 (very close to 1.0, indicating a high likelihood of attempted exploitation). However, our analysis shows that successful exploitation requires specific preconditions:
- mod_proxy must be enabled
- A reverse proxy configuration must be present

So while EPSS correctly indicates you're likely to face an exploit attempt within 30 days, it provides no insight into whether that attempt could succeed given your specific configuration.

Similarly, CVSS serves a different purpose:

> CVSS is thought of as a measure of overall "severity" of a vulnerability.

CVSS provides a useful way to understand the theoretical impact of a vulnerability, but like EPSS, it doesn't account for the actual configurations and dependencies required for exploitation.

Our approach complements these existing frameworks by:
- Focusing on dependency relationships
- Identifying specific preconditions required for exploitation
- Providing context for vulnerability remediation priorities

While our method is currently manual and requires significant effort, we believe this work is essential to provide a clear prioritization framework for vulnerability remediation.

Reference: [EPSS FAQ](https://www.first.org/epss/faq)

## Schema Structure

Each CVE entry contains:

```json
{
  "id": "CVE ID",
  "description": "Vulnerability description",
  "known_exploited": true,
  "dependencies": {
    "features": ["list of required features"],
    "conditions": ["list of required conditions"],
    "configuration": ["specific configs needed"],
    "notes": ["Additional context"]
  },
  "resources": {
    "nvd": "Link to NVD entry",
    "epss": "https://api.first.org/data/v1/epss?cve=CVE-XXXX-XXXXX",
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
