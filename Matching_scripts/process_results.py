import json

def mark_duplicates(semgrep_results_file):
    with open(semgrep_results_file, "r") as f:
        semgrep_results = json.load(f)

    duplicates = {}  # Map check_name to set of file paths
    for result in semgrep_results["results"]:
        if len(result["extra"]["lines"]) > 1:
            duplicates.setdefault(result["extra"]["metadata"]["check_name"], set()).add(result["extra"]["lines"][0]["path"])

    with open("snyk-results.json", "r") as f:
        snyk_results = json.load(f)

    for vuln in snyk_results["vulnerabilities"]:
        for file_path in vuln["from"]:
            for check_name, paths in duplicates.items():
                if file_path in paths:
                    vuln["identifiers"].append({"type": "CWE", "value": "Duplicate"})
                    vuln["severity"] = "critical"  
                    break  # No need to check other checks

    # Add unique CodeQL issues not matched by Semgrep
    for item in json.load(open("codeql-results.json")):
        if item['check_name'] not in duplicates:
            snyk_results["vulnerabilities"].append({
                "id": f"CodeQL-{item['check_name']}",
                "title": item['check_name'],
                "description": item['description'],
                "severity": item['severity'],
                "packageName": "N/A",
                "version": "N/A",
                "from": ["N/A"],
                "upgradePath": [],
                "identifiers": [{"type": "CWE", "value": "CodeQL"}]
            })

    with open("consolidated_results.json", "w") as f:
        json.dump(snyk_results, f, indent=2)
