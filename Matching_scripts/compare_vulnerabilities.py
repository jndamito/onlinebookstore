import json
import os

def load_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def find_vulnerabilities(data, source):
    vulnerabilities = []
    if source == 'snyk':
        for vulnerability in data.get("vulnerabilities", []):
            vulnerabilities.append({
                "title": vulnerability["title"],
                "severity": vulnerability["severity"],
                "path": vulnerability.get("packageName", ""),
                "id": vulnerability.get("id", "")
            })
    elif source == 'codeql':
        for result in data:
            vulnerabilities.append({
                "title": result["check_name"],
                "severity": result["severity"],
                "path": result["location"]["path"],
                "id": result["fingerprint"]
            })
    return vulnerabilities

def compare_vulnerabilities(snyk_vulns, codeql_vulns):
    matched = []
    snyk_only = []
    codeql_only = []

    snyk_titles = {vuln['title']: vuln for vuln in snyk_vulns}
    codeql_titles = {vuln['title']: vuln for vuln in codeql_vulns}

    for title in snyk_titles:
        if title in codeql_titles:
            matched.append((snyk_titles[title], codeql_titles[title]))
        else:
            snyk_only.append(snyk_titles[title])

    for title in codeql_titles:
        if title not in snyk_titles:
            codeql_only.append(codeql_titles[title])

    return matched, snyk_only, codeql_only

def generate_report(matched, snyk_only, codeql_only, output_path):
    report = {
        "matched_vulnerabilities": [
            {
                "title": snyk_vuln["title"],
                "snyk": {
                    "severity": snyk_vuln["severity"],
                    "path": snyk_vuln["path"],
                    "id": snyk_vuln["id"]
                },
                "codeql": {
                    "severity": codeql_vuln["severity"],
                    "path": codeql_vuln["path"],
                    "id": codeql_vuln["id"]
                }
            } for snyk_vuln, codeql_vuln in matched
        ],
        "snyk_only_vulnerabilities": snyk_only,
        "codeql_only_vulnerabilities": codeql_only
    }

    with open(output_path, 'w') as file:
        json.dump(report, file, indent=4)

def main(snyk_path, codeql_path, output_path):
    snyk_data = load_json(snyk_path)
    codeql_data = load_json(codeql_path)

    snyk_vulns = find_vulnerabilities(snyk_data, 'snyk')
    codeql_vulns = find_vulnerabilities(codeql_data, 'codeql')

    matched, snyk_only, codeql_only = compare_vulnerabilities(snyk_vulns, codeql_vulns)

    generate_report(matched, snyk_only, codeql_only, output_path)

if __name__ == '__main__':
    snyk_path = 'snyk-results/snyk_results.json'
    codeql_path = 'codeql-results/codeql-results.json'
    output_path = 'consolidated_results.json'
    main(snyk_path, codeql_path, output_path)
