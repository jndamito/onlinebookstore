import json

def mark_duplicates(semgrep_results_file):
    with open(semgrep_results_file, "r") as f:
        semgrep_results = json.load(f)

    duplicates_by_path_and_line = set()  # Store duplicates with file and line
    duplicates_by_title = set()          # Store duplicates with matching titles/descriptions

    for result in semgrep_results["results"]:
        if len(result["extra"]["lines"]) > 1:
            # Check if it's a file and line match
            snyk_finding, codeql_finding = result["extra"]["lines"]
            if snyk_finding["source"] == "snyk-results.json" and codeql_finding["source"] == "codeql-results.json":
                snyk_path = snyk_finding["path"].split(":")[-1]  # Extract module path
                if snyk_path == codeql_finding["path"]:
                    duplicates_by_path_and_line.add(snyk_path)  # Use Snyk path as key

            # Check if it's a title/description match
            if result["check_id"] == "duplicate-finding-snyk-codeql":
                duplicates_by_title.add(snyk_finding["path"]) # Use Snyk path as key

    with open("codeql-results.json", "r") as f:
        codeql_results = json.load(f)

    # Mark duplicates in CodeQL results
    for finding in codeql_results:
        path = finding["location"]["path"]
        if path in duplicates_by_path_and_line or path in duplicates_by_title:
            finding["severity"] = "error"
            finding["confirmation"] = "Confirmed by Snyk"

    with open("consolidated_results.json", "w") as f:
        json.dump(codeql_results, f, indent=2)


if __name__ == "__main__":
    import sys
    mark_duplicates(sys.argv[1])
