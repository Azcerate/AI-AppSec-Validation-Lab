findings = [
    {
        "title": "SQL Injection",
        "severity": "Critical",
        "component": "login form",
        "status": "Open",
        "explanation": "User input reaches the database query without proper parameterization."
    },
    {
        "title": "Hardcoded Secret",
        "severity": "High",
        "component": "config.py",
        "status": "Open",
        "explanation": "A credential appears to be stored directly in code and may be exposed."
    },
    {
        "title": "Outdated Dependency",
        "severity": "Medium",
        "component": "requirements.txt",
        "status": "Open",
        "explanation": "A package version contains known vulnerabilities and should be updated."
    }
]