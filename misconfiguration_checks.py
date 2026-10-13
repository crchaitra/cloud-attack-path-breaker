
"""Detect potentially dangerous settings in a simulated cloud graph."""


def check_misconfigurations(cloud):
    """Return warnings for resources with risky configurations."""
    findings = []

    for resource_id, attributes in cloud.nodes(data=True):
        resource_name = attributes.get("name", resource_id)
        resource_type = attributes.get("type", "unknown")
        public = attributes.get("public", False)
        sensitivity = attributes.get("sensitivity", "low")

        # Rule 1: Public resources containing highly sensitive data.
        if public and sensitivity in {"high", "critical"}:
            findings.append({
                "resource_id": resource_id,
                "resource_name": resource_name,
                "severity": "HIGH",
                "rule": "Public sensitive resource",
                "message": (
                    f"{resource_name} is public and has "
                    f"{sensitivity} sensitivity."
                ),
                "recommendation": (
                    "Review public exposure and restrict access "
                    "if public access is not required."
                ),
            })

        # Rule 2: Public storage resources.
        if public and resource_type == "storage":
            findings.append({
                "resource_id": resource_id,
                "resource_name": resource_name,
                "severity": "HIGH",
                "rule": "Public storage",
                "message": (
                    f"Storage resource {resource_name} is publicly exposed."
                ),
                "recommendation": (
                    "Review storage permissions and disable public "
                    "access unless it is explicitly required."
                ),
            })

    return findings
