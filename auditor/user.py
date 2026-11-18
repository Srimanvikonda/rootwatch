
import subprocess


def check_root_users():
    """Identify accounts with UID 0."""

    findings = []

    try:
        with open("/etc/passwd", "r", encoding="utf-8") as file:
            for line in file:
                fields = line.strip().split(":")

                if len(fields) < 7:
                    continue

                username = fields[0]
                uid = fields[2]

                if uid == "0" and username != "root":
                    findings.append({
                        "check": "Root Privilege Audit",
                        "severity": "HIGH",
                        "status": "FAIL",
                        "details": (
                            f"Unexpected UID 0 account: {username}"
                        )
                    })

    except PermissionError:
        findings.append({
            "check": "Root Privilege Audit",
            "severity": "MEDIUM",
            "status": "ERROR",
            "details": "Permission denied while reading /etc/passwd"
        })

    return findings


def check_sudo_users():
    """List users belonging to the sudo group."""

    findings = []

    try:
        result = subprocess.run(
            ["getent", "group", "sudo"],
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode != 0 or not result.stdout.strip():
            return [{
                "check": "Sudo Group Audit",
                "severity": "MEDIUM",
                "status": "ERROR",
                "details": "Unable to retrieve sudo group information"
            }]

        fields = result.stdout.strip().split(":")
        members = fields[3].split(",") if fields[3] else []

        findings.append({
            "check": "Sudo Group Audit",
            "severity": "INFO",
            "status": "REVIEW",
            "details": f"Users with sudo group membership: {members}"
        })

    except FileNotFoundError:
        findings.append({
            "check": "Sudo Group Audit",
            "severity": "MEDIUM",
            "status": "ERROR",
            "details": "getent utility is unavailable"
        })

    return findings


def run_user_audit():
    """Execute all user security checks."""

    results = []

    results.extend(check_root_users())
    results.extend(check_sudo_users())

    return results
