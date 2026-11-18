
import shutil
import subprocess


def get_ssh_configuration():
    """Retrieve effective SSH configuration, retrying with sudo if needed."""

    sshd_path = shutil.which("sshd") or "/usr/sbin/sshd"

    commands = [[sshd_path, "-T"]]

    sudo_path = shutil.which("sudo")

    if sudo_path:
        commands.append([sudo_path, "-n", sshd_path, "-T"])

    for command in commands:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )

            if result.returncode == 0:
                configuration = {}

                for line in result.stdout.splitlines():
                    parts = line.split(maxsplit=1)

                    if len(parts) == 2:
                        configuration[parts[0].lower()] = (
                            parts[1].lower()
                        )

                return configuration, None

        except subprocess.TimeoutExpired:
            return None, "SSH configuration check timed out"

        except OSError as error:
            return None, str(error)

    error_message = result.stderr.strip()

    return None, (
        error_message or
        "Unable to retrieve effective SSH configuration"
    )


def create_finding(check, severity, status, details):
    """Create a standardized security finding."""

    return {
        "check": check,
        "severity": severity,
        "status": status,
        "details": details
    }


def run_ssh_audit():
    """Run SSH server security configuration checks."""

    findings = []

    config, error = get_ssh_configuration()

    if error:
        return [
            create_finding(
                "SSH Configuration Audit",
                "MEDIUM",
                "ERROR",
                error
            )
        ]

    # 1. Root login audit
    root_login = config.get("permitrootlogin", "unknown")

    if root_login == "no":
        findings.append(create_finding(
            "Root Login Audit", "HIGH", "PASS",
            "Direct root login is disabled"
        ))
    elif root_login == "prohibit-password":
        findings.append(create_finding(
            "Root Login Audit", "MEDIUM", "REVIEW",
            "Root login is allowed using non-password authentication"
        ))
    else:
        findings.append(create_finding(
            "Root Login Audit", "HIGH", "FAIL",
            f"Root login setting is {root_login}"
        ))

    # 2. Password authentication audit
    password_auth = config.get("passwordauthentication", "unknown")

    if password_auth == "no":
        findings.append(create_finding(
            "Password Authentication Audit", "HIGH", "PASS",
            "Password-based SSH authentication is disabled"
        ))
    else:
        findings.append(create_finding(
            "Password Authentication Audit", "MEDIUM", "FAIL",
            f"Password authentication setting is {password_auth}"
        ))

    # 3. Public key authentication audit
    public_key = config.get("pubkeyauthentication", "unknown")

    if public_key == "yes":
        findings.append(create_finding(
            "Public Key Authentication Audit", "INFO", "PASS",
            "Public key authentication is enabled"
        ))
    else:
        findings.append(create_finding(
            "Public Key Authentication Audit", "HIGH", "REVIEW",
            f"Public key authentication setting is {public_key}"
        ))

    # 4. Maximum authentication attempts audit
    try:
        max_attempts = int(config.get("maxauthtries", "0"))

        if 1 <= max_attempts <= 4:
            findings.append(create_finding(
                "SSH Authentication Attempts Audit", "MEDIUM", "PASS",
                f"Maximum authentication attempts: {max_attempts}"
            ))
        else:
            findings.append(create_finding(
                "SSH Authentication Attempts Audit", "MEDIUM", "REVIEW",
                f"Maximum authentication attempts: {max_attempts}; "
                "consider a limit of 4 or fewer"
            ))

    except ValueError:
        findings.append(create_finding(
            "SSH Authentication Attempts Audit", "MEDIUM", "ERROR",
            "Unable to interpret MaxAuthTries setting"
        ))

    # 5. X11 forwarding audit
    x11_forwarding = config.get("x11forwarding", "unknown")

    if x11_forwarding == "no":
        findings.append(create_finding(
            "X11 Forwarding Audit", "LOW", "PASS",
            "X11 forwarding is disabled"
        ))
    else:
        findings.append(create_finding(
            "X11 Forwarding Audit", "LOW", "REVIEW",
            f"X11 forwarding setting is {x11_forwarding}; "
            "disable it if not required"
        ))

    return findings
