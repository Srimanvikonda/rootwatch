
import shutil
import subprocess


def get_ssh_configuration():
    """Retrieve the effective SSH server configuration using sshd -T."""

    sshd_path = shutil.which("sshd")

    if not sshd_path:
        return None, "OpenSSH server (sshd) is not installed or not in PATH"

    try:
        result = subprocess.run(
            [sshd_path, "-T"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )

        if result.returncode != 0:
            return None, result.stderr.strip() or "Unable to read SSH configuration"

        configuration = {}

        for line in result.stdout.splitlines():
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                configuration[parts[0].lower()] = parts[1].lower()

        return configuration, None

    except subprocess.TimeoutExpired:
        return None, "SSH configuration check timed out"

    except OSError as error:
        return None, str(error)


def create_finding(check, severity, status, details):
    return {
        "check": check,
        "severity": severity,
        "status": status,
        "details": details
    }


def run_ssh_audit():
    """Check important SSH security settings."""

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

    # 1. Check whether root can log in through SSH.
    root_login = config.get("permitrootlogin")

    if root_login == "no":
        findings.append(create_finding(
            "Root SSH Login",
            "INFO",
            "PASS",
            "Direct root SSH login is disabled"
        ))
    elif root_login == "prohibit-password":
        findings.append(create_finding(
            "Root SSH Login",
            "MEDIUM",
            "REVIEW",
            "Root login is allowed using non-password authentication"
        ))
    else:
        findings.append(create_finding(
            "Root SSH Login",
            "HIGH",
            "FAIL",
            f"Root SSH login setting is '{root_login}'"
        ))

    # 2. Check password authentication.
    password_auth = config.get("passwordauthentication")

    if password_auth == "no":
        findings.append(create_finding(
            "SSH Password Authentication",
            "INFO",
            "PASS",
            "Password-based SSH authentication is disabled"
        ))
    elif password_auth == "yes":
        findings.append(create_finding(
            "SSH Password Authentication",
            "MEDIUM",
            "FAIL",
            "Password-based SSH authentication is enabled"
        ))
    else:
        findings.append(create_finding(
            "SSH Password Authentication",
            "MEDIUM",
            "ERROR",
            f"Unexpected configuration value: {password_auth}"
        ))

    # 3. Check public key authentication.
    public_key_auth = config.get("pubkeyauthentication")

    if public_key_auth == "yes":
        findings.append(create_finding(
            "SSH Public Key Authentication",
            "INFO",
            "PASS",
            "Public key authentication is enabled"
        ))
    else:
        findings.append(create_finding(
            "SSH Public Key Authentication",
            "HIGH",
            "REVIEW",
            f"Public key authentication setting is '{public_key_auth}'"
        ))

    # 4. Check maximum authentication attempts.
    max_auth_tries = config.get("maxauthtries")

    try:
        attempts = int(max_auth_tries)

        if attempts <= 4:
            findings.append(create_finding(
                "SSH Authentication Attempts",
                "INFO",
                "PASS",
                f"Maximum authentication attempts: {attempts}"
            ))
        else:
            findings.append(create_finding(
                "SSH Authentication Attempts",
                "MEDIUM",
                "FAIL",
                f"Maximum authentication attempts are too high: {attempts}"
            ))

    except (TypeError, ValueError):
        findings.append(create_finding(
            "SSH Authentication Attempts",
            "MEDIUM",
            "ERROR",
            f"Invalid MaxAuthTries value: {max_auth_tries}"
        ))

    # 5. Check X11 forwarding.
    x11_forwarding = config.get("x11forwarding")

    if x11_forwarding == "no":
        findings.append(create_finding(
            "SSH X11 Forwarding",
            "INFO",
            "PASS",
            "X11 forwarding is disabled"
        ))
    else:
        findings.append(create_finding(
            "SSH X11 Forwarding",
            "LOW",
            "REVIEW",
            f"X11 forwarding is set to '{x11_forwarding}'"
        ))

    return findings
