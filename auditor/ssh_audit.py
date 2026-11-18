
import shutil
import subprocess


def get_ssh_configuration():
    """Retrieve effective SSH configuration, retrying with sudo if needed."""

    sshd_path = shutil.which("sshd") or "/usr/sbin/sshd"

    commands = [
        [sshd_path, "-T"]
    ]

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
