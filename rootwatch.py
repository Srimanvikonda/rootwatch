
from auditor.users import run_user_audit
from auditor.ssh_audit import run_ssh_audit


def display_findings(title, findings):
    print(f"\n[{title}]\n")

    for finding in findings:
        print(f"Check    : {finding['check']}")
        print(f"Severity : {finding['severity']}")
        print(f"Status   : {finding['status']}")
        print(f"Details  : {finding['details']}")
        print("-" * 50)


def main():
    print("=" * 50)
    print("       ROOTWATCH - LINUX SECURITY AUDITOR")
    print("=" * 50)

    display_findings("1. USER & PRIVILEGE AUDIT", run_user_audit())
    display_findings("2. SSH SECURITY AUDIT", run_ssh_audit())


if __name__ == "__main__":
    main()
