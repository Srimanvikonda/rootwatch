
from auditor.users import run_user_audit


def main():
    print("=" * 50)
    print("       ROOTWATCH - LINUX SECURITY AUDITOR")
    print("=" * 50)

    print("\n[1] USER & PRIVILEGE AUDIT\n")

    findings = run_user_audit()

    for finding in findings:
        print(f"Check    : {finding['check']}")
        print(f"Severity : {finding['severity']}")
        print(f"Status   : {finding['status']}")
        print(f"Details  : {finding['details']}")
        print("-" * 50)


if __name__ == "__main__":
    main()
