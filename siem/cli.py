"""Command-line interface (CLI) for PySIEM operations."""

import argparse
import sys
from siem import auth, storage
from siem.config import DB_PATH, HOST, PORT, RULES_DIR
from siem.ingest import ingest_log_file
from siem.rules import load_rules


def main():
    parser = argparse.ArgumentParser(description="PySIEM - Python Security Information and Event Management")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Ingest command
    ingest_p = subparsers.add_parser("ingest", help="Ingest a log file into PySIEM")
    ingest_p.add_argument("file", help="Path to auth.log file")
    ingest_p.add_argument("--db", default=DB_PATH, help="Path to SQLite database")

    # Serve command
    serve_p = subparsers.add_parser("serve", help="Run the FastAPI web dashboard server")
    serve_p.add_argument("--host", default=HOST, help="Host to bind server")
    serve_p.add_argument("--port", type=int, default=PORT, help="Port to bind server")
    serve_p.add_argument("--reload", action="store_true", help="Enable live reload")

    # Create user command
    user_p = subparsers.add_parser("create-user", help="Create an analyst user")
    user_p.add_argument("username", help="Analyst username")
    user_p.add_argument("password", help="Analyst password")
    user_p.add_argument("--db", default=DB_PATH, help="Path to SQLite database")

    # Check rules command
    subparsers.add_parser("check-rules", help="Validate and list all YAML detection rules")

    args = parser.parse_args()

    if args.command == "ingest":
        print(f"[*] Ingesting log file: {args.file} into {args.db} ...")
        res = ingest_log_file(args.file, db_path=args.db)
        print(f"[+] Events stored: {res['events_stored']}")
        print(f"[+] Ignored lines: {res['ignored_lines']}")
        print(f"[+] Unrecognized lines: {res['unrecognized_lines']}")
        print(f"[+] Alerts generated: {res['alerts_generated']}")
        for a in res["alerts"]:
            print(f"    - [{a['severity'].upper()}] {a['title']} (MITRE: {a.get('mitre_tag')})")

    elif args.command == "serve":
        import uvicorn
        storage.init_db(DB_PATH)
        auth.init_default_admin(DB_PATH)
        print(f"[*] Starting PySIEM Web Dashboard at http://{args.host}:{args.port}")
        uvicorn.run("siem.api:app", host=args.host, port=args.port, reload=args.reload)

    elif args.command == "create-user":
        storage.init_db(args.db)
        p_hash, salt = auth.hash_password(args.password)
        storage.create_user(args.username, p_hash, salt, db_path=args.db)
        print(f"[+] Successfully created user: {args.username}")

    elif args.command == "check-rules":
        rules = load_rules(RULES_DIR)
        print(f"[*] Found {len(rules)} detection rules in {RULES_DIR}:")
        for r in rules:
            print(f"    - {r.id}: {r.name} [{r.severity.upper()}] (MITRE: {r.mitre_attack})")


if __name__ == "__main__":
    main()
