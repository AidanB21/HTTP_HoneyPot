#import libraries
import argparse
from ssh_honeypot import honeypot
from web_honeypot import run_web_honeypot

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-a', '--address', type=str, required=True)
    parser.add_argument('-p', '--port', type=int, required=True)  # Fixed type=int
    parser.add_argument('-u', '--username', type=str)
    parser.add_argument('-pw', '--password', type=str)

    parser.add_argument('-s', "--ssh", action="store_true")
    parser.add_argument('-w', "--http", action="store_true")  # Fixed --http

    args = parser.parse_args()
    print(f"Debug: SSH={args.ssh}, HTTP={args.http}")  # Print parsed arguments


    try:
        # Debugging to check argument values
        print(f"Debug: SSH={args.ssh}, HTTP={args.http}")

        if args.ssh and args.http:
            print("Error! You cannot run both SSH and HTTP honeypots at the same time. Choose one.")
            exit(1)

        elif args.ssh:
            print("[-] Running SSH Honeypot...")
            honeypot(args.address, args.port, args.username, args.password)

        elif args.http:
            print("[-] Running HTTP WordPress Honeypot...")

            # Set defaults for HTTP honeypot
            if not args.username:
                args.username = "admin"
            if not args.password:
                args.password = "password"

            print(f"Port: {args.port} | Username: {args.username} | Password: {args.password}")
            run_web_honeypot(args.port, args.username, args.password)

        else:
            print("Error! Choose a particular type (SSH --ssh) or (HTTP --http).")

    except Exception as e:
        print("\n Exiting HONEYPY...\n", str(e))
