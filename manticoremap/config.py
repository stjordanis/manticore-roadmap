import argparse
import os

parser = argparse.ArgumentParser(description='Analyze how well Manticore supports a target binary')
parser.add_argument('filename', help="Target binary executable")
parser.add_argument('--stdin_file', help="File to read stdin data from", default='/dev/null')
parser.add_argument('--timeout', type=int, help="Timeout for running target program (seconds)")
parser.add_argument('--ratio', action='store_true', help="Only print the syscall similarity ratio")
parser.add_argument('--args', nargs=argparse.REMAINDER, default=[], help="Arguments to pass to the target binary")

args = parser.parse_args()
args.abspath = os.path.abspath(args.filename)
args.stdin_abspath = os.path.abspath(args.stdin_file)

if not os.path.exists(args.filename):
    print(f"Error: Invalid file path: {args.filename}")
    exit(1)
