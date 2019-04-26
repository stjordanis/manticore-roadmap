import argparse
import os

parser = argparse.ArgumentParser(description='Analyze how well Manticore supports a target binary')
parser.add_argument('filename', help="Target binary executable")
parser.add_argument('--stdin_file', help="File to read stdin data from")
parser.add_argument('--timeout', type=int, help="Timeout for running target program (seconds)")
parser.add_argument('--ratio', action='store_true', help="Only print the syscall similarity ratio")
parser.add_argument('--args', nargs=argparse.REMAINDER, help="Arguments to pass to the target binary")

args = parser.parse_args()

if not os.path.exists(args.file):
    print(f"Error: Invalid file path: {args.file}")
    exit(1)
