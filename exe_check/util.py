import sys

def warn(text):
    print(f"Warning: {text}", file=sys.stderr)

def error(text):
    print(f"Error: {text}", file=sys.stderr)
    exit(1)
