# When testing, use:
# (env) $ python3 -c 'import check_exe.cli; check_exe.cli.main()' [ARGS]
# This makes it run the same way as installed version, which makes imports work correctly. 

import argparse
import pefile
import sys
from pathlib import Path

from . import packing
from .util import error


def get_full_path(input_str):
    return Path(input_str).expanduser().resolve()

def check_file(f):
    packing.show_packed_status(f, *packing.get_packed_status_and_warnings(f))

def list_packed_files(base_dir, exts):
    """ Scan folder and all subfolders for packed EXE, etc. files. """
    # Putting the glob generator directly in the for-loop allows real-time file
    #   checking. Otherwise, all the files have to be found first, then they can
    #   be checked.
    for f in (p for p in base_dir.rglob('*') if p.suffix.lower() in exts):
        packing.show_packed_status(f, *packing.get_packed_status_and_warnings(f))

def show_file_info(f):
    # Dump all PE info to stdout.
    pe = pefile.PE(f, fast_load=True)
    print(pe.dump_info())

def main():
    description = "Quickly determine if EXE or other similar file has been \"packed\" with extra data; i.e. it has been corrupted by a virus."
    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        )
    parser.add_argument(
        '-d', '--directory',
        action='store_true',
        help="arg is a directory; recursively check all EXE and similar files within",
    )
    parser.add_argument(
        '-i', '--info',
        action='store_true',
        help="show all Portable Executable-related info for the given file",
    )
    parser.add_argument(
        'file',
        nargs='?',
        help="check the given EXE (or similar) file for evidence of packing",
    )
    args = parser.parse_args()
    exts = ['.dll', '.exe']

    if args.file is None:
        parser.print_help()
        exit(1)

    full_path = get_full_path(args.file)

    if args.directory:
        # Scan folder and all subfolders for packed EXE files.
        base_dir = full_path
        if not base_dir.is_dir():
            error(f"Not a folder: {base_dir}")

        # Putting the glob generator directly in the for-loop allows real-time file
        #   checking. Otherwise, all the files have to be found first, then they can
        #   be checked.
        list_packed_files(base_dir, exts)
        exit()

    elif args.info:
        target_file = full_path
        if not target_file.is_file():
            error(f"File not found: {target_file}")
        show_file_info(target_file)
        exit()

    elif args.file:
        target_file = full_path
        if not target_file.is_file():
            error(f"File not found: {target_file}")
        if not target_file.suffix.lower() in exts:
            error(f"Invalid file type: {target_file}")
        check_file(target_file)
        exit()
