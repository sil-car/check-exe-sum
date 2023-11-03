# When testing, use:
# (env) $ python3 -c 'import exe_check.cli; exe_check.cli.main()' [ARGS]
# This makes it run the same way as installed version, which makes imports work correctly. 

import argparse
import pefile
import sys
from pathlib import Path

from . import config
from . import packing
from .util import error
from .util import get_valid_size_status
from .util import show_file_status


def get_full_path(input_str):
    return Path(input_str).expanduser().resolve()

def check_file(f):
    status = 'Good'
    reasons = []
    # Check for zero size.
    if get_valid_size_status(f) is False:
        status = 'Bad'
        reasons.append('File has zero length.')
    # Check for packing.
    res = packing.get_packed_status_and_reasons(f)
    if res[0] is None and status == 'Good':
        status = 'Unknown'
        if res[1] is not None:
            reasons.extend(res[1])
    elif res[0] is True:
        status = 'Bad'
        if res[1] is not None:
            reasons.extend(res[1])
    return status, reasons

def show_file_results(file_path):
    status, reasons = check_file(file_path)
    show_file_status(file_path, status, reasons)

def evaluate_dir_path(base_dir, exts):
    """ Scan folder and all subfolders for packed EXE, etc. files. """
    # Putting the glob generator directly in the for-loop allows real-time file
    #   checking. Otherwise, all the files have to be found first, then they can
    #   be checked.
    for f in (p for p in base_dir.rglob('*') if p.suffix.lower() in exts):
        show_file_results(f)

def show_file_info(f):
    # Dump all PE info to stdout.
    try:
        pe = pefile.PE(f, fast_load=True)
        print(pe.dump_info())
        # # TODO: Testing.
        # packing.packed_mismatched_data_sizes(pe)
    except pefile.PEFormatError as e:
        error(e)

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
        '-V', '--version',
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

    if args.version is True:
        print(config.VERSION)
        exit()

    if args.file is None:
        parser.print_help()
        exit(1)

    full_path = get_full_path(args.file)

    if args.directory:
        # Scan folder and all subfolders for packed EXE files.
        base_dir = full_path
        if not base_dir.is_dir():
            error(f"Not a folder: {base_dir}")
        evaluate_dir_path(base_dir, exts)
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
        show_file_results(target_file)
        exit()
