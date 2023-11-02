import pefile
# import peutils
import sys

from pathlib import Path

from .util import warn

def get_packed_status_and_warnings(file_path):
    try:
        if not file_path.is_file():
            warn(f"Not a valid file: {file_path}")
            return None, None
    except OSError as e:
        warn(f"{e}")
        return None, None
    try:
        pe = pefile.PE(file_path, fast_load=True)
    except pefile.PEFormatError as e:
        if str(e) != "'The file is empty'":
            warn(f"{e}: {file_path}")
        return None, None
    return packed_section_flags(pe), pe.get_warnings()

# def packed_peutils(pe): # incorrect result often given for installer EXEs.
#     return peutils.is_probably_packed(pe)

def packed_section_flags(pe):
    for s in pe.sections:
        if s.IMAGE_SCN_MEM_WRITE and s.IMAGE_SCN_MEM_EXECUTE:
            return True
    return False
