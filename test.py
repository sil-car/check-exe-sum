#!/usr/bin/env python3

import os
import pefile
import sys

from pathlib import Path

exe = Path(sys.argv[1])
if not exe.is_file():
    print(f"Error: File not found: {exe}")
    exit(1)

print(os.stat(exe))
# pe = pefile.PE(str(exe))
pe = pefile.PE(exe, fast_load=True)
# pe = pefile.PE(exe)

# print(pe.dump_info())
# # print(pe.OPTIONAL_HEADER)
# # print(pe.FILE_HEADER)
# print(pe.DOS_HEADER)
# print(pe.NT_HEADERS)
# for section in pe.sections:
#     print(
#         section.Name.decode(),
#         hex(section.VirtualAddress),
#         hex(section.Misc_VirtualSize),
#         section.SizeOfRawData,
#     )
#     if section.Name == b'.reloc\x00\x00':
#         # print(dir(section))
#         print(section.Characteristics)
#         print(section.Misc)
#         print(section.NumberOfRelocations)
#         print(section.IMAGE_SCN_MEM_WRITE)
#         print(section.IMAGE_SCN_MEM_EXECUTE)
#     # Final newline.
#     print()
# print(pe.generate_checksum())
# print(pe.OPTIONAL_HEADER.CheckSum)

