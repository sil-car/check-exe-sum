### EXE-Check

Quickly determine if EXE or other similar file has been "packed" with extra data;
i.e. it has been corrupted by a virus.

```
$ exe-check ~/Téléchargements/Thunderbird\ Setup\ 102.10.0.exe 
Bad	~/Téléchargements/Thunderbird Setup 102.10.0.exe
  > Suspicious flags set for section 0. Both IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE are set. This might indicate a packed executable.
  > Suspicious flags set for section 1. Both IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE are set. This might indicate a packed executable.
```

> This project relies heavily on pefile, which can be found on [GitHub](https://github.com/erocarrera/pefile)
> and on [PyPI](https://pypi.org/project/pefile/).
