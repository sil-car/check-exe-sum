### EXE-Check

Quickly determine if EXE or other similar file has been "packed" with extra data;
i.e. it has been corrupted by a virus.

## Usage

```
$ exe-check eis_nt64.good.exe
Good	/media/nate/Storage/virus-research/eis_nt64.good.exe
$ exe-check eis_nt64.bad.exe
Bad     /media/nate/Storage/virus-research/eis_nt64.bad.exe
  > Suspicious flags set for section 6. Both IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE are set. This might indicate a packed executable.
  > Reported size is less than actual size.
$ exe-check zero-size.exe
Bad	/media/nate/Storage/virus-research/zero-size.exe
  > File has zero length.
$ exe-check Firefox\ Setup\ 119.0.exe
Unknown	/media/nate/Storage/virus-research/Firefox Setup 119.0.exe
  > UPX-type exe; packing status unknown
```

## Installation

```
$ git clone --depth 1 https://github.com/sil-car/exe-check.git
$ python3 -m pip install ./exe-check
Processing ./exe-check
  Installing build dependencies ... done
  Getting requirements to build wheel ... done
  Installing backend dependencies ... done
    Preparing wheel metadata ... done
Collecting pefile
  Using cached pefile-2023.2.7-py3-none-any.whl (71 kB)
Building wheels for collected packages: exe-check
  Building wheel for exe-check (PEP 517) ... done
  Created wheel for exe-check: filename=exe_check-0.1-py3-none-any.whl size=3534 sha256=24b1f7c38f3e510d62bcdddd6b921c09a45f6a94905f3af62ae8ffb8f35e2f64
  Stored in directory: ~/.cache/pip/wheels/ac/72/9a/35cbdf79a53b9a27e88fe5dad0b5a3ea39450843e4f08c486c
Successfully built exe-check
Installing collected packages: pefile, exe-check
Successfully installed exe-check-0.1 pefile-2023.2.7
$ which exe-check
~/.local/bin/exe-check
```

> More info: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
> This project relies heavily on pefile, which can be found on [GitHub](https://github.com/erocarrera/pefile)
> and on [PyPI](https://pypi.org/project/pefile/).
