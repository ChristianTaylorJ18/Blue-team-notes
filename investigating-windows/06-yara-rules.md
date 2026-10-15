# 06 — Writing a YARA Rule

LOKI didn't flag **`mim.exe`**, so the fix is a custom YARA rule to detect what the signatures missed.

## Finding strings to match on
Pull printable strings from the binary and filter for distinctive ones:
```cmd
strings mim.exe | findstr /i ".exe"
strings mim.exe | findstr /i "ps powershell"
```
(`strings` is a Sysinternals tool; `findstr` filters.) Pick strings that are unique to the sample — filenames it drops and a version marker work well. Here the three chosen strings were:
- `mk.ps1`
- `mk.exe`
- `v2.0.50727`  (a .NET runtime version string — a good unique marker)

## Rule shape
```yara
rule Detect_mim {
    strings:
        $a = "mk.ps1"
        $b = "mk.exe"
        $c = "v2.0.50727"
    condition:
        all of them
}
```
(The room's rule file in the Desktop `Tools` folder just needed those three strings filled in.)

Lesson: when a scanner misses a sample, `strings` + `findstr` to find unique markers → write a YARA rule → detect it (and siblings) going forward. Prefer a combination of distinctive strings (`all of them`) over one generic string to keep false positives down.
