# slpatch

Unofficial patcher for Superluminal Performance. Not affiliated with the original creator.

## Use

```powershell
.\slpatch.exe --status     # original / patched / unrecognised
.\slpatch.exe --dry-run    # full analysis, target not modified
.\slpatch.exe              # apply
.\slpatch.exe --restore    # restore the original binary
```

Defaults to `%ProgramFiles%\Superluminal\Performance\Profiler.exe`; `--path <file>` works for overrides.
Exit codes: `0` ok, `1` bad args, `2` IO/not elevated, `3` unrecognised image.

## Caveats

- `Profiler.exe` only. `SuperluminalCmd.exe` and the collection service are untouched.
- Auto-update overwrites the patch. Re-run afterwards or block in the hosts file.
- Keep the free-trial `activation.dat`, without it parts of the license UI break.
- First patch writes `Profiler.exe.orig` (even on `--dry-run`);

Signature-based, not offset-based, so minor layout shifts survive and unknown builds abort at `3`.

## Version

| Build | Status | Stock SHA-256 |
|---|---|---|
| `1.0.7708.1297` | supported | `bf3183ab330c2185b01940f3841b39c2eefd279cff2872d3e03d37853797b781` |

Other hashes warn and fall back to signature matching, untested.

## Build

Zig 0.16.0:

```
zig build-exe -O ReleaseSmall -target x86_64-windows-gnu --name slpatch slpatch.zig
```

made for research purposes; if you enjoy Superliminal buy a license to support them :)