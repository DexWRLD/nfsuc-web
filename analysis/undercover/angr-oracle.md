# angr as an optional analysis oracle

`angr` is an **independent static-analysis oracle**. It is not the recompilation backend.

| Role | Owner |
| --- | --- |
| Function boundaries, ABI, lift, generate, compile | **UC analyzer / lifter** (authoritative) |
| Second opinion CFG / decompilation / comparison | **angr** (optional) |

Never treat angr pseudocode as generated game C for builds. Never silently overwrite UC confidence from angr output. Every important fact should keep `UC_ANALYZER` / `ANGR` / `CONSENSUS` provenance.

## Install (optional)

Recorded environment: **Python 3.12**, **angr 10.0.5**.

```sh
pip install "angr==10.0.5" "bitstring>=4.1,<4.3"
```

Normal project build, runtime, tests, and `tools/progress.py` work **without** angr. The dashboard reads cached metadata under `analysis/undercover/angr/` and does not invoke angr.

## Safety

- Loads the user-supplied `nfs.exe` read-only (via the same ordinary `.text` mapping as UC tools).
- Does not copy the executable into the repo.
- Does not start from the PE entry (protected startup).
- Does not symbolically execute protected startup.
- Central guard: `is_protected_address(addr)` in `tools/angr_oracle.py`. Edges into protected ranges terminate as `PROTECTED_BOUNDARY`.

## Mode

Initial mode is **static** only: per-function shellcode windows + CFGFast (`resolve_indirect_jumps=False`) + selective Decompiler.

Full-image CFGFast on this PE is impractically slow; Phase 21 uses bounded windows around known ordinary VAs. Symbolic execution is documented as a future bounded query only — not run.

## CLI

```sh
python tools/angr_oracle.py status
python tools/angr_oracle.py function 0x00752AF0
python tools/angr_oracle.py decompile 0x007B2AC0
python tools/angr_oracle.py compare 0x0072E340
python tools/angr_oracle.py xrefs 0x013C6510
python tools/angr_oracle.py controls
```

`xrefs` uses the UC immediate scanner (full-image); angr windows alone cannot see all cross-refs.

## Outputs

Under `analysis/undercover/angr/`:

- `summary.json` — version, controls, optional flag
- `functions.json` — compact priority-function metadata
- `comparison.json` — UC vs angr classes
- `graphics-phase21.json` — device/renderer/Draw consensus

No executable bytes. No game assets.
