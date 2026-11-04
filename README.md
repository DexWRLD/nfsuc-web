# nfsuc-web

Research fork aimed at **Need for Speed: Undercover** — take a retail `nfs.exe` you already own, lift ordinary x86 into C, and poke at what actually runs in a small native harness.

The private browser preview displays verified startup media and a Windows-compatible CRT diagnostic bootstrap. Full game boot and gameplay remain blocked. Independent of Electronic Arts.

Your install stays on your machine. Tools only read it. Game binaries and generated game C never go in git.

## Progress

![function maps](analysis/undercover/progress.png)

Top: translation/compile. Bottom: runtime. Green on the top map ≠ the game works.

```sh
python tools/progress.py
```

**Current phase: 76.** Roughly ~22.7k high-confidence functions generate and compile. In an opt-in Edge compatibility CRT path (not original PE entry), the host-scheduled security-cookie routine returns, then a bounded prefix of original CRT startup at `0x0087BB3D` runs through SEH / `FS:[0x18]` / `InterlockedCompareExchange`, sets startup state to 1, and stops at `_initterm_e`. Graphics remains blocked on a protected backend; Direct3D is not implemented. Original PE-entry reachability and loader binding are still unverified.

More detail: [analysis/undercover/runtime-phase76.md](analysis/undercover/runtime-phase76.md), [docs/roadmap.md](docs/roadmap.md), [docs/feasibility.md](docs/feasibility.md), [analysis/undercover/](analysis/undercover/).

## Quick start

Python 3, `requirements.txt` (`capstone`, `pefile`). Compile checks want `clang` (`CLANG` if it’s not on `PATH`). Optional analysis oracle: `pip install "angr==10.0.5"` — not needed for build/tests/dashboard.

```sh
python tools/uc_analyze.py "C:\Games\Need For Speed Undercover\nfs.exe"
python tools/uc_code_analyze.py "C:\Games\Need For Speed Undercover\nfs.exe"
python tools/uc_gen.py "C:\Games\Need For Speed Undercover\nfs.exe" --sample-only
```

Point those paths at your own copy.

## Layout

| | |
| --- | --- |
| `tools/uc_*.py`, `tools/lift.py` | Undercover analysis / lift / generate |
| `runtime/` | Guest CPU + the tiny helpers the harness knows |
| `analysis/undercover/` | Notes and counts (no game bytes) |
| `generated/undercover/` | Local C output (gitignored) |

## Don’t commit

- `nfs.exe`, EA assets, dumps
- anything that unpacks / decrypts / bypasses protection
- generated translated game C or Wasm

## Lineage

Grew out of [nfsu2-web](https://github.com/th0mk/nfsu2-web) (Thom), itself from the MIT drop of [NFSU2Recomp](https://github.com/TalhaMudo/NFSU2Recomp). Underground 2 bits and the shared lifter are still here — see [docs/upstream-nfsu2.md](docs/upstream-nfsu2.md). Architecture notes: [docs/architecture.md](docs/architecture.md).

## License

MIT — [LICENSE](LICENSE). Copyright (c) 2026 th0mk; portions (c) 2026 Talha Müderrisoğlu.

*Need for Speed* / *Undercover* are EA trademarks.
