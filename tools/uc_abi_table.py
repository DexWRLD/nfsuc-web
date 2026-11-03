#!/usr/bin/env python3
"""Write runtime/uc_import_table.inc from analysis/undercover/import-abi.json.

Does not read the game executable. Argument counts are recorded only for the
CRT functions the harness implements, plus the one thiscall whose mangled
name states that it takes no stack arguments.
"""
import json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ABI = {
    "cdecl": "UC_ABI_CDECL",
    "stdcall": "UC_ABI_STDCALL",
    "thiscall": "UC_ABI_THISCALL",
    "fastcall": "UC_ABI_FASTCALL",
    "unknown": "UC_ABI_UNKNOWN",
}
# Stack dwords and HLE id. Anything absent stays unknown layout / no HLE.
KNOWN = {
    "memcpy": (3, "UC_HLE_MEMCPY"),
    "memmove": (3, "UC_HLE_MEMMOVE"),
    "memset": (3, "UC_HLE_MEMSET"),
    "memcmp": (3, "UC_HLE_MEMCMP"),
    "strlen": (1, "UC_HLE_STRLEN"),
    "strcmp": (2, "UC_HLE_STRCMP"),
    "strncmp": (3, "UC_HLE_STRNCMP"),
    "strncpy": (3, "UC_HLE_STRNCPY"),
}
# Public Win32 stdcall helpers with proven zero stack args.
STDCALL_KNOWN = {
    "TlsAlloc": (0, "UC_HLE_TLSALLOC"),
    "TlsSetValue": (2, "UC_HLE_TLSSETVALUE"),
}
# public: void type_info::_type_info_dtor_internal_method(void)
THISCALL_NO_STACK = "?_type_info_dtor_internal_method@type_info@@QAEXXZ"
X87 = {
    "_CIsin": "UC_HLE_CISIN",
    "_CIcos": "UC_HLE_CICOS",
    "_CIacos": "UC_HLE_CIACOS",
    "_CIsqrt": "UC_HLE_CISQRT",
}


def c_string(text):
    out = ['"']
    for ch in text:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif 32 <= ord(ch) < 127:
            out.append(ch)
        else:
            out.append("\\x%02x" % ord(ch))
    out.append('"')
    return "".join(out)


def main():
    doc = json.load(open(os.path.join(ROOT, "analysis", "undercover", "import-abi.json"), encoding="utf-8"))
    rows = sorted(doc["imports"], key=lambda row: int(row["thunk"], 16))
    lines = [
        "/* Generated from analysis/undercover/import-abi.json. Not game bytes. */",
        "static const UcImport uc_import_table[] = {",
    ]
    for row in rows:
        symbol = row["symbol"] or ""
        ordinal = -1 if row["ordinal"] is None else int(row["ordinal"])
        abi = ABI[row["calling_convention"]]
        dwords, hle = -1, "UC_HLE_NONE"
        arg_loc, ret_loc = "UC_LOC_STACK", "UC_LOC_EAX"
        if symbol in KNOWN and row["calling_convention"] == "cdecl":
            dwords, hle = KNOWN[symbol]
        elif symbol in STDCALL_KNOWN and row["calling_convention"] == "stdcall":
            dwords, hle = STDCALL_KNOWN[symbol]
            arg_loc = "UC_LOC_NONE" if dwords == 0 else "UC_LOC_STACK"
        elif symbol in X87 and row["calling_convention"] == "cdecl":
            dwords, hle = 0, X87[symbol]
            arg_loc, ret_loc = "UC_LOC_ST0", "UC_LOC_ST0"
        elif symbol == THISCALL_NO_STACK and row["calling_convention"] == "thiscall":
            dwords = 0
        lines.append(
            "    { %s, %s, %s, %s, %d, %s, %d, %s, %s, %s },"
            % (
                row["thunk"],
                row["iat_slot"],
                c_string(row["dll"]),
                c_string(symbol),
                ordinal,
                abi,
                dwords,
                hle,
                arg_loc,
                ret_loc,
            )
        )
    lines.append("};")
    lines.append("")
    path = os.path.join(ROOT, "runtime", "uc_import_table.inc")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    print(f"wrote {len(rows)} imports to {path}")


if __name__ == "__main__":
    main()
