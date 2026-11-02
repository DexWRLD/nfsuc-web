"""Phase 12 provenance checks.

Reads ordinary .text only. Does not execute a function, does not write
0x0189DA84 or 0x0189D0A0, and does not start the game.
"""
import sys

import uc_code_analyze as uca
import uc_initprov as prov

GAME = r"C:\Games\Need For Speed Undercover\nfs.exe"


def main():
    game = sys.argv[1] if len(sys.argv) > 1 else GAME
    info = uca.read_inputs(game)
    blob, base = info["bytes"], info["text_va"]

    def at(va, n):
        off = va - base
        return blob[off:off + n]

    # 0x009E9391 call 0x009E9160; 0x009E9396 mov [0x0189DA84], eax
    window = prov.decode_window(blob, base, 0x009E9391, 16)
    if prov.previous_call_target(window, 1) != 0x009E9160:
        sys.exit("EAX store is not preceded by call 0x009E9160")
    if at(0x009E9396, 5) != bytes.fromhex("a384da8901"):
        sys.exit("store at 0x009E9396 is not mov [0x0189DA84], eax")

    # 0x009E9160 returns the incoming object, then the caller publishes it.
    if at(0x009E9313, 5) != bytes.fromhex("8bc65e5bc2"):
        sys.exit("0x009E9160 does not end with mov eax, esi; pop; pop; ret")

    # The leaf runs inside 0x009E9160, before that return.
    if prov.relative_callers(blob, base, 0x009E8AD0) != [0x009E9305]:
        sys.exit("callback leaf caller changed")

    # Fault-field writer: call 0x009DC250, then mov [ecx+8], eax.
    body = prov.decode_window(blob, base, 0x009E4699, 24)
    if not body or body[0].mnemonic != "call" or prov.previous_call_target(body, 1) != 0x009DC250:
        sys.exit("0x009E4699 is not call 0x009DC250")
    if not any(i.mnemonic == "mov" and "+ 8]" in i.op_str and "eax" in i.op_str for i in body):
        sys.exit("no store of EAX to offset 8 after 0x009DC250")

    # That allocator forwards the size through the slot the Phase 11 leaf fills.
    alloc = prov.decode_window(blob, base, 0x009DBE50, 24)
    texts = ["%s %s" % (i.mnemonic, i.op_str) for i in alloc]
    if not any("0x189d198" in t for t in texts):
        sys.exit("0x009DBE50 does not call through 0x0189D198")

    # The only publisher of 0x0189DA88 calls 0x00686000, which is not a function entry.
    if prov.relative_callers(blob, base, 0x009E9410) != [0x00810291]:
        sys.exit("factory-pointer writer changed")
    stub = list(prov.decode_window(blob, base, 0x00686000, 16))
    if not stub or stub[0].mnemonic == "ret" or (stub[0].mnemonic == "call" and stub[0].op_str.startswith("0x4")):
        sys.exit("unexpected ordinary entry at 0x00686000")
    generated = {0x009E78C0}
    if prov.dispatch_entry_ok(0x00686000, generated, info["text_va"], info["text_va"] + len(blob)):
        sys.exit("non-generated stub accepted")
    if prov.dispatch_entry_ok(0x00695490, generated, info["text_va"], info["text_va"] + len(blob)):
        sys.exit("0x00695490 accepted")
    print("uc phase12 provenance checks passed")


if __name__ == "__main__":
    main()
