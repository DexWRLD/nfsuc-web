import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'uc-flags-'));
let code;
try {
  const build = spawnSync('python', [path.join(repository, 'tools/uc_unified_flags_fixture.py'), path.join(temp, 'flags.wasm')], { encoding: 'utf8' });
  assert.equal(build.status, 0, build.stderr);
  code = await fs.readFile(path.join(temp, 'flags.wasm'));
} finally { await fs.rm(temp, { recursive: true, force: true }); }

async function fixture(onDispatch = () => assert.fail('Unexpected dispatch')) {
  const stack = new Map();
  let exports;
  const instance = await WebAssembly.instantiate(code, {
    env: { memory: new WebAssembly.Memory({ initial: 2 }) },
    guest: {
      read32: address => { assert.ok(stack.has(address)); return stack.get(address); },
      write32: (address, value) => stack.set(address, value >>> 0),
      write8: () => assert.fail('Unexpected byte store'), instruction: () => {},
      dispatch: address => onDispatch(address >>> 0, exports, stack),
    },
  });
  exports = instance.instance.exports;
  return exports;
}

function reference(a, b, carry, bits, sub) {
  const modulus = 1n << BigInt(bits), mask = modulus - 1n, sign = modulus >> 1n;
  a = BigInt(a) & mask; b = BigInt(b) & mask;
  const total = sub ? a - b - BigInt(carry) : a + b + BigInt(carry);
  const result = total & mask;
  const signed = value => value >= sign ? value - modulus : value;
  const signedTotal = sub ? signed(a) - signed(b) - BigInt(carry) : signed(a) + signed(b) + BigInt(carry);
  const cf = Number(total < 0 || total >= modulus);
  const of = Number(signedTotal < -sign || signedTotal >= sign);
  const af = Number(sub ? (a & 15n) < (b & 15n) + BigInt(carry) : (a & 15n) + (b & 15n) + BigInt(carry) > 15n);
  const zf = Number(result === 0n), sf = Number(result >= sign);
  const pf = Number([...Number(result & 255n).toString(2)].filter(value => value === '1').length % 2 === 0);
  return { result: Number(result), flags: cf | pf << 2 | af << 4 | zf << 6 | sf << 7 | of << 11,
    conditions: [of,!of,cf,!cf,zf,!zf,cf||zf,!cf&&!zf,sf,!sf,pf,!pf,sf!==of,sf===of,zf||sf!==of,!zf&&sf===of].map(Number) };
}

test('Wasm arithmetic matches independent width, borrow, overflow and condition references', async () => {
  const wasm = await fixture();
  for (const bits of [8, 16, 32]) {
    const sign = 2 ** (bits - 1), max = 2 ** bits - 1;
    const values = [0, 1, 15, 16, sign - 1, sign, max - 1, max, 0xdeadbeef];
    for (const a of values) for (const b of values) for (const op of [0, 1, 4]) for (const carry of op === 4 ? [0, 1] : [0]) {
      wasm.arithmetic(1, 0, carry, 32); // SUB establishes input CF; no host flag injection.
      const expected = reference(a, b, carry, bits, op !== 0);
      assert.equal(wasm.arithmetic(op, a, b, bits) >>> 0, expected.result);
      assert.equal(wasm.flags(), expected.flags, JSON.stringify({ op, a, b, carry, bits }));
      assert.equal(wasm.known(), 63);
      expected.conditions.forEach((value, condition) => assert.equal(wasm.condition(condition), value));
    }
    for (const a of values) {
      const neg = reference(0, a, 0, bits, true);
      assert.equal(wasm.arithmetic(2, a, 0, bits) >>> 0, neg.result);
      assert.equal(wasm.flags(), neg.flags);
      for (const carry of [0, 1]) {
        wasm.arithmetic(1, 0, carry, 32);
        const dec = reference(a, 1, 0, bits, true);
        assert.equal(wasm.arithmetic(3, a, 0, bits) >>> 0, dec.result);
        assert.equal(wasm.flags(), (dec.flags & ~1) | carry);
      }
    }
  }
});

test('unknown flags reject consumption and DEC preserves unknown carry', async () => {
  const wasm = await fixture();
  assert.throws(() => wasm.arithmetic(4, 0, 0, 32), WebAssembly.RuntimeError);
  wasm.arithmetic(3, 0, 0, 32);
  assert.equal(wasm.known() & 1, 0);
  assert.throws(() => wasm.condition(2), WebAssembly.RuntimeError);
  wasm.arithmetic(5, 1, 1, 8);
  assert.throws(() => wasm.condition(16), WebAssembly.RuntimeError); // Logical AF is undefined.
  assert.throws(() => wasm.arithmetic(0, 1, 1, 64), WebAssembly.RuntimeError);
});

test('volatile flags survive re-entrant dispatch and reflect nested arithmetic', async () => {
  let calls = 0;
  const wasm = await fixture((address, nested) => {
    assert.equal(address, 0xf17);
    assert.equal(nested.flags() & 1, 1);
    nested.arithmetic(1, 1, 1, 32); // Actual nested SUB clears CF.
    calls++;
  });
  assert.equal(wasm.nested(), 0);
  assert.equal(calls, 1);
  assert.equal(wasm.flags() & 1, 0);
});

test('lifted wrapper fixture forwards the original argument and computes its result with real flags', async () => {
  for (const returned of [0, 1, 0x80000000, 0xffffffff]) {
    const wasm = await fixture((address, state, stack) => {
      assert.equal(address, 0x0087b59b);
      const esp = state.register_value(0) >>> 0;
      assert.equal(esp, 0xfff8);
      assert.equal(stack.get(esp), 0x0087b649);
      assert.equal(stack.get(esp + 4), 0x00b602e0);
      assert.equal(stack.get(esp + 12), 0x00b602e0);
      state.fixture_return(returned); // Synthetic result; not a registered game service.
    });
    assert.equal(wasm.wrapper_fixture() >>> 0, returned === 0 ? 0xffffffff : 0);
    assert.equal(wasm.flags() & 1, returned === 0 ? 0 : 1); // DEC preserves final NEG carry.
    assert.equal(wasm.flags(), returned === 0 ? 0x94 : 0x45);
    assert.equal(wasm.register_value(0), 0x10004);
    assert.equal(wasm.register_value(1), 0x00dec0de);
    assert.equal(wasm.register_value(4), 0x00b602e0);
    for (const [index, value] of [[3,0x1234],[6,0xabcd],[7,0xef01],[8,0x5678]]) assert.equal(wasm.register_value(index), value);
  }
});
