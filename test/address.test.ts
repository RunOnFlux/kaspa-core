import { describe, expect, it } from 'vitest';
import { hexToBytes } from '../src/bytes.js';
import {
  addressToScriptPublicKey,
  decodeAddress,
  encodeAddress,
  isValidAddress,
  scriptPublicKeyToAddress,
} from '../src/address.js';
import { InvalidAddressError } from '../src/errors.js';
import { xOnlyPublicKey } from '../src/sign.js';
import { multisigSpend, spendScriptPublicKey } from '../src/spend.js';

/** Vectors from zelcore/packages/addresses/__tests__/families/kaspa.test.ts. */
const ZELCORE = [
  [
    'dc1ec19756d3b63aeb752ead612087858d1bdc1cf24287dd4f2ab32f6cfe1905',
    'kaspa:qpk4r2vujaj6xcsx6jgn7x92y443htckc0hhk049ks7fgkwmfjwlk6dx2nq63',
  ],
  [
    '363c269151c5be140dcdf65ddfb18cc0d967bf2b68972905b5c4888a9b112f27',
    'kaspa:qrswppwx52j2q2rv7hh4329kjraut7sm9y8vvd9tankhvzem9gftw34q72mmx',
  ],
  [
    'a5d7d8a1bb1fa7b849734ea151c1b19511864e7fcdac3ef59911cc83145ccda3',
    'kaspa:qptemr5394q26s9rmedfyqggl3txah9uc7vxy0tfghsuzsqw8494jg9n4490f',
  ],
  [
    '44746141f33d2705dda34bf4cdb441aeed1f7022d3dfc4adcd6354ecf66ba0a9',
    'kaspa:qqwqr2cu3n8qaugtgs0nsky574kqan4j0rdf4adqtx5kvz33f523762k63pue',
  ],
] as const;

describe('address codec', () => {
  it.each(ZELCORE)('derives %s', (pk, address) => {
    expect(encodeAddress('kaspa', 0, xOnlyPublicKey(hexToBytes(pk)))).toBe(
      address,
    );
  });

  it('round-trips P2PK and P2SH through their locking scripts', () => {
    const [pk, address] = ZELCORE[0];
    const spk = addressToScriptPublicKey(address);
    expect(scriptPublicKeyToAddress(spk, 'kaspa')).toBe(address);
    const vault = multisigSpend(
      [
        xOnlyPublicKey(hexToBytes(pk)),
        xOnlyPublicKey(hexToBytes(ZELCORE[1][0])),
      ],
      2,
    );
    const p2sh = scriptPublicKeyToAddress(
      spendScriptPublicKey(vault),
      'kaspa',
    )!;
    expect(p2sh.startsWith('kaspa:p')).toBe(true);
    expect(p2sh.length).toBe('kaspa:'.length + 61);
    expect(addressToScriptPublicKey(p2sh)).toEqual(spendScriptPublicKey(vault));
  });

  it('rejects malformed addresses', () => {
    const good = ZELCORE[0][1];
    const flip = good.slice(0, -1) + (good.endsWith('3') ? '4' : '3');
    for (const bad of [
      flip,
      good.toUpperCase(),
      good.replace('kaspa:', 'kaspatest:'),
      good.slice(0, 20),
      good.replace('q', 'b'),
      'kaspa',
      'nope:qqqq',
    ]) {
      expect(() => decodeAddress(bad), bad).toThrow(InvalidAddressError);
      expect(isValidAddress(bad)).toBe(false);
    }
    expect(isValidAddress(good, 'kaspatest')).toBe(false);
    expect(() => encodeAddress('kaspa', 0, new Uint8Array(33))).toThrow(
      InvalidAddressError,
    );
  });
});
