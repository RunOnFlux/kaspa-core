/**
 * Install a global `BigInt.prototype.toJSON` that returns a string, as some
 * libraries do (e.g. @alephium/web3). JSON.stringify calls it before any
 * replacer. Returns a function that restores the previous state.
 */
export function installBigIntToJSON(): () => void {
  const proto = BigInt.prototype as unknown as Record<string, unknown>;
  const previous = Object.getOwnPropertyDescriptor(proto, 'toJSON');
  Object.defineProperty(proto, 'toJSON', {
    configurable: true,
    writable: true,
    value: function (this: bigint): string {
      return this.toString();
    },
  });
  return () => {
    if (previous) Object.defineProperty(proto, 'toJSON', previous);
    else delete proto.toJSON;
  };
}
