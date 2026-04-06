export async function onRpcRequest({ origin, request }: { origin: string; request: { method: string; params?: unknown } }) {
  switch (request.method) {
    case "zeno_getCompatibility":
      return {
        origin,
        network: "Zeno PQ Devnet",
        chainId: "zeno-devnet",
        evmChainId: 424242,
        signing: "ML-DSA",
        mode: "snap-relayed-account-abstraction",
      };
    case "zeno_signMlDsa":
      throw new Error("Snap scaffold only: implement ML-DSA key management and signing flow.");
    default:
      throw new Error(`Unsupported method: ${request.method}`);
  }
}
