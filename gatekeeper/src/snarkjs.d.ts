// Minimal type declarations for snarkjs (the package ships no types).
declare module "snarkjs" {
  export interface Groth16Proof {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  }
  export namespace groth16 {
    function fullProve(
      input: Record<string, unknown>,
      wasmFile: string,
      zkeyFileName: string,
      logger?: unknown,
    ): Promise<{ proof: Groth16Proof; publicSignals: string[] }>;
    function verify(
      vKey: unknown,
      publicSignals: string[],
      proof: Groth16Proof,
    ): Promise<boolean>;
  }
}
