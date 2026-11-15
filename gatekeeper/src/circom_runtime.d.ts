// Minimal type declarations for circom_runtime (the package ships no types).
declare module "circom_runtime" {
  export interface WitnessCalculator {
    instance: {
      exports: {
        getInputSize(): number;
        getWitnessSize(): number;
        getVersion(): number;
      };
    };
    circom_version(): number;
    calculateWitness(
      input: Record<string, unknown>,
      sanityCheck?: boolean,
    ): Promise<bigint[]>;
  }
  export function WitnessCalculatorBuilder(
    wasm: Uint8Array,
    options?: { sanityCheck?: boolean },
  ): Promise<WitnessCalculator>;
}
