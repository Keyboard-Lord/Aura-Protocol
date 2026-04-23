import {
  bytesToHexLowerV1,
  decodeCanonicalFixedHexBytesV1,
  FIELD_ELEMENT_521_BYTE_LEN_V1,
  validateFieldElement521BytesV1,
} from "./stormHash521V1.ts";

export type StormState521V1 = {
  xHex66Be: string;
  yHex66Be: string;
};

export function encodeStormRowBytesV1(state: StormState521V1): Uint8Array {
  const xBytes = validateFieldElement521BytesV1(
    decodeCanonicalFixedHexBytesV1(
      state.xHex66Be,
      FIELD_ELEMENT_521_BYTE_LEN_V1,
      "storm state xHex66Be",
    ),
    "storm state xHex66Be",
  );
  const yBytes = validateFieldElement521BytesV1(
    decodeCanonicalFixedHexBytesV1(
      state.yHex66Be,
      FIELD_ELEMENT_521_BYTE_LEN_V1,
      "storm state yHex66Be",
    ),
    "storm state yHex66Be",
  );

  const output = new Uint8Array(FIELD_ELEMENT_521_BYTE_LEN_V1 * 2);
  output.set(xBytes, 0);
  output.set(yBytes, FIELD_ELEMENT_521_BYTE_LEN_V1);
  return output;
}

export function decodeStormRowBytesV1(bytes: Uint8Array): StormState521V1 {
  if (bytes.length !== FIELD_ELEMENT_521_BYTE_LEN_V1 * 2) {
    throw new TypeError("storm row bytes must be 132 bytes");
  }

  const xBytes = validateFieldElement521BytesV1(
    bytes.subarray(0, FIELD_ELEMENT_521_BYTE_LEN_V1),
    "storm row x",
  );
  const yBytes = validateFieldElement521BytesV1(
    bytes.subarray(FIELD_ELEMENT_521_BYTE_LEN_V1),
    "storm row y",
  );

  return {
    xHex66Be: bytesToHexLowerV1(xBytes),
    yHex66Be: bytesToHexLowerV1(yBytes),
  };
}
