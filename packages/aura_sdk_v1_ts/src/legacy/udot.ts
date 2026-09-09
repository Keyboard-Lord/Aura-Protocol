// Historical UDOT wrappers. Canonical callers use UdotBundleV2 at the SDK root.
export {
  generateUdotArtifactsV1,
  parseUdotArtifactV1,
  validateUdotArtifactV1,
  generateUdotArtifactBundleWireV1,
  parseUdotArtifactWireV1,
  parseUdotArtifactBundleWireV1,
  validateUdotArtifactWireV1,
  validateUdotArtifactBundleWireV1,
} from "../sdkCoreV1.ts";
export type {
  UdotVersion,
  UdotArtifactKind,
  GenerateUdotArtifactsRequestV1,
  ParseUdotArtifactRequestV1,
  ValidateUdotArtifactRequestV1,
  UdotArtifactEnvelopeV1,
  GeneratedUdotArtifactsV1,
  GenerateUdotArtifactBundleWireRequestV1,
  UdotArtifactWireV1,
  UdotArtifactBundleWireV1,
  ValidateUdotArtifactWireRequestV1,
} from "../sdkCoreV1.ts";
