/**
 * Legacy protocol interfaces for historical compatibility only.
 * 
 * @module legacy
 * 
 * @description
 * These exports implement deprecated protocol versions and are NOT part of the
 * active canonical protocol. They are provided solely for:
 * - Historical compatibility
 * - Migration support
 * - Testing against known vectors
 * 
 * Active implementations MUST use the storm_* surfaces which implement
 * AURA_HASH_V2 and the STORM_V1_1 quadratic recurrence.
 * 
 * @deprecated All exports in this module are deprecated. Use the storm_* surfaces instead.
 */

/**
 * Legacy SHA-256-based hash (AURA_HASH_V1) - DEPRECATED
 * 
 * This module implements the deprecated V1 identity function using SHA-256.
 * The active protocol uses AURA_HASH_V2 (H_521 with SHA3-512) via `stormHash521V1`.
 * 
 * @deprecated Use `stormHash521V1` (AURA_HASH_V2) instead.
 */
export * as auraHashV1 from "../auraHashV1.ts";

export * from "./solana.ts";
export * from "./udot.ts";
