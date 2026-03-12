/**
 * reticulum-ts - TypeScript port of the Reticulum cryptographic networking stack.
 *
 * Wire-compatible with Python Reticulum (https://github.com/markqvist/Reticulum).
 * Designed for React Native / Expo Go mobile apps.
 *
 * Usage:
 *   import { Reticulum, Identity, Destination, Link, LogLevel } from 'reticulum-ts';
 *
 *   // Initialize
 *   const rns = new Reticulum({ logLevel: LogLevel.DEBUG });
 *   await rns.start();
 *
 *   // Create an identity and destination
 *   const identity = new Identity();
 *   const dest = new Destination(identity, Destination.IN, Destination.SINGLE, 'myapp', 'service');
 *   rns.registerDestination(dest);
 *
 *   // Announce to the network
 *   const pkt = dest.announce();
 *   rns.transport.outbound(pkt);
 *
 *   // Listen for packets
 *   dest.onPacket((data, packet) => {
 *     console.log('Received:', data);
 *   });
 *
 * @packageDocumentation
 */

// ── Core ────────────────────────────────────────────────────────

export { Reticulum, ReticulumConfig, VERSION, PROTOCOL_VERSION } from './RNS';
export { Transport } from './Transport';
export { Identity, ANNOUNCE_SIGNATURE_SIZE } from './Identity';
export {
  Destination,
  DEST_SINGLE,
  DEST_GROUP,
  DEST_PLAIN,
  DEST_LINK,
  IN,
  OUT,
  PROVE_NONE,
  PROVE_APP,
  PROVE_ALL,
  ALLOW_NONE,
  ALLOW_ALL,
  ALLOW_LIST,
} from './Destination';

// ── Packet ──────────────────────────────────────────────────────

export {
  Packet,
  PacketReceipt,
  DeliveryStatus,
  MTU,
  MDU,
  PLAIN_MDU,
  ENCRYPTED_MDU,
  // Packet types
  PACKET_DATA,
  PACKET_ANNOUNCE,
  PACKET_LINKREQUEST,
  PACKET_PROOF,
  // Header types
  HEADER_1,
  HEADER_2,
  // Propagation types
  PROPAGATION_BROADCAST,
  PROPAGATION_TRANSPORT,
  // Destination types (packet-level)
  DESTINATION_SINGLE,
  DESTINATION_GROUP,
  DESTINATION_PLAIN,
  DESTINATION_LINK,
  // Context types
  CONTEXT_NONE,
  CONTEXT_RESOURCE,
  CONTEXT_RESOURCE_ADV,
  CONTEXT_RESOURCE_REQ,
  CONTEXT_CACHE_REQUEST,
  CONTEXT_REQUEST,
  CONTEXT_RESPONSE,
  CONTEXT_PATH_RESPONSE,
  CONTEXT_COMMAND,
  CONTEXT_COMMAND_STATUS,
  CONTEXT_CHANNEL,
  CONTEXT_KEEPALIVE,
  CONTEXT_LINKIDENTIFY,
  CONTEXT_LINKCLOSE,
  CONTEXT_LINKPROOF,
} from './Packet';

// ── Link & Communication ────────────────────────────────────────

export {
  Link,
  LinkStatus,
  TeardownReason,
  LinkMode,
} from './Link';

export {
  Channel,
  MessageBase,
  DataMessage,
  StreamDataMessage,
  SMT_STREAM_DATA,
} from './Channel';

export {
  BufferReader,
  BufferWriter,
  createBuffer,
} from './Buffer';

export {
  Resource,
  ResourceStatus,
} from './Resource';

// ── Interfaces ──────────────────────────────────────────────────

export {
  InterfaceBase,
  InterfaceConfig,
  MODE_FULL,
  MODE_POINT_TO_POINT,
  MODE_ACCESS_POINT,
  MODE_ROAMING,
  MODE_BOUNDARY,
  MODE_GATEWAY,
} from './interfaces/Interface';

export { TCPInterface, TCPInterfaceConfig } from './interfaces/TCPInterface';
export { WebSocketInterface, WebSocketInterfaceConfig } from './interfaces/WebSocketInterface';
export { LocalInterface, LocalInterfaceConfig } from './interfaces/LocalInterface';

// ── Crypto (for advanced use) ───────────────────────────────────

export {
  randomBytes,
  sha256,
  sha512,
  fullHash,
  truncatedHash,
  hmacSha256,
  deriveKey,
  Token,
  TOKEN_OVERHEAD,
  X25519PrivateKey,
  X25519PublicKey,
  Ed25519PrivateKey,
  Ed25519PublicKey,
  KEYSIZE,
  IDENTITY_KEY_LENGTH,
  HASHLENGTH,
  TRUNCATED_HASHLENGTH,
} from './crypto';

// ── Logging ─────────────────────────────────────────────────────

export { Logger, LogLevel, LogCallback } from './log/Logger';

// ── Utilities ───────────────────────────────────────────────────

export {
  toHex,
  fromHex,
  concatBytes,
  constantTimeEqual,
  shortHex,
} from './utils/bytes';

export { getPlatform, Platform, isMobile, isNode } from './utils/platform';

export {
  ReticulumStorage,
  StorageProvider,
  createStorageProvider,
} from './utils/storage';

export {
  ReticulumJsonConfig,
  InterfaceDefinition,
  DEFAULT_CONFIG,
  mergeConfig,
  generateSampleConfig,
} from './utils/config';
