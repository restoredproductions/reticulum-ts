/**
 * Packet - Wire format for Reticulum protocol.
 *
 * Header format (2 bytes flags + destination hash):
 *   Byte 0 (flags):
 *     Bits 7-6: ifac_flag (1 bit) + header_type (1 bit)
 *     Bits 5-4: propagation_type (2 bits)
 *     Bits 3-2: destination_type (2 bits)
 *     Bits 1-0: packet_type (2 bits)
 *   Byte 1: hops (8 bits)
 *   Bytes 2+: destination hash (16 or 32 bytes depending on header type)
 *   Remaining: context (1 byte, for some types) + data payload
 *
 * MTU: 500 bytes
 * Wire-compatible with Python RNS Packet.pack() / Packet.unpack()
 */

import { Logger, LogLevel } from './log/Logger';
import {
  fullHash,
  truncatedHash,
  TRUNCATED_HASHLENGTH,
  TOKEN_OVERHEAD,
  X25519_KEY_LENGTH,
} from './crypto';
import { concatBytes, shortHex } from './utils/bytes';

const TAG = 'Packet';

// ── Protocol Constants (matching Python RNS) ──────────────────────

export const MTU = 500;
export const HEADER_MINSIZE = 2; // flags + hops (before dest hash)
export const HEADER_MAXSIZE = 23; // flags(1) + hops(1) + context(1) + dest(16) + transport_id(4) -- simplified

// Header types
export const HEADER_1 = 0x00; // Normal: 2 flag bytes + 16-byte dest hash
export const HEADER_2 = 0x01; // Transport: 2 flag bytes + 16-byte transport_id + 16-byte dest hash

// Propagation types
export const PROPAGATION_BROADCAST = 0x00;
export const PROPAGATION_TRANSPORT = 0x01;
export const PROPAGATION_RESERVED1 = 0x02;
export const PROPAGATION_RESERVED2 = 0x03;

// Destination types
export const DESTINATION_SINGLE = 0x00;
export const DESTINATION_GROUP = 0x01;
export const DESTINATION_PLAIN = 0x02;
export const DESTINATION_LINK = 0x03;

// Packet types
export const PACKET_DATA = 0x00;
export const PACKET_ANNOUNCE = 0x01;
export const PACKET_LINKREQUEST = 0x02;
export const PACKET_PROOF = 0x03;

// Context types
export const CONTEXT_NONE = 0x00;
export const CONTEXT_RESOURCE = 0x01;
export const CONTEXT_RESOURCE_ADV = 0x02;
export const CONTEXT_RESOURCE_REQ = 0x03;
export const CONTEXT_RESOURCE_HMU = 0x04;
export const CONTEXT_RESOURCE_PRF = 0x05;
export const CONTEXT_RESOURCE_ICL = 0x06;
export const CONTEXT_RESOURCE_RCL = 0x07;
export const CONTEXT_CACHE_REQUEST = 0x08;
export const CONTEXT_REQUEST = 0x09;
export const CONTEXT_RESPONSE = 0x0a;
export const CONTEXT_PATH_RESPONSE = 0x0b;
export const CONTEXT_COMMAND = 0x0c;
export const CONTEXT_COMMAND_STATUS = 0x0d;
export const CONTEXT_CHANNEL = 0x0e;
export const CONTEXT_KEEPALIVE = 0xfa;
export const CONTEXT_LINKIDENTIFY = 0xfb;
export const CONTEXT_LINKCLOSE = 0xfc;
export const CONTEXT_LINKPROOF = 0xfd;
export const CONTEXT_LRRTT = 0xfe;
export const CONTEXT_LRPROOF = 0xff;

// IFAC
export const IFAC_MIN_SIZE = 1;

// MDU calculations
export const HEADER1_SIZE = 2 + TRUNCATED_HASHLENGTH; // 2 + 16 = 18 bytes
export const HEADER2_SIZE = 2 + TRUNCATED_HASHLENGTH * 2; // 2 + 32 = 34 bytes
export const MDU = MTU - HEADER2_SIZE - IFAC_MIN_SIZE; // 500 - 34 - 1 = 465
export const PLAIN_MDU = MDU;
export const ENCRYPTED_MDU = PLAIN_MDU - TOKEN_OVERHEAD; // 465 - 48 = 417

// For announces
export const ANNOUNCE_IDENTITY_SIZE = X25519_KEY_LENGTH + X25519_KEY_LENGTH; // 64 bytes (enc + sig pubkeys)

/** Receipt callback types */
export type PacketReceiptCallback = (receipt: PacketReceipt) => void;

/** Delivery status for packet receipts */
export enum DeliveryStatus {
  UNKNOWN = 0,
  SENT = 1,
  DELIVERED = 2,
  FAILED = 3,
}

export interface PacketHeader {
  ifacFlag: number;
  headerType: number;
  propagationType: number;
  destinationType: number;
  packetType: number;
  hops: number;
  transportId: Uint8Array | null; // 16 bytes, only for HEADER_2
  destinationHash: Uint8Array;    // 16 bytes
  context: number;
}

/**
 * Pack the flags byte from header fields.
 * Matches Python: self.flags = ... in Packet.pack()
 */
export function packFlags(header: PacketHeader): number {
  let flags = 0;
  flags |= (header.ifacFlag & 0x01) << 7;
  flags |= (header.headerType & 0x01) << 6;
  flags |= (header.propagationType & 0x03) << 4;
  flags |= (header.destinationType & 0x03) << 2;
  flags |= header.packetType & 0x03;
  return flags;
}

/**
 * Unpack a flags byte into header fields.
 */
export function unpackFlags(flags: number): Partial<PacketHeader> {
  return {
    ifacFlag: (flags >> 7) & 0x01,
    headerType: (flags >> 6) & 0x01,
    propagationType: (flags >> 4) & 0x03,
    destinationType: (flags >> 2) & 0x03,
    packetType: flags & 0x03,
  };
}

/**
 * Raw packet representation. Holds all fields needed to produce
 * a wire-format packet or recreate one from received bytes.
 */
export class Packet {
  // Header fields
  headerType: number = HEADER_1;
  propagationType: number = PROPAGATION_BROADCAST;
  destinationType: number = DESTINATION_SINGLE;
  packetType: number = PACKET_DATA;
  context: number = CONTEXT_NONE;
  hops: number = 0;
  transportId: Uint8Array | null = null;
  destinationHash: Uint8Array = new Uint8Array(TRUNCATED_HASHLENGTH);

  // Payload
  data: Uint8Array = new Uint8Array(0);

  // IFAC (Interface Access Code)
  ifacFlag: number = 0;

  // Metadata (not transmitted)
  raw: Uint8Array | null = null;
  sent: boolean = false;
  fromPacked: boolean = false;
  createReceipt: boolean = true;
  receipt: PacketReceipt | null = null;

  // Signal metrics from receiving interface
  rssi: number | null = null;
  snr: number | null = null;
  q: number | null = null;

  // Receiving interface reference
  receivingInterface: any = null;

  /**
   * Pack this packet into wire format.
   * Returns the raw bytes ready for transmission.
   */
  pack(): Uint8Array {
    const flags = packFlags({
      ifacFlag: this.ifacFlag,
      headerType: this.headerType,
      propagationType: this.propagationType,
      destinationType: this.destinationType,
      packetType: this.packetType,
      hops: this.hops,
      transportId: this.transportId,
      destinationHash: this.destinationHash,
      context: this.context,
    });

    const parts: Uint8Array[] = [
      new Uint8Array([flags, this.hops & 0xff]),
    ];

    if (this.headerType === HEADER_2 && this.transportId) {
      parts.push(this.transportId.slice(0, TRUNCATED_HASHLENGTH));
    }

    parts.push(this.destinationHash.slice(0, TRUNCATED_HASHLENGTH));
    parts.push(new Uint8Array([this.context & 0xff]));
    parts.push(this.data);

    this.raw = concatBytes(...parts);

    if (this.raw.length > MTU) {
      Logger.warn(
        `Packet exceeds MTU: ${this.raw.length} > ${MTU}`,
        TAG
      );
    }

    Logger.log(
      `Packed ${this.raw.length}B: type=${this.packetType} ctx=${this.context} dest=${shortHex(this.destinationHash)} hops=${this.hops}`,
      LogLevel.EXTREME,
      TAG
    );
    return this.raw;
  }

  /**
   * Unpack raw bytes into a Packet.
   * Wire format: flags(1) + hops(1) + [transportId(16)] + destHash(16) + context(1) + data(...)
   */
  static unpack(raw: Uint8Array): Packet {
    if (raw.length < 2 + TRUNCATED_HASHLENGTH + 1) {
      throw new Error(`Packet too short: ${raw.length} bytes`);
    }

    const pkt = new Packet();
    pkt.raw = new Uint8Array(raw);
    pkt.fromPacked = true;

    // Byte 0: flags
    const flags = raw[0];
    const parsed = unpackFlags(flags);
    pkt.ifacFlag = parsed.ifacFlag!;
    pkt.headerType = parsed.headerType!;
    pkt.propagationType = parsed.propagationType!;
    pkt.destinationType = parsed.destinationType!;
    pkt.packetType = parsed.packetType!;

    // Byte 1: hops
    pkt.hops = raw[1];

    let offset = 2;

    // Transport ID (only in HEADER_2)
    if (pkt.headerType === HEADER_2) {
      if (raw.length < offset + TRUNCATED_HASHLENGTH) {
        throw new Error('Packet too short for HEADER_2 transport ID');
      }
      pkt.transportId = raw.slice(offset, offset + TRUNCATED_HASHLENGTH);
      offset += TRUNCATED_HASHLENGTH;
    }

    // Destination hash (always 16 bytes)
    if (raw.length < offset + TRUNCATED_HASHLENGTH) {
      throw new Error('Packet too short for destination hash');
    }
    pkt.destinationHash = raw.slice(offset, offset + TRUNCATED_HASHLENGTH);
    offset += TRUNCATED_HASHLENGTH;

    // Context byte
    if (raw.length < offset + 1) {
      throw new Error('Packet too short for context byte');
    }
    pkt.context = raw[offset];
    offset += 1;

    // Remaining bytes are data payload
    pkt.data = raw.slice(offset);

    Logger.log(
      `Unpacked ${raw.length}B: type=${pkt.packetType} ctx=${pkt.context} dest=${shortHex(pkt.destinationHash)} hops=${pkt.hops} data=${pkt.data.length}B`,
      LogLevel.EXTREME,
      TAG
    );
    return pkt;
  }

  /** Get the packet hash (SHA-256 of raw bytes, truncated to 16 bytes) */
  getHash(): Uint8Array {
    if (!this.raw) this.pack();
    return truncatedHash(this.raw!);
  }

  /** Get the full packet hash (SHA-256, 32 bytes) */
  getFullHash(): Uint8Array {
    if (!this.raw) this.pack();
    return fullHash(this.raw!);
  }

  /** Human-readable packet description for logging */
  toString(): string {
    const types = ['DATA', 'ANNOUNCE', 'LINKREQUEST', 'PROOF'];
    const propTypes = ['BROADCAST', 'TRANSPORT', 'RSVD1', 'RSVD2'];
    const destTypes = ['SINGLE', 'GROUP', 'PLAIN', 'LINK'];

    return `Packet<${types[this.packetType] ?? '?'} ${propTypes[this.propagationType] ?? '?'} ${destTypes[this.destinationType] ?? '?'} dest=${shortHex(this.destinationHash)} hops=${this.hops} data=${this.data.length}B>`;
  }
}

/**
 * PacketReceipt tracks delivery status of sent packets.
 */
export class PacketReceipt {
  hash: Uint8Array;
  status: DeliveryStatus = DeliveryStatus.SENT;
  sentAt: number = Date.now();
  provedAt: number | null = null;
  callbacks: {
    delivered?: PacketReceiptCallback;
    timeout?: PacketReceiptCallback;
  } = {};

  private _timeout: number = 0;
  private _timeoutTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(packet: Packet) {
    this.hash = packet.getHash();
  }

  /** Set delivery callback */
  onDelivered(callback: PacketReceiptCallback): void {
    this.callbacks.delivered = callback;
    if (this.status === DeliveryStatus.DELIVERED) {
      callback(this);
    }
  }

  /** Set timeout callback */
  onTimeout(callback: PacketReceiptCallback, timeout: number): void {
    this.callbacks.timeout = callback;
    this._timeout = timeout;
    this._timeoutTimer = setTimeout(() => {
      if (this.status === DeliveryStatus.SENT) {
        this.status = DeliveryStatus.FAILED;
        Logger.log(
          `PacketReceipt timeout: ${shortHex(this.hash)}`,
          LogLevel.DEBUG,
          TAG
        );
        callback(this);
      }
    }, timeout);
  }

  /** Mark as delivered (called when proof is received) */
  prove(): void {
    this.status = DeliveryStatus.DELIVERED;
    this.provedAt = Date.now();
    if (this._timeoutTimer) {
      clearTimeout(this._timeoutTimer);
      this._timeoutTimer = null;
    }
    if (this.callbacks.delivered) {
      this.callbacks.delivered(this);
    }
    Logger.log(
      `PacketReceipt proved: ${shortHex(this.hash)} (${this.provedAt - this.sentAt}ms)`,
      LogLevel.DEBUG,
      TAG
    );
  }

  /** Cancel receipt tracking */
  cancel(): void {
    if (this._timeoutTimer) {
      clearTimeout(this._timeoutTimer);
      this._timeoutTimer = null;
    }
  }
}
