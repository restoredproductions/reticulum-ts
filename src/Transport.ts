/**
 * Transport - Core routing and relay engine for Reticulum.
 *
 * Handles all packet routing, announce propagation, path management,
 * and deduplication. This is the "brain" of the mesh network.
 *
 * Converted from Python's static Transport class (3,312 lines) to
 * an async singleton with setInterval-based job loops.
 *
 * Wire-compatible with Python RNS Transport.
 */

import { Logger, LogLevel } from './log/Logger';
import {
  Packet,
  PacketReceipt,
  PACKET_DATA,
  PACKET_ANNOUNCE,
  PACKET_LINKREQUEST,
  PACKET_PROOF,
  PROPAGATION_BROADCAST,
  CONTEXT_PATH_RESPONSE,
  HEADER_1,
  HEADER_2,
} from './Packet';
import { Destination, AnnounceHandler, DEST_SINGLE, IN, OUT } from './Destination';
import { Identity } from './Identity';
import {
  truncatedHash,
  fullHash,
  TRUNCATED_HASHLENGTH,
  HASHLENGTH,
  sha256,
} from './crypto';
import { toHex, shortHex, concatBytes, bytesEqual } from './utils/bytes';

const TAG = 'Transport';

// ── Constants (matching Python RNS) ──────────────────────────────

/** Transport types */
export const TRANSPORT_BROADCAST = 0x00;
export const TRANSPORT_TRANSPORT = 0x01;
export const TRANSPORT_RELAY = 0x02;
export const TRANSPORT_TUNNEL = 0x03;

/** Pathfinder constants */
export const PATHFINDER_M = 128; // Max hops
export const PATHFINDER_R = 1; // Path request retries
export const PATHFINDER_G = 5; // Grace hops
export const PATHFINDER_RW = 10; // Random window

/** Timing constants (in milliseconds) */
export const JOB_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
export const CLEAN_INTERVAL_MS = 15 * 60 * 1000; // 15 minutes
export const PERSIST_INTERVAL_MS = 12 * 60 * 60 * 1000; // 12 hours
export const DEFAULT_PER_HOP_TIMEOUT_MS = 6000; // 6 seconds
export const PATH_REQUEST_TIMEOUT_MS = 15000; // 15 seconds

/** Path expiry times */
export const PATH_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
export const AP_PATH_EXPIRY_MS = 24 * 60 * 60 * 1000; // 1 day
export const ROAMING_PATH_EXPIRY_MS = 6 * 60 * 60 * 1000; // 6 hours

/** Announce management */
export const MAX_QUEUED_ANNOUNCES = 16384;
export const QUEUED_ANNOUNCE_LIFE_MS = 24 * 60 * 60 * 1000;
export const ANNOUNCE_CAP = 0.02; // 2% bandwidth cap

/** Packet cache */
export const PACKET_CACHE_MAX = 1000;
export const DEDUP_WINDOW_MS = 5000; // 5 seconds

/** Path entry in the routing table */
interface PathEntry {
  destinationHash: Uint8Array;
  nextHop: Uint8Array | null;
  interfaceName: string | null;
  hops: number;
  timestamp: number;
  expiresAt: number;
  announcePacket: Uint8Array | null;
}

/** Announce entry in the rebroadcast queue */
interface QueuedAnnounce {
  packet: Packet;
  interfaceName: string;
  timestamp: number;
  retransmitAt: number;
  hops: number;
}

/** Link tracking entry */
interface LinkEntry {
  linkId: Uint8Array;
  destinationHash: Uint8Array;
  interfaceName: string;
  timestamp: number;
}

export class Transport {
  private static _instance: Transport | null = null;

  // State
  private _started: boolean = false;
  private _identity: Identity | null = null;

  // Destination registry
  private _destinations: Map<string, Destination> = new Map();

  // Routing table (destination_hash_hex → PathEntry)
  private _pathTable: Map<string, PathEntry> = new Map();

  // Announce handlers
  private _announceHandlers: AnnounceHandler[] = [];

  // Packet deduplication (hash_hex → timestamp)
  private _packetHashCache: Map<string, number> = new Map();

  // Pending path requests (dest_hash_hex → {timestamp, callbacks})
  private _pendingPathRequests: Map<string, {
    timestamp: number;
    callbacks: Array<(success: boolean) => void>;
  }> = new Map();

  // Queued announces for rebroadcast
  private _announceQueue: QueuedAnnounce[] = [];

  // Active links
  private _activeLinks: Map<string, LinkEntry> = new Map();

  // Registered interfaces
  private _interfaces: any[] = [];

  // Packet receipts
  private _receipts: Map<string, PacketReceipt> = new Map();

  // Timers
  private _jobTimer: ReturnType<typeof setInterval> | null = null;
  private _cleanTimer: ReturnType<typeof setInterval> | null = null;
  private _persistTimer: ReturnType<typeof setInterval> | null = null;

  // Traffic counters
  private _txBytes: number = 0;
  private _rxBytes: number = 0;
  private _txPackets: number = 0;
  private _rxPackets: number = 0;

  // ── Singleton ─────────────────────────────────────────────────

  static getInstance(): Transport {
    if (!Transport._instance) {
      Transport._instance = new Transport();
    }
    return Transport._instance;
  }

  private constructor() {}

  // ── Lifecycle ─────────────────────────────────────────────────

  /** Start the transport engine */
  start(identity?: Identity): void {
    if (this._started) return;

    this._identity = identity ?? new Identity();
    this._started = true;

    // Start job loops
    this._jobTimer = setInterval(() => this.jobLoop(), JOB_INTERVAL_MS);
    this._cleanTimer = setInterval(() => this.cleanLoop(), CLEAN_INTERVAL_MS);

    Logger.info('Transport engine started', TAG);
    Logger.debug(`Transport identity: ${this._identity.hexHash.slice(0, 12)}...`, TAG);
  }

  /** Stop the transport engine */
  stop(): void {
    if (!this._started) return;

    if (this._jobTimer) clearInterval(this._jobTimer);
    if (this._cleanTimer) clearInterval(this._cleanTimer);
    if (this._persistTimer) clearInterval(this._persistTimer);
    this._jobTimer = null;
    this._cleanTimer = null;
    this._persistTimer = null;

    this._started = false;
    Logger.info('Transport engine stopped', TAG);
  }

  get isStarted(): boolean {
    return this._started;
  }

  // ── Destination Management ────────────────────────────────────

  /** Register a destination for receiving packets */
  registerDestination(destination: Destination): void {
    const key = toHex(destination.hash);
    this._destinations.set(key, destination);
    Logger.info(
      `Registered destination: ${destination.fullName} [${shortHex(destination.hash)}]`,
      TAG
    );
  }

  /** Unregister a destination */
  deregisterDestination(destination: Destination): void {
    const key = toHex(destination.hash);
    this._destinations.delete(key);
    Logger.debug(`Deregistered destination: ${shortHex(destination.hash)}`, TAG);
  }

  /** Find a registered destination by hash */
  findDestination(destinationHash: Uint8Array): Destination | null {
    return this._destinations.get(toHex(destinationHash)) ?? null;
  }

  // ── Interface Management ──────────────────────────────────────

  /** Register a network interface */
  registerInterface(iface: any): void {
    this._interfaces.push(iface);
    Logger.info(`Registered interface: ${iface.name ?? 'unnamed'}`, TAG);
  }

  /** Get all registered interfaces */
  getInterfaces(): any[] {
    return [...this._interfaces];
  }

  // ── Announce Handling ─────────────────────────────────────────

  /** Register an announce handler */
  registerAnnounceHandler(handler: AnnounceHandler): void {
    this._announceHandlers.push(handler);
  }

  /** Process an incoming announce */
  private handleAnnounce(packet: Packet, fromInterface?: string): void {
    Logger.debug(
      `Processing announce for ${shortHex(packet.destinationHash)} from ${fromInterface ?? 'local'}`,
      TAG
    );

    // Validate the announce
    const identity = Identity.validateAnnounce(packet.data, packet.destinationHash);
    if (!identity) {
      Logger.warn(`Invalid announce for ${shortHex(packet.destinationHash)}`, TAG);
      return;
    }

    // Update path table
    const hashHex = toHex(packet.destinationHash);
    const existingPath = this._pathTable.get(hashHex);
    const newHops = packet.hops;

    // Only update if this is a shorter/equal path or no existing path
    if (!existingPath || newHops <= existingPath.hops) {
      this._pathTable.set(hashHex, {
        destinationHash: packet.destinationHash,
        nextHop: null, // Direct for locally received announces
        interfaceName: fromInterface ?? null,
        hops: newHops,
        timestamp: Date.now(),
        expiresAt: Date.now() + PATH_EXPIRY_MS,
        announcePacket: packet.raw,
      });

      Logger.info(
        `Path updated: ${shortHex(packet.destinationHash)} via ${fromInterface ?? 'local'} (${newHops} hops)`,
        TAG
      );
    }

    // Notify announce handlers
    // Extract app data from announce
    const appDataOffset = 64 + 10 + 10 + 64; // pubkey + name_hash + random_hash + signature
    const appData = packet.data.length > appDataOffset
      ? packet.data.slice(appDataOffset)
      : null;

    for (const handler of this._announceHandlers) {
      try {
        handler(packet.destinationHash, identity, appData);
      } catch (e) {
        Logger.error(`Announce handler error: ${e}`, TAG);
      }
    }

    // Check pending path requests
    const pendingKey = toHex(packet.destinationHash);
    const pending = this._pendingPathRequests.get(pendingKey);
    if (pending) {
      for (const cb of pending.callbacks) {
        try { cb(true); } catch {}
      }
      this._pendingPathRequests.delete(pendingKey);
    }

    // Queue for rebroadcast if applicable
    if (packet.hops < PATHFINDER_M) {
      this.queueAnnounce(packet, fromInterface ?? 'local');
    }
  }

  /** Queue an announce for rebroadcast */
  private queueAnnounce(packet: Packet, fromInterface: string): void {
    if (this._announceQueue.length >= MAX_QUEUED_ANNOUNCES) {
      // Remove oldest
      this._announceQueue.shift();
    }

    // Random delay for rebroadcast to prevent collisions
    const delay = Math.random() * PATHFINDER_RW * 1000;

    this._announceQueue.push({
      packet,
      interfaceName: fromInterface,
      timestamp: Date.now(),
      retransmitAt: Date.now() + delay,
      hops: packet.hops,
    });
  }

  // ── Packet Routing ────────────────────────────────────────────

  /**
   * Process an outbound packet (from local application).
   * This is the main entry point for sending packets.
   */
  outbound(packet: Packet): boolean {
    if (!this._started) {
      Logger.error('Cannot send: Transport not started', TAG);
      return false;
    }

    // Pack the packet
    const raw = packet.pack();

    // Create receipt if needed
    if (packet.createReceipt && packet.packetType === PACKET_DATA) {
      const receipt = new PacketReceipt(packet);
      packet.receipt = receipt;
      this._receipts.set(toHex(receipt.hash), receipt);
    }

    // Determine routing
    if (packet.packetType === PACKET_ANNOUNCE) {
      // Announces go to all interfaces
      this.transmitToAll(packet);
    } else {
      // Data packets need routing
      const destHex = toHex(packet.destinationHash);
      const path = this._pathTable.get(destHex);

      if (path) {
        // We have a path - send to the appropriate interface
        this.transmitToPath(packet, path);
      } else {
        // No path known - broadcast
        this.transmitToAll(packet);
      }
    }

    this._txPackets++;
    this._txBytes += raw.length;
    packet.sent = true;

    Logger.debug(
      `Outbound: ${packet.toString()} (${raw.length}B)`,
      TAG
    );
    return true;
  }

  /**
   * Process an inbound packet (from a network interface).
   */
  inbound(raw: Uint8Array, fromInterface?: any): void {
    if (!this._started) return;

    this._rxPackets++;
    this._rxBytes += raw.length;

    // Unpack
    let packet: Packet;
    try {
      packet = Packet.unpack(raw);
      packet.receivingInterface = fromInterface;
    } catch (e) {
      Logger.warn(`Failed to unpack packet: ${e}`, TAG);
      return;
    }

    // Deduplication
    const pktHash = toHex(packet.getHash());
    if (this._packetHashCache.has(pktHash)) {
      Logger.log('Duplicate packet dropped', LogLevel.EXTREME, TAG);
      return;
    }
    this._packetHashCache.set(pktHash, Date.now());

    Logger.debug(
      `Inbound: ${packet.toString()} from ${fromInterface?.name ?? 'unknown'}`,
      TAG
    );

    // Route by packet type
    switch (packet.packetType) {
      case PACKET_ANNOUNCE:
        this.handleAnnounce(packet, fromInterface?.name);
        break;

      case PACKET_LINKREQUEST:
        this.handleLinkRequest(packet);
        break;

      case PACKET_PROOF:
        this.handleProof(packet);
        break;

      case PACKET_DATA:
        this.handleData(packet);
        break;

      default:
        Logger.warn(`Unknown packet type: ${packet.packetType}`, TAG);
    }
  }

  /** Handle incoming data packet */
  private handleData(packet: Packet): void {
    const destHex = toHex(packet.destinationHash);
    const dest = this._destinations.get(destHex);

    if (dest) {
      // Packet is for a local destination
      dest.receive(packet);
    } else if (packet.headerType === HEADER_2 && packet.transportId) {
      // Packet needs forwarding (transport mode)
      this.forwardPacket(packet);
    } else {
      Logger.log(
        `No destination for ${shortHex(packet.destinationHash)}, dropping`,
        LogLevel.VERBOSE,
        TAG
      );
    }
  }

  /** Handle incoming link request */
  private handleLinkRequest(packet: Packet): void {
    const destHex = toHex(packet.destinationHash);
    const dest = this._destinations.get(destHex);

    if (dest && dest.acceptsLinks) {
      Logger.info(
        `Link request for ${shortHex(packet.destinationHash)}`,
        TAG
      );
      // Link establishment is handled by Link module
      // Emit event for Link to pick up
      if ((this as any)._linkRequestCallback) {
        (this as any)._linkRequestCallback(packet, dest);
      }
    }
  }

  /** Handle incoming proof */
  private handleProof(packet: Packet): void {
    // Check if we have a receipt for this proof
    const proofHash = toHex(packet.destinationHash);
    const receipt = this._receipts.get(proofHash);
    if (receipt) {
      receipt.prove();
      this._receipts.delete(proofHash);
      Logger.debug(`Proof received for ${shortHex(packet.destinationHash)}`, TAG);
    }
  }

  /** Forward a packet through the mesh */
  private forwardPacket(packet: Packet): void {
    // Increment hop count
    packet.hops++;

    if (packet.hops > PATHFINDER_M) {
      Logger.debug('Packet exceeded max hops, dropping', TAG);
      return;
    }

    const destHex = toHex(packet.destinationHash);
    const path = this._pathTable.get(destHex);

    if (path) {
      this.transmitToPath(packet, path);
      Logger.log(
        `Forwarded packet to ${shortHex(packet.destinationHash)} (hop ${packet.hops})`,
        LogLevel.VERBOSE,
        TAG
      );
    } else {
      Logger.debug(
        `No path for forward to ${shortHex(packet.destinationHash)}`,
        TAG
      );
    }
  }

  // ── Transmission ──────────────────────────────────────────────

  /** Transmit a packet to all interfaces */
  private transmitToAll(packet: Packet): void {
    const raw = packet.raw ?? packet.pack();
    for (const iface of this._interfaces) {
      try {
        iface.send(raw);
      } catch (e) {
        Logger.error(`Failed to transmit on ${iface.name ?? 'unnamed'}: ${e}`, TAG);
      }
    }
  }

  /** Transmit a packet along a specific path */
  private transmitToPath(packet: Packet, path: PathEntry): void {
    const raw = packet.raw ?? packet.pack();
    const iface = this._interfaces.find(
      (i: any) => i.name === path.interfaceName
    );
    if (iface) {
      try {
        iface.send(raw);
      } catch (e) {
        Logger.error(`Failed to transmit on path via ${iface.name}: ${e}`, TAG);
      }
    } else {
      // Fallback to broadcast
      this.transmitToAll(packet);
    }
  }

  // ── Path Management ───────────────────────────────────────────

  /** Check if we have a path to a destination */
  hasPath(destinationHash: Uint8Array): boolean {
    const path = this._pathTable.get(toHex(destinationHash));
    return path !== undefined && path.expiresAt > Date.now();
  }

  /** Get hop count to a destination (-1 if no path) */
  hopsTo(destinationHash: Uint8Array): number {
    const path = this._pathTable.get(toHex(destinationHash));
    if (!path || path.expiresAt < Date.now()) return -1;
    return path.hops;
  }

  /** Get the next hop for a destination */
  nextHop(destinationHash: Uint8Array): Uint8Array | null {
    const path = this._pathTable.get(toHex(destinationHash));
    if (!path || path.expiresAt < Date.now()) return null;
    return path.nextHop;
  }

  /**
   * Request a path to a destination.
   * Returns a promise that resolves when the path is found or times out.
   */
  requestPath(destinationHash: Uint8Array): Promise<boolean> {
    // If we already have a path, resolve immediately
    if (this.hasPath(destinationHash)) {
      return Promise.resolve(true);
    }

    const destHex = toHex(destinationHash);

    return new Promise<boolean>((resolve) => {
      // Add to pending
      let pending = this._pendingPathRequests.get(destHex);
      if (!pending) {
        pending = { timestamp: Date.now(), callbacks: [] };
        this._pendingPathRequests.set(destHex, pending);

        // Broadcast a path request
        const pkt = new Packet();
        pkt.packetType = PACKET_DATA;
        pkt.context = CONTEXT_PATH_RESPONSE;
        pkt.destinationHash = destinationHash;
        pkt.data = new Uint8Array(0);
        pkt.propagationType = PROPAGATION_BROADCAST;
        this.outbound(pkt);

        Logger.info(`Path requested for ${shortHex(destinationHash)}`, TAG);
      }
      pending.callbacks.push(resolve);

      // Timeout
      setTimeout(() => {
        const p = this._pendingPathRequests.get(destHex);
        if (p) {
          this._pendingPathRequests.delete(destHex);
          for (const cb of p.callbacks) {
            try { cb(false); } catch {}
          }
        }
      }, PATH_REQUEST_TIMEOUT_MS);
    });
  }

  /**
   * Wait for a path to be available.
   * Calls requestPath if needed and waits.
   */
  async awaitPath(
    destinationHash: Uint8Array,
    timeoutMs: number = PATH_REQUEST_TIMEOUT_MS
  ): Promise<boolean> {
    if (this.hasPath(destinationHash)) return true;
    return this.requestPath(destinationHash);
  }

  // ── Job Loops ─────────────────────────────────────────────────

  /** Main job loop - runs every 5 minutes */
  private jobLoop(): void {
    Logger.log('Running transport job loop', LogLevel.EXTREME, TAG);

    // Process announce rebroadcast queue
    this.processAnnounceQueue();

    // Clean up receipts
    this.cleanReceipts();

    Logger.debug(
      `Stats: TX=${this._txPackets}pkts/${this._txBytes}B RX=${this._rxPackets}pkts/${this._rxBytes}B paths=${this._pathTable.size} dests=${this._destinations.size}`,
      TAG
    );
  }

  /** Clean loop - runs every 15 minutes */
  private cleanLoop(): void {
    Logger.log('Running transport clean loop', LogLevel.EXTREME, TAG);
    const now = Date.now();

    // Clean expired paths
    for (const [key, path] of this._pathTable) {
      if (path.expiresAt < now) {
        this._pathTable.delete(key);
        Logger.log(`Expired path: ${key.slice(0, 12)}...`, LogLevel.VERBOSE, TAG);
      }
    }

    // Clean packet hash cache (dedup window)
    for (const [hash, timestamp] of this._packetHashCache) {
      if (now - timestamp > DEDUP_WINDOW_MS) {
        this._packetHashCache.delete(hash);
      }
    }

    // Trim cache size
    if (this._packetHashCache.size > PACKET_CACHE_MAX) {
      const entries = [...this._packetHashCache.entries()].sort((a, b) => a[1] - b[1]);
      const toRemove = entries.slice(0, entries.length - PACKET_CACHE_MAX);
      for (const [hash] of toRemove) {
        this._packetHashCache.delete(hash);
      }
    }

    // Clean expired pending path requests
    for (const [key, pending] of this._pendingPathRequests) {
      if (now - pending.timestamp > PATH_REQUEST_TIMEOUT_MS) {
        for (const cb of pending.callbacks) {
          try { cb(false); } catch {}
        }
        this._pendingPathRequests.delete(key);
      }
    }
  }

  /** Process queued announces for rebroadcast */
  private processAnnounceQueue(): void {
    const now = Date.now();
    const toRebroadcast: QueuedAnnounce[] = [];

    this._announceQueue = this._announceQueue.filter((entry) => {
      // Remove expired
      if (now - entry.timestamp > QUEUED_ANNOUNCE_LIFE_MS) return false;

      // Check if ready to retransmit
      if (entry.retransmitAt <= now) {
        toRebroadcast.push(entry);
        return false; // Remove after rebroadcast
      }
      return true;
    });

    for (const entry of toRebroadcast) {
      // Increment hops and retransmit
      entry.packet.hops++;
      if (entry.packet.hops <= PATHFINDER_M) {
        this.transmitToAll(entry.packet);
        Logger.log(
          `Rebroadcast announce for ${shortHex(entry.packet.destinationHash)} (hop ${entry.packet.hops})`,
          LogLevel.VERBOSE,
          TAG
        );
      }
    }
  }

  /** Clean expired receipts */
  private cleanReceipts(): void {
    const now = Date.now();
    const expiry = 5 * 60 * 1000; // 5 min receipt lifetime
    for (const [hash, receipt] of this._receipts) {
      if (now - receipt.sentAt > expiry) {
        receipt.cancel();
        this._receipts.delete(hash);
      }
    }
  }

  // ── Cache ─────────────────────────────────────────────────────

  /** Cache a packet by hash */
  cachePacket(packet: Packet): void {
    const hash = toHex(packet.getHash());
    this._packetHashCache.set(hash, Date.now());
  }

  /** Check if a packet is in the cache */
  isCached(packetHash: Uint8Array): boolean {
    return this._packetHashCache.has(toHex(packetHash));
  }

  // ── Statistics ────────────────────────────────────────────────

  get stats() {
    return {
      txPackets: this._txPackets,
      txBytes: this._txBytes,
      rxPackets: this._rxPackets,
      rxBytes: this._rxBytes,
      paths: this._pathTable.size,
      destinations: this._destinations.size,
      interfaces: this._interfaces.length,
      pendingPathRequests: this._pendingPathRequests.size,
      announceQueue: this._announceQueue.length,
      receipts: this._receipts.size,
    };
  }

  /** Get all known paths */
  getPathTable(): Map<string, PathEntry> {
    return new Map(this._pathTable);
  }

  // ── Persistence ───────────────────────────────────────────────

  /** Export path table and known destinations for persistence */
  exportState(): {
    paths: Array<{ hash: string; hops: number; iface: string | null; expires: number }>;
  } {
    const paths: Array<{ hash: string; hops: number; iface: string | null; expires: number }> = [];
    for (const [hash, path] of this._pathTable) {
      paths.push({
        hash,
        hops: path.hops,
        iface: path.interfaceName,
        expires: path.expiresAt,
      });
    }
    return { paths };
  }

  /** Import persisted state */
  importState(state: ReturnType<typeof Transport.prototype.exportState>): void {
    const now = Date.now();
    for (const p of state.paths) {
      if (p.expires > now) {
        this._pathTable.set(p.hash, {
          destinationHash: new Uint8Array(0), // Will be derived from hex
          nextHop: null,
          interfaceName: p.iface,
          hops: p.hops,
          timestamp: now,
          expiresAt: p.expires,
          announcePacket: null,
        });
      }
    }
    Logger.info(`Imported ${state.paths.length} paths from persistence`, TAG);
  }
}
