/**
 * Example 3: Encrypted Link-based Chat
 *
 * Shows how to establish an encrypted Link to another Reticulum
 * destination and exchange messages. This works with Python RNS
 * nodes running the same app name/aspect.
 *
 * A Link provides:
 *   - End-to-end AES-256 encryption (ephemeral ECDH keys)
 *   - Bidirectional communication
 *   - Keepalive and automatic stale detection
 *   - RTT measurement
 */

import {
  Reticulum,
  Identity,
  Destination,
  Link,
  LinkStatus,
  TCPInterface,
  LogLevel,
  Logger,
  IN,
  OUT,
  DEST_SINGLE,
  fromHex,
  toHex,
} from '../src';

const APP_NAME = 'example';
const APP_ASPECT = 'chat';

// ── Server Mode: Listen for incoming links ──────────────────────────

async function runServer() {
  const tcpIface = new TCPInterface({
    name: 'RNS Gateway',
    host: '192.168.1.100',
    port: 4965,
    role: 'client',
  });

  const rns = new Reticulum({
    logLevel: LogLevel.VERBOSE,
    interfaces: [tcpIface],
  });
  await rns.start();

  // Create server identity and destination
  const serverIdentity = new Identity();
  const serverDest = new Destination(
    serverIdentity, IN, DEST_SINGLE, APP_NAME, APP_ASPECT
  );
  rns.registerDestination(serverDest);

  console.log(`\nChat server running!`);
  console.log(`Destination hash: ${serverDest.hexHash}`);
  console.log(`Share this hash with the client to connect.\n`);

  // Announce so clients can find us
  const announcePkt = serverDest.announce();
  rns.transport.outbound(announcePkt);

  // The Transport engine will handle incoming Link requests.
  // When a Link is established, we receive packets on it:
  // (In a full implementation, Transport would wire this up automatically.
  //  This shows the manual pattern for clarity.)
}

// ── Client Mode: Connect to a known destination ─────────────────────

async function runClient(remoteHashHex: string) {
  const tcpIface = new TCPInterface({
    name: 'RNS Gateway',
    host: '192.168.1.100',
    port: 4965,
    role: 'client',
  });

  const rns = new Reticulum({
    logLevel: LogLevel.VERBOSE,
    interfaces: [tcpIface],
  });
  await rns.start();

  // Create client identity
  const clientIdentity = new Identity();

  // Create an outbound destination for the remote server
  // Note: For a real app, you'd discover this via announces.
  // Here we create a placeholder destination with the known hash.
  const remoteDest = new Destination(
    clientIdentity, OUT, DEST_SINGLE, APP_NAME, APP_ASPECT
  );

  // Request a path to the destination
  const remoteHash = fromHex(remoteHashHex);
  console.log(`Requesting path to ${remoteHashHex.slice(0, 12)}...`);

  const pathFound = await rns.transport.awaitPath(remoteHash, 30000);
  if (!pathFound) {
    console.log('No path found! Is the server running and announced?');
    return;
  }
  console.log('Path found!');

  // Establish an encrypted link
  const link = new Link(remoteDest);

  link.onEstablished((l) => {
    console.log(`\nLink established! RTT: ${l.rtt}ms`);
    console.log('Sending hello message...\n');

    // Send an encrypted message
    const msg = new TextEncoder().encode('Hello from reticulum-ts!');
    l.send(msg);
  });

  link.onPacket((data, pkt) => {
    const text = new TextDecoder().decode(data);
    console.log(`Received: ${text}`);
  });

  link.onClosed((l) => {
    console.log('Link closed.');
  });

  link.establish();
}

// ── Entry point ─────────────────────────────────────────────────────

const mode = process.argv[2];
const remoteHash = process.argv[3];

if (mode === 'server') {
  runServer().catch(console.error);
} else if (mode === 'client' && remoteHash) {
  runClient(remoteHash).catch(console.error);
} else {
  console.log('Usage:');
  console.log('  Server: ts-node examples/03-link-chat.ts server');
  console.log('  Client: ts-node examples/03-link-chat.ts client <destination-hash>');
}
