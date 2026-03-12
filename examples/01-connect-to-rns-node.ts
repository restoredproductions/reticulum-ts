/**
 * Example 1: Connect to a Python RNS Transport Node via TCP
 *
 * This is the simplest way to get your RORK/Expo app onto the
 * Reticulum network. Your app connects as a TCP client to an
 * existing Python RNS node that's already on the mesh.
 *
 * ┌─────────────────────┐         ┌──────────────────────────┐
 * │  Your RORK App       │  TCP   │  Python RNS Node          │
 * │  (reticulum-ts)      │───────▶│  (transport enabled)      │
 * │                      │ :4965  │                            │
 * │  TCPInterface        │◀───────│  TCPServerInterface        │
 * │  (client mode)       │        │                            │
 * └─────────────────────┘         │  ┌──────────────────────┐ │
 *                                  │  │ LoRa / Serial / I2P  │ │
 *                                  │  │ UDP / other RNS nodes│ │
 *                                  │  └──────────────────────┘ │
 *                                  └──────────────────────────┘
 *
 * Prerequisites:
 *   1. Python RNS node running with a TCPServerInterface (see example config below)
 *   2. `react-native-tcp-socket` installed in your Expo project
 *      (requires Expo dev client, not bare Expo Go)
 *
 * Python RNS config (~/.reticulum/config):
 *
 *   [reticulum]
 *     enable_transport = True
 *
 *   [interfaces]
 *     [[TCP Server Interface]]
 *       type = TCPServerInterface
 *       enabled = yes
 *       listen_ip = 0.0.0.0
 *       listen_port = 4965
 */

import {
  Reticulum,
  Identity,
  Destination,
  Link,
  TCPInterface,
  LogLevel,
  Logger,
  IN,
  OUT,
  DEST_SINGLE,
  DEST_PLAIN,
  toHex,
} from '../src';

async function main() {
  // ── Step 1: Subscribe to logs so you can see what's happening ────
  // In RORK, you'd pipe these into your debug UI component
  Logger.onLog((message, level, tag, timestamp) => {
    // This callback fires for every log message.
    // In RORK you could push these into a state array for display.
    console.log(`[${tag}] ${message}`);
  });

  // ── Step 2: Create a TCP interface pointing at your Python RNS node ──
  const tcpInterface = new TCPInterface({
    name: 'RNS Gateway',
    host: '192.168.1.100',   // <-- Change to your RNS node's IP
    port: 4965,              // <-- Standard RNS TCP port
    role: 'client',
    reconnect: true,         // Auto-reconnect if connection drops
    reconnectDelay: 5000,    // Retry every 5 seconds
  });

  // ── Step 3: Initialize Reticulum with TCP as the primary interface ──
  const rns = new Reticulum({
    logLevel: LogLevel.VERBOSE,  // Crank up logging for debug
    interfaces: [tcpInterface],
  });

  await rns.start();
  // At this point you're connected to the Reticulum network!

  // ── Step 4: Create your app's identity and destination ────────────
  const myIdentity = new Identity();
  console.log(`My identity hash: ${myIdentity.hexHash}`);

  // Create a destination other RNS nodes can reach
  const myDest = new Destination(
    myIdentity,
    IN,                    // We're receiving on this destination
    DEST_SINGLE,           // Encrypted, single-identity destination
    'myapp',               // App name
    'messenger',           // Aspect
  );

  rns.registerDestination(myDest);
  console.log(`Destination registered: ${myDest.fullName} [${myDest.hexHash}]`);

  // ── Step 5: Announce ourselves to the network ─────────────────────
  // Other RNS nodes (Python or TS) will see this announce
  // and learn how to route packets to us.
  const announcePkt = myDest.announce();
  rns.transport.outbound(announcePkt);
  console.log('Announced to network!');

  // ── Step 6: Listen for incoming packets ───────────────────────────
  myDest.onPacket((data, packet) => {
    console.log(`Received ${data.length} bytes from the mesh!`);
    console.log(`Data: ${new TextDecoder().decode(data)}`);
  });

  // ── Step 7: Send a packet to a known destination ──────────────────
  // If you know another node's destination hash, you can send to it:
  //
  //   const remoteHash = fromHex('abcdef0123456789abcdef0123456789');
  //   const remoteDest = new Destination(null, OUT, DEST_SINGLE, 'otherapp', 'service');
  //   // ... would need to set the remote identity after path discovery
  //
  // Or establish a Link for bidirectional encrypted communication:
  //
  //   const link = new Link(remoteDest);
  //   link.onEstablished((l) => {
  //     console.log('Link established!');
  //     l.send(new TextEncoder().encode('Hello from RORK!'));
  //   });
  //   link.establish();

  // ── Step 8: Print stats periodically ──────────────────────────────
  setInterval(() => {
    const stats = rns.getStats();
    console.log('Transport stats:', JSON.stringify(stats, null, 2));
  }, 30000);

  console.log('\nReticulum is running. Listening for packets...\n');
}

main().catch(console.error);
