/**
 * Example 2: RORK / Expo React Native Integration
 *
 * This shows how to use reticulum-ts inside a RORK-built Expo app.
 * Copy this pattern into your RORK screens/components.
 *
 * Prerequisites:
 *   npx expo install react-native-tcp-socket
 *   npm install reticulum-ts   (or link from git repo)
 *
 * Note: react-native-tcp-socket requires an Expo dev client build,
 * not bare Expo Go. Use `npx expo run:ios` or `npx expo run:android`.
 */

import React, { useEffect, useState, useRef, useCallback } from 'react';
import { View, Text, ScrollView, TextInput, Button, StyleSheet } from 'react-native';

import {
  Reticulum,
  Identity,
  Destination,
  TCPInterface,
  LogLevel,
  Logger,
  Link,
  IN,
  DEST_SINGLE,
  toHex,
  shortHex,
} from 'reticulum-ts';

// ── Configuration ───────────────────────────────────────────────────

const RNS_HOST = '192.168.1.100';  // Your Python RNS node IP
const RNS_PORT = 4965;             // Python RNS TCP port
const APP_NAME = 'rorkapp';
const APP_ASPECT = 'messenger';

// ── Main Screen Component ───────────────────────────────────────────

export default function ReticulumScreen() {
  const [logs, setLogs] = useState<string[]>([]);
  const [connected, setConnected] = useState(false);
  const [destHash, setDestHash] = useState('');
  const [stats, setStats] = useState<any>(null);
  const rnsRef = useRef<Reticulum | null>(null);
  const destRef = useRef<Destination | null>(null);

  // ── Append a log line (capped at 200 for performance) ─────────
  const addLog = useCallback((msg: string) => {
    setLogs((prev) => [...prev.slice(-199), msg]);
  }, []);

  // ── Initialize Reticulum on mount ─────────────────────────────
  useEffect(() => {
    let unsub: (() => void) | null = null;

    async function init() {
      // Subscribe to all Reticulum logs
      unsub = Logger.onLog((message, level, tag) => {
        addLog(`[${tag}] ${message}`);
      });

      // Create TCP interface to your RNS gateway
      const tcpIface = new TCPInterface({
        name: 'RNS Gateway',
        host: RNS_HOST,
        port: RNS_PORT,
        role: 'client',
        reconnect: true,
        reconnectDelay: 5000,
      });

      // Initialize and start Reticulum
      const rns = new Reticulum({
        logLevel: LogLevel.VERBOSE,
        interfaces: [tcpIface],
      });

      try {
        await rns.start();
        rnsRef.current = rns;
        setConnected(true);
        addLog('--- Reticulum started! ---');

        // Create identity and destination
        const identity = new Identity();
        const dest = new Destination(
          identity, IN, DEST_SINGLE, APP_NAME, APP_ASPECT
        );
        rns.registerDestination(dest);
        destRef.current = dest;
        setDestHash(dest.hexHash);

        // Listen for incoming packets
        dest.onPacket((data, pkt) => {
          const text = new TextDecoder().decode(data);
          addLog(`📨 RECEIVED: ${text}`);
        });

        // Announce to the network
        const announcePkt = dest.announce();
        rns.transport.outbound(announcePkt);
        addLog(`Announced as ${dest.fullName}`);

        // Stats refresh
        const statsTimer = setInterval(() => {
          if (rnsRef.current) {
            setStats(rnsRef.current.getStats());
          }
        }, 10000);

        return () => clearInterval(statsTimer);
      } catch (e) {
        addLog(`ERROR: Failed to start: ${e}`);
      }
    }

    init();

    return () => {
      unsub?.();
      rnsRef.current?.stop();
    };
  }, [addLog]);

  return (
    <View style={styles.container}>
      {/* Status Bar */}
      <View style={styles.statusBar}>
        <View style={[styles.dot, { backgroundColor: connected ? '#4CAF50' : '#f44336' }]} />
        <Text style={styles.statusText}>
          {connected ? `Connected | ${destHash.slice(0, 12)}...` : 'Disconnected'}
        </Text>
      </View>

      {/* Stats */}
      {stats && (
        <View style={styles.statsBar}>
          <Text style={styles.statsText}>
            TX: {stats.txPackets} pkts | RX: {stats.rxPackets} pkts | Paths: {stats.paths}
          </Text>
        </View>
      )}

      {/* Log Output */}
      <ScrollView style={styles.logContainer}>
        {logs.map((line, i) => (
          <Text key={i} style={styles.logLine}>{line}</Text>
        ))}
      </ScrollView>
    </View>
  );
}

// ── Styles ──────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#1a1a2e' },
  statusBar: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 12,
    backgroundColor: '#16213e',
  },
  dot: { width: 10, height: 10, borderRadius: 5, marginRight: 8 },
  statusText: { color: '#e0e0e0', fontFamily: 'monospace', fontSize: 13 },
  statsBar: { padding: 8, backgroundColor: '#0f3460' },
  statsText: { color: '#a0c4ff', fontFamily: 'monospace', fontSize: 11 },
  logContainer: { flex: 1, padding: 8 },
  logLine: { color: '#c0c0c0', fontFamily: 'monospace', fontSize: 11, marginBottom: 2 },
});
