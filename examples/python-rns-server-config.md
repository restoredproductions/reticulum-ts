# Python RNS Node Configuration for reticulum-ts Clients

Your RORK app connects directly to a Python RNS node via TCP.
Here's how to set up the Python side.

## 1. Install Python Reticulum

```bash
pip install rns
```

## 2. Generate default config

```bash
rnsd
# This creates ~/.reticulum/config on first run, then ctrl-c
```

## 3. Edit ~/.reticulum/config

Replace the contents with:

```ini
[reticulum]
  enable_transport = True
  share_instance = Yes
  shared_instance_port = 37428
  instance_control_port = 37429

[logging]
  loglevel = 4

[interfaces]

  # This is what your RORK app connects to.
  # It listens for incoming TCP connections from reticulum-ts clients.
  [[TCP Server Interface]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 0.0.0.0
    listen_port = 4965

  # Add any other interfaces your node needs to reach the mesh.
  # Examples below - uncomment and configure as needed:

  # [[UDP Interface]]
  #   type = UDPInterface
  #   enabled = yes
  #   listen_ip = 0.0.0.0
  #   listen_port = 4242
  #   forward_ip = 255.255.255.255
  #   forward_port = 4242

  # [[RNode LoRa Interface]]
  #   type = RNodeInterface
  #   enabled = yes
  #   port = /dev/ttyUSB0
  #   frequency = 915000000
  #   bandwidth = 125000
  #   txpower = 7
  #   spreadingfactor = 8
  #   codingrate = 5
```

## 4. Start the RNS transport daemon

```bash
rnsd -v
```

You should see:
```
[2026-03-12 10:00:00] [NOTICE] TCP Server Interface listening on 0.0.0.0:4965
```

## 5. Connect from your RORK app

In your TypeScript code:

```typescript
const tcpInterface = new TCPInterface({
  name: 'RNS Gateway',
  host: '192.168.1.100',  // Your server's LAN IP
  port: 4965,
});

const rns = new Reticulum({
  interfaces: [tcpInterface],
});
await rns.start();
```

## 6. Verify connectivity

On the Python side, you should see a log like:
```
[VERBOSE] TCP Server Interface: incoming connection from 192.168.1.50
```

On the RORK app side, the Logger will emit:
```
[TCPInterface] Connected to 192.168.1.100:4965
[Reticulum] Reticulum v0.1.0 started successfully
```

## Network diagram

```
┌─────────────────────┐                ┌──────────────────────┐
│  iPhone / Android    │     TCP        │  Linux/Mac/RPi       │
│  (RORK + Expo)       │────────────────│  Python RNS Node     │
│                      │   port 4965    │                      │
│  reticulum-ts        │                │  rnsd (transport)    │
│  TCPInterface        │                │  TCPServerInterface  │
└─────────────────────┘                │                      │
                                        │  + LoRa / UDP /     │
                                        │    Serial / I2P     │
                                        └──────────────────────┘
                                                   │
                                          ┌────────┴────────┐
                                          │  Reticulum Mesh  │
                                          │  (other nodes)   │
                                          └─────────────────┘
```

## Firewall note

Make sure port 4965 TCP is open on your RNS server's firewall:

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 4965/tcp

# firewalld (Fedora/RHEL)
sudo firewall-cmd --add-port=4965/tcp --permanent
sudo firewall-cmd --reload
```

## Running on a VPS

If your RNS node runs on a VPS (DigitalOcean, AWS, etc.), your
RORK app can connect over the internet - just use the VPS public IP.
The TCP connection is encrypted at the Reticulum protocol level
(per-packet ephemeral encryption), so it's safe over the open internet.
