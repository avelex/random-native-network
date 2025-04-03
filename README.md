# Random Native Network (Proof of Concept)

## Overview

Random Native Network is a blockchain platform designed to provide secure, unbiasable, and verifiable randomness as a service. This proof-of-concept implementation demonstrates a comprehensive random number generation system built directly into the blockchain protocol, leveraging threshold cryptography and BLS signatures.

![Random Network Demo](assets/screen.png)

## Key Features

### Distributed Key Generation (DKG)

The platform implements Pedersen's DKG protocol with libp2p networking to establish a distributed cryptographic setup where:

- Validators collectively generate a shared public key while individually maintaining private key shares
- The t-of-n threshold scheme ensures Byzantine fault tolerance
- The system remains secure even when up to t-1 validators are compromised
- No single entity can reconstruct the private key or bias the randomness generation

### Verifiable Random Function (VRF)

Our implementation uses BLS threshold signatures to create a VRF system that guarantees:

- **Unpredictability**: Future random values cannot be determined in advance
- **Unbiasability**: No participant can manipulate the output
- **Verifiability**: Anyone can verify the correctness of generated random values
- **Determinism**: Same inputs produce identical random outputs

### libp2p Networking Layer

The system leverages libp2p for peer-to-peer communication:

- **PubSub Messaging**: Efficient topic-based publish/subscribe for DKG protocol messages
- **Peer Discovery**: Automatic validator node discovery and connection establishment
- **NAT Traversal**: Communication across diverse network topologies
- **Message Authentication**: Cryptographic verification of all protocol messages

The Pedersen DKG messages (deals, responses, and justifications) are exchanged via dedicated libp2p pubsub topics, ensuring reliable and consistent message delivery across the validator network.

## Technical Requirements

- Go 1.24+
- libp2p networking stack
- Secure private key management
- Network connectivity between validator nodes

## Validator Configuration

The current implementation supports a 2-of-3 threshold configuration with the following validator setup:

| Node | Private Key |
|------|-------------|
| 0    | `6b865eeebef3a3ad47a6bb43d9c7f6a8b7bd3dca5f508a9842fb8c4f549ef2d1` |
| 1    | `8c0c2e94d80a74e8875a5d1048cc308a4fdc2bd737bf0c9383d4d786b1b35be3` |
| 2    | `4d3bd130a9b481a01c84ae3b99339a32237d5294f6298d0257fbc625e00bda33` |

**Network Nonce**: `fc25646dfb70219cc0dfeb4f9bdfb4fba33c1fec6b0dc654cdeb7eb5dacde7f6`

## Running Validator Nodes

Launch validator nodes with the following commands:

**Primary Node (0)**:
```bash
go run main.go -index 0 -pk 6b865eeebef3a3ad47a6bb43d9c7f6a8b7bd3dca5f508a9842fb8c4f549ef2d1 -nonce fc25646dfb70219cc0dfeb4f9bdfb4fba33c1fec6b0dc654cdeb7eb5dacde7f6
```

**Secondary Nodes**:
```bash
go run main.go -index 1 -pk 8c0c2e94d80a74e8875a5d1048cc308a4fdc2bd737bf0c9383d4d786b1b35be3 -nonce fc25646dfb70219cc0dfeb4f9bdfb4fba33c1fec6b0dc654cdeb7eb5dacde7f6
```

```bash
go run main.go -index 2 -pk 4d3bd130a9b481a01c84ae3b99339a32237d5294f6298d0257fbc625e00bda33 -nonce fc25646dfb70219cc0dfeb4f9bdfb4fba33c1fec6b0dc654cdeb7eb5dacde7f6
```

## Protocol Workflow

### DKG Phase

1. **Network Initialization**: Validators establish secure libp2p connections
2. **Deal Generation**: Each validator generates encrypted key shares for other participants
3. **Deal Distribution**: Shares are published to the libp2p pubsub topic
4. **Deal Verification**: Validators verify received deals and send response messages
5. **Threshold Confirmation**: The system confirms that enough valid responses were received
6. **Key Finalization**: Public key is established, and validators secure their private shares

### Random Beacon Generation

1. **Beacon Initialization**: Primary node proposes a seed based on blockchain state
2. **Partial Signing**: Each validator produces a BLS partial signature on the seed
3. **Signature Collection**: All partial signatures are collected via libp2p
4. **Aggregation**: Valid signatures are combined into a threshold signature
5. **Randomness Extraction**: Final random value is derived from the threshold signature
6. **Verification**: Random value and cryptographic proof are made available on-chain

## Security Properties

- **Distributed Trust**: No single validator can compromise the system
- **Byzantine Fault Tolerance**: Functions correctly with up to t-1 malicious validators
- **Cryptographic Verifiability**: All random outputs include cryptographic proofs
- **Forward Secrecy**: Past random values remain secure even if keys are later compromised

## Production Considerations

For production deployment, additional security measures are recommended:

- TLS encryption for all network communication
- Hardware security modules (HSMs) for key management
- libp2p private networks with strong peer authentication
- DoS protection and rate limiting
- Comprehensive monitoring and alerting
- Secure key rotation procedures

## License

This project is licensed under the Apache License 2.0.

Dependencies:
- [Kyber](https://github.com/dedis/kyber) cryptographic library (Mozilla Public License 2.0)
- [libp2p](https://github.com/libp2p/go-libp2p) networking stack (MIT/Apache-2.0 dual license)
