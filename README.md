# Distributed Key Generation (DKG) Network PoC

This project demonstrates a Distributed Key Generation (DKG) protocol implementation using the Pedersen DKG scheme from the Kyber cryptographic library. The system allows multiple nodes to collaboratively generate a shared public key while each node maintains its own private key share.

## Overview

The DKG protocol enables a group of nodes to generate a distributed key pair where:
- Each node has a share of the private key
- The public key is known to all participants
- No single node knows the complete private key
- A threshold of nodes can collaborate to use the private key

This implementation uses:
- Go programming language
- Kyber cryptographic library (specifically the Pedersen DKG implementation)
- HTTP for node communication

## Prerequisites

- Go 1.21 or higher
- The required dependencies (automatically installed via go modules)

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd random-network-poc
   ```

2. Install dependencies:
   ```
   go mod download
   ```

## Running the DKG Network

The system requires at least 3 nodes to run the DKG protocol. Each node needs:
- A unique index (0, 1, or 2)
- A private key in hex format
- The same nonce value for all nodes
- A unique HTTP port

### Step 1: Prepare the Keys and Nonce

The private keys for each node and the nonce are already defined in the `nodes` file:

- **Node 0**:
  - Private key: `6b865eeebef3a3ad47a6bb43d9c7f6a8b7bd3dca5f508a9842fb8c4f549ef2d1`

- **Node 1**:
  - Private key: `8c0c2e94d80a74e8875a5d1048cc308a4fdc2bd737bf0c9383d4d786b1b35be3`

- **Node 2**:
  - Private key: `4d3bd130a9b481a01c84ae3b99339a32237d5294f6298d0257fbc625e00bda33`

- **Nonce** (shared by all nodes):
  - `fc25646dfb70219cc0dfeb4f9bdfb4fba33c1fec6b0dc654cdeb7eb5dacde7f6`

### Step 2: Start the Nodes

Open three separate terminal windows and run each node with its respective parameters:

**Node 0**:
```bash
go run main.go -index 0 -pk 6b865eeebef3a3ad47a6bb43d9c7f6a8b7bd3dca5f508a9842fb8c4f549ef2d1 -nonce fc25646dfb70219cc0dfeb4f9bdfb4fba33c1fec6b0dc654cdeb7eb5dacde7f6 -http_port 8000
```

**Node 1**:
```bash
go run main.go -index 1 -pk 8c0c2e94d80a74e8875a5d1048cc308a4fdc2bd737bf0c9383d4d786b1b35be3 -nonce fc25646dfb70219cc0dfeb4f9bdfb4fba33c1fec6b0dc654cdeb7eb5dacde7f6 -http_port 8001
```

**Node 2**:
```bash
go run main.go -index 2 -pk 4d3bd130a9b481a01c84ae3b99339a32237d5294f6298d0257fbc625e00bda33 -nonce fc25646dfb70219cc0dfeb4f9bdfb4fba33c1fec6b0dc654cdeb7eb5dacde7f6 -http_port 8002
```

### Step 3: DKG Protocol Execution

The DKG protocol will automatically execute in the following steps:

1. Each node waits for all peers to become available (health check)
2. Each node generates its deal bundle
3. Each node sends its deal bundle to all other nodes
4. Each node processes the received deals
5. Each node sends its response bundle to all other nodes
6. Each node processes the received responses
7. Each node computes the final distributed key

After successful completion, each node will output its share of the distributed key and the common public key.

## API Endpoints

The nodes expose the following HTTP endpoints:

- `/health` - Health check endpoint
- `/deals` - Endpoint to receive deal bundles
- `/responses` - Endpoint to receive response bundles

## Project Structure

- `main.go` - The main application that sets up the HTTP server and coordinates the DKG protocol
- `dkg/` - Package containing the DKG implementation
  - `dkg.go` - Core DKG node implementation
  - `nodes.go` - Configuration for the DKG nodes
  - `dto.go` - Data Transfer Objects for JSON serialization
  - `dkg_test.go` - Tests for the DKG implementation

## Security Considerations

This is a proof-of-concept implementation and may not be suitable for production use without further security hardening:

- Communication between nodes is not encrypted (uses plain HTTP)
- There's no authentication mechanism for the API endpoints
- Error handling could be improved for production scenarios

## License

[Specify your license here]
