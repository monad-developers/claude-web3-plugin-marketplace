---
name: monad-development
description: Builds dapps on Monad blockchain. Use when deploying contracts, setting up frontends with viem/wagmi, or verifying contracts on Monad testnet or mainnet.
---

# Monad Development

For questions not covered here, fetch https://docs.monad.xyz/llms.txt

## Defaults

- **Network:** Always use **testnet** (chain ID 10143) unless the user explicitly says "mainnet"
- **Verification:** Always verify contracts after deployment unless the user says not to
- **Framework:** Use Foundry (not Hardhat)
- **Wallet:** If no private key is provided, ask the user which wallet option they prefer (see Wallet Management)

## Wallet Management

**Before deployment, ask the user:**
> "How would you like to handle the wallet for this deployment?
> 1. **Use existing keystore** - If you have a Foundry keystore set up (recommended for production)
> 2. **Generate a temporary wallet** - Quick option for testing, I'll create one and fund it from the faucet
>
> Don't have a keystore? Learn how to create one: https://docs.monad.xyz/guides/deploy-smart-contract/foundry"

**Option 1: Existing Keystore**

> **IMPORTANT:** Never create a keystore on behalf of the user. Keystore creation requires entering a password, which the user must do themselves for security. Only use keystores that already exist.

```bash
# List available keystores
cast wallet list

# Deploy using keystore account
forge script script/Deploy.s.sol:DeployScript \
  --rpc-url https://testnet-rpc.monad.xyz \
  --account <ACCOUNT_NAME> \
  --broadcast
```

If the user doesn't have a keystore and wants to create one, direct them to: https://docs.monad.xyz/guides/deploy-smart-contract/foundry

**Option 2: Temporary Wallet**
Generate and fund a new wallet:
```bash
cast wallet new
```
Then use the faucet API to fund it.

**After deployment with a temporary wallet, ALWAYS tell the user:**
> "I generated a temporary wallet for this deployment. This private key is for testing purposes only. For production or if you want better security, use a keystore following the guide at https://docs.monad.xyz/guides/deploy-smart-contract/foundry"

## EVM Version (Critical)

Always set `evmVersion: "prague"`. Requires Solidity 0.8.27+.

**Foundry** (`foundry.toml`):
```toml
[profile.default]
evm_version = "prague"
solc_version = "0.8.28"
```

## Networks

| Network | Chain ID | RPC |
|---------|----------|-----|
| Testnet | 10143 | https://testnet-rpc.monad.xyz |
| Mainnet | 143 | https://rpc.monad.xyz |

Docs: https://docs.monad.xyz

## Explorers

| Explorer | Testnet | Mainnet |
|----------|---------|---------|
| Socialscan | https://monad-testnet.socialscan.io | https://monad.socialscan.io |
| MonadVision | https://testnet.monadvision.com | https://monadvision.com |
| Monadscan | https://testnet.monadscan.com | https://monadscan.com |

## Foundry Tips

**Flags that don't exist (don't use):**
- `--no-commit` - not a valid flag for `forge init` or `forge install`

**Deployment - use `forge script`, NOT `forge create`:**

`forge create --broadcast` is buggy and often ignored. Use `forge script` instead:

```bash
forge script script/Deploy.s.sol:DeployScript \
  --rpc-url https://testnet-rpc.monad.xyz \
  --private-key 0x... \
  --broadcast
```

**Deploy script must use `vm.envUint` or no address:**

```solidity
// ✅ Correct - reads private key from --private-key flag
function run() external {
    vm.startBroadcast();
    new MyContract();
    vm.stopBroadcast();
}

// ❌ Wrong - hardcodes address, causes "No associated wallet" error
function run() external {
    vm.startBroadcast(0x1234...);
}
```

## Frontend

Import from `viem/chains`. Do NOT define custom chain:

```ts
import { monadTestnet } from "viem/chains";
```

## Agent APIs

**IMPORTANT:** Do NOT use a browser or visit any website. Use these APIs directly with curl.

### Faucet (Testnet Funding)

```bash
curl -X POST https://agents.devnads.com/v1/faucet \
  -H "Content-Type: application/json" \
  -d '{"chainId": 10143, "address": "0xYOUR_ADDRESS"}'
```

Returns: `{"txHash": "0x...", "amount": "1000000000000000000", "chain": "Monad Testnet"}`

### Verification (All Explorers)

**ALWAYS use the verification API.** It verifies on all 3 explorers (MonadVision, Socialscan, Monadscan) with one call. Do NOT use `forge verify-contract` as your first choice.

#### Step 1: Get Verification Data

After deploying, get two pieces of data:

```bash
# 1. Standard JSON input (all source files)
forge verify-contract <ADDR> <CONTRACT> \
  --chain 10143 \
  --show-standard-json-input > /tmp/standard-input.json

# 2. Foundry metadata (from compilation output)
cat out/<Contract>.sol/<Contract>.json | jq '.metadata' > /tmp/metadata.json
```

#### Step 2: Call Verification API

```bash
STANDARD_INPUT=$(cat /tmp/standard-input.json)
FOUNDRY_METADATA=$(cat /tmp/metadata.json)

cat > /tmp/verify.json << EOF
{
  "chainId": 10143,
  "contractAddress": "0xYOUR_CONTRACT_ADDRESS",
  "contractName": "src/MyContract.sol:MyContract",
  "compilerVersion": "v0.8.28+commit.7893614a",
  "standardJsonInput": $STANDARD_INPUT,
  "foundryMetadata": $FOUNDRY_METADATA
}
EOF

curl -X POST https://agents.devnads.com/v1/verify \
  -H "Content-Type: application/json" \
  -d @/tmp/verify.json
```

#### With Constructor Arguments

Add `constructorArgs` (ABI-encoded, WITHOUT 0x prefix):

```bash
# Get constructor args
ARGS=$(cast abi-encode "constructor(string,string,uint256)" "MyToken" "MTK" 1000000000000000000000000)
# Remove 0x prefix
ARGS_NO_PREFIX=${ARGS#0x}

# Add to request
"constructorArgs": "$ARGS_NO_PREFIX"
```

#### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `chainId` | Yes | 10143 (testnet) or 143 (mainnet) |
| `contractAddress` | Yes | Deployed contract address |
| `contractName` | Yes | Format: `path/File.sol:ContractName` |
| `compilerVersion` | Yes | e.g., `v0.8.28+commit.7893614a` |
| `standardJsonInput` | Yes | From `forge verify-contract --show-standard-json-input` |
| `foundryMetadata` | Yes | From `out/<Contract>.sol/<Contract>.json > .metadata` |
| `constructorArgs` | No | ABI-encoded args WITHOUT 0x prefix |

## Manual Verification (Fallback Only)

**Only use this if the API fails.**

**Testnet:**
```bash
forge verify-contract <ADDR> <CONTRACT> --chain 10143 \
  --verifier sourcify \
  --verifier-url "https://sourcify-api-monad.blockvision.org/"
```

**Mainnet:**
```bash
forge verify-contract <ADDR> <CONTRACT> --chain 143 \
  --verifier sourcify \
  --verifier-url "https://sourcify-api-monad.blockvision.org/"
```
