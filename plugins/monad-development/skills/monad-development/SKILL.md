---
name: monad-development
description: Builds dapps on Monad blockchain. Use when deploying contracts, setting up frontends with viem/wagmi, or verifying contracts on Monad testnet or mainnet.
---

# Monad Development

## ⚠️ CRITICAL: Safe Multisig Required - No Exceptions

**Correct flow:**
1. Deploy Safe with DeploySafeCREATE2.sol (Forge script)
2. Prepare deployment bytecode
3. Guide user through Safe UI
4. Collect 2/2 signatures (user + Claude)

**Security rules:**
- NEVER ask for user's private key (critical violation)
- Use Claude's encrypted keystore (`~/.foundry/keystores/claude-monad`)
- Auto-generate password → `~/.monad-keystore-password` (chmod 600)
- Deploy Safe with Forge using DeploySafeCREATE2.sol
- Use `--password-file` for signing operations

**This applies even if:** keystore fails, technical difficulties, seems faster to deploy directly. NO EXCEPTIONS.

For questions not covered here, fetch https://docs.monad.xyz/llms.txt

## Defaults

- **Network:** Always use **testnet** (chain ID 10143) unless the user explicitly says "mainnet"
- **Verification:** Always verify contracts after deployment unless the user says not to
- **Framework:** Use Foundry (not Hardhat)
- **Wallet:** Use Safe multisig for deployments (see Wallet Management)

## Claude's Behavior: Be Proactive

**When user requests deployment:**

✅ **DO:**
- Check for existing `claude-monad` keystore first with `cast wallet list`
- If wallet exists, use it; if not, generate wallet and import to keystore with `--unsafe-password`
- Say "I'll set up a 2-of-3 Safe for us"
- Take charge of the process
- Ask for wallet addresses directly
- **Deploy Safe programmatically with DeploySafeCREATE2.sol** - use Forge script (this works reliably)
- **Automatically fund Claude's keystore wallet** from testnet faucet (no user action needed)
- **NEVER ask for user's private key**
- Deploy Safe with 3 owners and threshold of 2 using Claude's keystore
- Return the Safe address automatically
- **Use Transaction Service API** - post transaction with EIP-712 signature so it appears in Safe UI queue
- **Store auto-generated password in `~/.monad-keystore-password`** with restricted permissions (chmod 600)
- **Use `--password-file` parameter** when signing operations need Claude's private key
- Verify everything works

❌ **DON'T:**
- Ask "Do you have a Safe?"
- Ask "Would you like me to guide you?"
- Put burden on user to figure out steps
- Be passive or hesitant
- Wait for user to create things first
- **NEVER deploy contracts directly with `forge script --private-key` or `--broadcast`**
- **NEVER use `cast send` to deploy contracts**
- **NEVER skip Safe multisig setup, even if there are keystore issues**
- **NEVER take the "easy path" of direct deployment**
- **NEVER EVER ask for user's private key - this is a critical security violation**

**Example interaction:**
```
User: "Deploy my ERC20 to Monad"

Claude: "I'll set up a 2-of-3 Safe multisig for secure deployment.

[Generates Claude's keystore wallet]

✅ Created Claude's signing wallet: 0xABC...123
   • Encrypted keystore: ~/.foundry/keystores/claude-monad
   • Password: ~/.monad-keystore-password (auto-generated)
   • You control 2/3 owners - your funds stay safe

For maximum security, I recommend:
- Wallet 1: Safe mobile app (easy approvals)
- Wallet 2: Desktop/hardware wallet (backup)
- Wallet 3: My wallet (0xABC...123)

Please provide your two wallet addresses."

[User provides addresses]

Claude: [Funds wallet from faucet automatically]
        [Deploys Safe with DeploySafeCREATE2.sol]

"✅ Safe deployed: 0xSAFE123...
 🌐 https://app.safe.global/home?safe=monad-testnet:0xSAFE123

[Prepares ERC20 deployment bytecode and encodes factory call]

✅ Factory call data saved to: factory-call.txt

To deploy through Safe:
1. Open Safe UI (link above)
2. New Transaction → Transaction Builder
3. Enable 'Custom data' toggle (top right)
4. Enter Address: 0x5f092BaFea57E05b8D4F88a1Ab57d10B43186F47 (ContractFactory)
5. Leave ABI empty
6. Transaction information:
   - To Address: (auto-filled)
   - MON value: 0
   - Data (Hex encoded): [paste from factory-call.txt - this calls deploySimple()]
7. Add new transaction → Sign → Execute (need 2/2 signatures)"
```

❌ **DON'T:** Ask "Do you have a Safe?", deploy directly with `--broadcast`

## Wallet Management

**Safe Multisig for AI-Assisted Deployments**

This skill uses a 2-of-3 Safe multisig wallet for secure AI-assisted deployments. Claude can propose and sign transactions (1 of 2 required signatures), but you must approve with your wallet to execute. This ensures AI-assisted deployments require human authorization.

### How It Works

1. **I'll set up a 2-of-3 Safe** with you for secure deployments
2. **I'll generate my signing wallet** (Owner 3) using `cast wallet new`
3. **I'll guide you** to create the Safe at app.safe.global with:
   - Your mobile wallet (Owner 1) - for easy approval
   - Your desktop wallet (Owner 2) - for backup
   - My wallet (Owner 3) - for signing proposals
4. **I'll propose and sign** deployments (1/2 signatures)
5. **You approve** in Safe mobile app (2/2 signatures)
6. **I'll monitor** for execution and extract the contract address

> **SECURITY MODEL:** The 2-of-3 Safe gives Claude signing capability (1 of 2 required) but prevents autonomous execution. You maintain final approval authority - transactions cannot execute without your signature. This creates secure AI-human collaboration where Claude handles technical preparation and signing while you maintain authorization control.

### How I'll Set Up the Safe for You

When you request a deployment, I'll:

1. **Check for my existing wallet** in Foundry keystore (`claude-monad`)
2. **Check if you have a Safe** by asking for your Safe address
3. **If you don't have one**, I'll set it up:

   **Step A: Generate and import wallet to keystore**
   ```bash
   # Check if claude-monad exists
   if ! cast wallet list | grep -q "claude-monad"; then
     # Generate wallet
     WALLET_OUTPUT=$(cast wallet new)
     ADDRESS=$(echo "$WALLET_OUTPUT" | grep "Address:" | awk '{print $2}')
     PRIVATE_KEY=$(echo "$WALLET_OUTPUT" | grep "Private key:" | awk '{print $3}')

     # Generate and save password
     openssl rand -base64 32 > ~/.monad-keystore-password
     chmod 600 ~/.monad-keystore-password

     # Import to keystore
     cast wallet import claude-monad \
       --private-key "$PRIVATE_KEY" \
       --unsafe-password "$(cat ~/.monad-keystore-password)"

     # Show disclaimer (wallet address, encryption, security model)
     echo "✅ Created Claude's signing wallet: $ADDRESS"
   fi

   CLAUDE_ADDRESS=$(cast wallet address --account claude-monad --password-file ~/.monad-keystore-password)
   ```

   Claude will show a disclaimer explaining the wallet, encryption (`~/.foundry/keystores/claude-monad`), and security model (you control 2/3 owners).

   **Step B: I ask for your wallets**
   I'll ask: "Please provide your two wallet addresses:
   - Wallet 1 (recommended: Safe mobile app for easy approvals)
   - Wallet 2 (recommended: desktop/hardware wallet for backup)"

   **Step C: Fund wallet and deploy Safe**

   I'll automatically fund Claude's wallet from the faucet, then deploy the Safe with Forge:

   ```bash
   # Fund Claude's wallet from faucet
   FAUCET_RESPONSE=$(curl -s -X POST https://agents.devnads.com/v1/faucet \
     -H "Content-Type: application/json" \
     -d "{\"chainId\": 10143, \"address\": \"$CLAUDE_ADDRESS\"}")

   # Wait for funds (poll with `cast balance` until non-zero)
   while [ "$(cast balance $CLAUDE_ADDRESS --rpc-url https://testnet-rpc.monad.xyz)" = "0" ]; do
     sleep 2
   done

   # Deploy Safe with CREATE2 (standard SafeProxyFactory)
   OWNER_1=$OWNER_1 OWNER_2=$OWNER_2 OWNER_3=$CLAUDE_ADDRESS \
     forge script DeploySafeCREATE2.sol:DeploySafeCREATE2 \
       --account claude-monad \
       --password-file ~/.monad-keystore-password \
       --rpc-url https://testnet-rpc.monad.xyz \
       --broadcast

   # Extract Safe address
   SAFE_ADDRESS=$(forge script DeploySafeCREATE2.sol:DeploySafeCREATE2 --sig "run()" | grep "Safe deployed at:" | awk '{print $NF}')

   echo "✅ Safe deployed: $SAFE_ADDRESS"
   echo "🌐 https://app.safe.global/home?safe=monad-testnet:$SAFE_ADDRESS"
   ```

   **Step D: Proceed with deployment**
   - Prepare contract deployment bytecode
   - Save to file for Safe UI
   - Guide you through Safe transaction creation
   - Sign with your wallet (1/2), Claude signs (2/2)

### What I'll Handle for You

**First deployment:**
- ✅ Generate Claude's wallet → encrypted keystore (`claude-monad`)
- ✅ Auto-generate password → `~/.monad-keystore-password` (chmod 600)
- ✅ Fund wallet from faucet automatically
- ✅ Deploy Safe with DeploySafeCREATE2.sol (3 owners, 2/3 threshold)
- ✅ Prepare deployment bytecode → save to file
- ✅ Guide you through Safe UI transaction creation

**Subsequent deployments:**
- ✅ Use existing `claude-monad` keystore + password
- ✅ Ask for Safe address (or reuse from session)
- ✅ Prepare bytecode → guide through Safe UI
- ✅ Sign with your wallet (1/2), Claude signs (2/2)

**You provide:**
- Two wallet addresses (public, safe to share)
- Approval in Safe app for each deployment

**You never provide:**
- ❌ Your private key (critical security violation)
- ❌ Passwords (auto-generated)

**System requirements:**
- Foundry (forge, cast)

### Recovery: If Keystore Lost

If keystore is corrupted or password lost:

1. Delete old files: `rm ~/.foundry/keystores/claude-monad ~/.monad-keystore-password`
2. Generate new wallet → import to keystore
3. Update Safe: Remove old Owner 3, add new Owner 3 (keep your 2 wallets)

Your funds stay safe - you control 2/3 owners and can execute with just your wallets.

### ContractFactory: Required for Contract Deployments

**CRITICAL:** Safe wallets cannot directly CREATE contracts. When you send a transaction to `0x0000...0000`, it's a regular CALL, not a CREATE operation. To deploy contracts through Safe, you must use a factory contract.

**ContractFactory deployed on Monad Testnet:**
```
Address: 0x5f092BaFea57E05b8D4F88a1Ab57d10B43186F47
```

**Why it's needed:**
- Safe executes transactions via CALL opcode (not CREATE)
- Sending bytecode to `0x0000...0000` doesn't deploy anything
- Factory provides `deploySimple(bytes)` function that uses CREATE internally
- Safe calls the factory, factory creates the contract

**Factory interface:**
```solidity
contract ContractFactory {
    // Deploy with CREATE (simpler, non-deterministic address)
    function deploySimple(bytes memory bytecode) external returns (address);

    // Deploy with CREATE2 (deterministic address)
    function deploy(bytes memory bytecode, bytes32 salt) external returns (address);

    // Compute CREATE2 address before deploying
    function computeAddress(address deployer, bytes memory bytecode, bytes32 salt)
        external view returns (address);
}
```

**How to use:**
1. Prepare your contract deployment bytecode (e.g., `0x608060...`)
2. Encode factory call: `factory.deploySimple(bytecode)`
3. Safe calls factory with encoded data
4. Factory deploys contract and returns address

### Workflow

**IMPORTANT: This workflow uses Safe multisig for ALL deployments. Direct deployment with `--private-key` or `--broadcast` is NOT allowed.**

**DEPLOYMENT APPROACH:**
1. ✅ Deploy Safe with DeploySafeCREATE2.sol (CREATE2 via SafeProxyFactory)
2. ✅ Prepare deployment bytecode and encode factory call
3. ✅ Post transaction to Transaction Service API with Claude's EIP-712 signature
4. ✅ User sees transaction in Safe UI queue, signs (2/2), executes

**Why this works:**
- ✅ Best UX: Transaction appears in user's Safe UI automatically
- ✅ No manual bytecode copying needed
- ✅ User just signs and executes in familiar UI
- ✅ Transaction Service API works perfectly on Monad with EIP-712 signatures
- ✅ Tested and confirmed working (returns 201 Created)

#### Step 1: Prepare Deployment Transaction

Use `forge script` with `--sender` set to the Safe address (NOT with --private-key):

```bash
forge script script/Deploy.s.sol:DeployScript \
  --rpc-url https://testnet-rpc.monad.xyz \
  --sender <SAFE_ADDRESS>
```

This simulates the deployment from the Safe wallet and generates transaction data without broadcasting. The `--sender` flag tells Foundry to prepare the transaction as if it's coming from the Safe address.

#### Step 2: Extract Deployment Bytecode

Extract the deployment bytecode from the forge script output:

```bash
DEPLOYMENT_BYTECODE=$(jq -r '.transactions[0].transaction.input' \
  broadcast/Deploy.s.sol/10143/dry-run/run-latest.json)
```

Ensure the Safe address is checksummed:

```bash
SAFE_ADDRESS=$(cast to-check-sum-address "<SAFE_ADDRESS>")
```

Extract Claude's private key from encrypted keystore:

```bash
# Keystore and password file locations
KEYSTORE_PATH="$HOME/.foundry/keystores/claude-monad"
PASSWORD_FILE="$HOME/.monad-keystore-password"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔐 Claude signing the deployment proposal (1/2 signatures)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check password file exists
if [ ! -f "$PASSWORD_FILE" ]; then
  echo "❌ Error: Password file not found at $PASSWORD_FILE"
  echo "Run keystore setup again to regenerate"
  exit 1
fi

# Read password from file
KEYSTORE_PASSWORD=$(cat "$PASSWORD_FILE")

# Get private key using cast wallet address with password (doesn't expose private key)
# We'll use the password-file parameter in Safe SDK instead
# For verification, just check keystore is accessible
if ! cast wallet address --account claude-monad --password-file "$PASSWORD_FILE" > /dev/null 2>&1; then
  echo "❌ Error: Failed to access keystore. Keystore may be corrupted."
  exit 1
fi

echo "✅ Keystore accessible"
```

> **SECURITY:** The password is stored at `~/.monad-keystore-password` with chmod 600 (user-only access). The keystore is encrypted on disk. The 2-of-3 multisig provides defense in depth - even if the password file is compromised, an attacker needs 2/3 signatures to execute transactions.

#### Step 3: Execute Transaction Through Safe

Use the Transaction Service API with EIP-712 signatures for the best user experience:

**Transaction appears in Safe UI automatically for user to sign and execute**

⚠️ **CRITICAL:** Must use EIP-712 signatures (not raw signatures from `cast wallet sign`). The Transaction Service API works perfectly on Monad when using proper EIP-712 format.

**Create proposal script:**

```bash
# Install dependencies if needed
npm install --no-save ethers@^6.0.0

# Create propose.mjs
cat > propose.mjs << 'EOF'
import { ethers } from 'ethers';
import fs from 'fs';

const SAFE_ADDRESS = process.env.SAFE_ADDRESS;
const FACTORY_ADDRESS = '0x5f092BaFea57E05b8D4F88a1Ab57d10B43186F47';
const RPC_URL = 'https://testnet-rpc.monad.xyz';
const TX_SERVICE_URL = 'https://api.safe.global/tx-service/monad-testnet/api/v1';
const CHAIN_ID = 10143;

async function main() {
  // Load Claude's wallet from keystore
  const keystorePath = `${process.env.HOME}/.foundry/keystores/claude-monad`;
  const passwordPath = `${process.env.HOME}/.monad-keystore-password`;
  const keystoreJson = fs.readFileSync(keystorePath, 'utf8');
  const password = fs.readFileSync(passwordPath, 'utf8').trim();
  const wallet = await ethers.Wallet.fromEncryptedJson(keystoreJson, password);

  console.log(`✅ Claude's address: ${wallet.address}`);

  // Connect to provider and get Safe nonce
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const safeAbi = ['function nonce() view returns (uint256)'];
  const safeContract = new ethers.Contract(SAFE_ADDRESS, safeAbi, provider);
  const nonce = await safeContract.nonce();

  console.log(`✅ Safe nonce: ${nonce}`);

  // Get deployment bytecode from environment
  const deploymentBytecode = process.env.DEPLOYMENT_BYTECODE;

  // Encode factory call: factory.deploySimple(deploymentBytecode)
  const factoryInterface = new ethers.Interface([
    'function deploySimple(bytes memory bytecode) external returns (address)'
  ]);
  const factoryCallData = factoryInterface.encodeFunctionData('deploySimple', [deploymentBytecode]);

  // Prepare transaction data - Safe calls ContractFactory
  const txData = {
    to: FACTORY_ADDRESS,
    value: '0',
    data: factoryCallData,
    operation: 0,
    safeTxGas: '0',
    baseGas: '0',
    gasPrice: '0',
    gasToken: '0x0000000000000000000000000000000000000000',
    refundReceiver: '0x0000000000000000000000000000000000000000',
    nonce: nonce.toString()
  };

  // EIP-712 Domain for Safe on Monad
  const domain = {
    chainId: CHAIN_ID,
    verifyingContract: SAFE_ADDRESS
  };

  // EIP-712 Types for Safe transaction
  const types = {
    SafeTx: [
      { name: 'to', type: 'address' },
      { name: 'value', type: 'uint256' },
      { name: 'data', type: 'bytes' },
      { name: 'operation', type: 'uint8' },
      { name: 'safeTxGas', type: 'uint256' },
      { name: 'baseGas', type: 'uint256' },
      { name: 'gasPrice', type: 'uint256' },
      { name: 'gasToken', type: 'address' },
      { name: 'refundReceiver', type: 'address' },
      { name: 'nonce', type: 'uint256' }
    ]
  };

  // Sign with EIP-712 (CRITICAL: Not raw signature!)
  console.log('✍️  Signing with EIP-712...');
  const connectedWallet = wallet.connect(provider);
  const signature = await connectedWallet.signTypedData(domain, types, txData);

  // Calculate transaction hash
  const txHash = ethers.TypedDataEncoder.hash(domain, types, txData);
  console.log(`✅ Transaction hash: ${txHash}`);
  console.log(`✅ Claude signed (1/2)`);

  // POST to Transaction Service API
  console.log('📤 Posting to Transaction Service API...');
  const response = await fetch(`${TX_SERVICE_URL}/safes/${SAFE_ADDRESS}/multisig-transactions/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ...txData,
      contractTransactionHash: txHash,
      sender: wallet.address,
      signature: signature
    })
  });

  if (response.ok) {
    console.log('✅ Transaction proposed successfully!');
    console.log('');
    console.log('🎉 Transaction appears in Safe UI queue!');
    console.log('');
    console.log('User can now:');
    console.log(`1. Open: https://app.safe.global/transactions/queue?safe=monad-testnet:${SAFE_ADDRESS}`);
    console.log('2. See pending transaction (Claude already signed 1/2)');
    console.log('3. Sign with their wallet (2/2)');
    console.log('4. Execute to deploy');
  } else {
    const error = await response.text();
    console.error(`❌ API Error: ${response.status}`);
    console.error(error);
    process.exit(1);
  }
}

main();
EOF

# Run proposal
SAFE_ADDRESS=$SAFE_ADDRESS \
  DEPLOYMENT_BYTECODE=$(jq -r '.bytecode.object' out/Contract.sol/Contract.json) \
  node propose.mjs
```

**Result:**
```
✅ Claude's address: 0x937d...
✅ Safe nonce: 0
✍️  Signing with EIP-712...
✅ Transaction hash: 0x0560...
✅ Claude signed (1/2)
📤 Posting to Transaction Service API...
✅ Transaction proposed successfully!

🎉 Transaction appears in Safe UI queue!

User can now:
1. Open: https://app.safe.global/transactions/queue?safe=monad-testnet:0x...
2. See pending transaction (Claude already signed 1/2)
3. Sign with their wallet (2/2)
4. Execute to deploy
```

#### Step 4: Monitor and Get Contract Address

After user executes the transaction in Safe UI, get the contract address:

```bash
# User tells you the transaction hash after execution
cast receipt <TRANSACTION_HASH> --rpc-url https://testnet-rpc.monad.xyz
```

Look for the `contractAddress` field in the receipt.

---

## ✅ Safe Multisig on Monad - Working Solution

**Status**: Safe v1.4.1 WORKS PERFECTLY on Monad with full CREATE2 support (as of Jan 26, 2026)

### ✅ CREATE2 Works on Monad

**Previous incorrect claim:** "SafeProxyFactory (CREATE2) fails on Monad"
**Reality:** CREATE2 works flawlessly on Monad's Prague EVM implementation.

**Use the standard SafeProxyFactory deployment method:**
- ✅ CREATE2 fully supported
- ✅ Transaction Service API functional (correct endpoint)
- ✅ Safe UI integration works
- ✅ Safes are properly indexed

### Official Safe Contract Addresses (Monad Testnet)

```solidity
Safe Singleton (v1.4.1):  0x3E5c63644E683549055b9Be8653de26E0B4CD36E
SafeProxyFactory:         0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2
FallbackHandler:          0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4
ContractFactory:          0x5f092BaFea57E05b8D4F88a1Ab57d10B43186F47  (for contract deployments)
```

All contracts verified and functional. Chain ID: 10143

### How It Works

1. **Deploy Safe with CREATE2** (SafeProxyFactory) - standard approach
2. **Safe appears in Transaction Service** automatically
3. **Prepare contract deployment bytecode**
4. **Use Safe web UI** to create and sign transactions
5. **Full 2-of-3 multisig functionality** - all features work

### Step 1: Deploy Safe with CREATE2 (Recommended)

Create `DeploySafeCREATE2.sol` in your project:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "forge-std/Script.sol";

interface ISafe {
    function setup(
        address[] calldata _owners,
        uint256 _threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external;
}

interface ISafeProxyFactory {
    function createProxyWithNonce(
        address _singleton,
        bytes memory initializer,
        uint256 saltNonce
    ) external returns (address);
}

contract DeploySafeCREATE2 is Script {
    address constant SAFE_SINGLETON = 0x3E5c63644E683549055b9Be8653de26E0B4CD36E;
    address constant SAFE_PROXY_FACTORY = 0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2;
    address constant FALLBACK_HANDLER = 0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4;

    function run() external returns (address) {
        address owner1 = vm.envAddress("OWNER_1");
        address owner2 = vm.envAddress("OWNER_2");
        address owner3 = vm.envAddress("OWNER_3");

        address[] memory owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;

        // Prepare initializer data for Safe setup
        bytes memory initializer = abi.encodeWithSelector(
            ISafe.setup.selector,
            owners,              // _owners
            2,                   // _threshold (2 of 3)
            address(0),          // to
            "",                  // data
            FALLBACK_HANDLER,    // fallbackHandler
            address(0),          // paymentToken
            0,                   // payment
            payable(0)           // paymentReceiver
        );

        vm.startBroadcast();

        // Deploy Safe using CREATE2 via SafeProxyFactory
        address proxy = ISafeProxyFactory(SAFE_PROXY_FACTORY).createProxyWithNonce(
            SAFE_SINGLETON,
            initializer,
            block.timestamp  // Use timestamp as salt for unique address
        );

        console.log("Safe deployed at:", proxy);
        console.log("Access: https://app.safe.global/home?safe=monad-testnet:", proxy);
        console.log("Transaction Service: https://api.safe.global/tx-service/monad-testnet/api/v1/safes/", proxy);

        vm.stopBroadcast();
        return proxy;
    }
}
```

**Deploy with:**
```bash
# Set owner addresses
export OWNER_1="0xUserWallet1"
export OWNER_2="0xUserWallet2"
export OWNER_3="$(cast wallet address --account claude-monad --password-file ~/.monad-keystore-password)"

# Deploy Safe using CREATE2
forge script DeploySafeCREATE2.sol:DeploySafeCREATE2 \
  --account claude-monad \
  --password-file ~/.monad-keystore-password \
  --rpc-url https://testnet-rpc.monad.xyz \
  --broadcast

# Verify Safe is indexed by Transaction Service
SAFE_ADDRESS="<address from output>"
curl "https://api.safe.global/tx-service/monad-testnet/api/v1/safes/${SAFE_ADDRESS}/" | jq .
```

**Why CREATE2 is preferred:**
- ✅ Standard Safe deployment method
- ✅ Automatically indexed by Transaction Service
- ✅ Appears in Safe UI without manual URL entry
- ✅ Deterministic addresses (can predict before deployment)
- ✅ Full ecosystem compatibility
```

### Step 2: Prepare Contract Deployment Bytecode

For any contract you want to deploy through the Safe:

```bash
# Build your contract first
forge build

# Extract deployment bytecode
BYTECODE=$(jq -r '.bytecode.object' out/YourContract.sol/YourContract.json)

# Ensure it starts with 0x
if [[ ! "$BYTECODE" =~ ^0x ]]; then
  BYTECODE="0x$BYTECODE"
fi

# ContractFactory address on Monad Testnet
FACTORY_ADDRESS="0x5f092BaFea57E05b8D4F88a1Ab57d10B43186F47"

# Encode factory call: factory.deploySimple(bytecode)
# This is what Safe will actually call
FACTORY_CALL=$(cast calldata "deploySimple(bytes)" "$BYTECODE")

# Save to file for Safe UI
echo "$FACTORY_CALL" > factory-call.txt
echo "✅ Factory call data saved (${#FACTORY_CALL} characters)"
echo "   Safe will call: ContractFactory.deploySimple()"
```

### Step 3: Deploy Through Safe Web UI

**Give user the Safe URL:**
```
https://app.safe.global/home?safe=monad-testnet:{SAFE_ADDRESS}
```

**Guide user through UI (step-by-step):**

1. **Open Safe** - Click the Safe URL
2. **New Transaction** - Click "New transaction" button
3. **Transaction Builder** - Select "Transaction Builder"
4. **Enable Custom data** - Toggle "Custom data" at the top (should turn green)
5. **Enter Address or ENS Name:**
   - Enter: `0x5f092BaFea57E05b8D4F88a1Ab57d10B43186F47` (ContractFactory)
6. **Enter ABI** - Leave empty (we're using custom data)
7. **Transaction information:**
   - **To Address**: Will auto-populate with the factory address above
   - **MON value**: Enter `0` (no ETH/MON being sent)
   - **Data (Hex encoded)**: Paste factory call data from `factory-call.txt`
     - **IMPORTANT**: Data must start with `0x` (if your file doesn't have it, add it)
     - Example: `0x7cb647590000000000000000000000000000...` (calls deploySimple())
8. **Add new transaction** - Click "Add new transaction" button
9. **Review and sign** - Review the transaction details, then sign with your MetaMask
10. **Execute** - After collecting 2/2 signatures, execute to deploy contract

**Note on signatures:**
- The Safe is 2-of-3, so you need 2 signatures
- You provide 1 signature (your wallet) when creating the transaction
- For the 2nd signature, you'll need another owner to sign (either your other wallet or have Claude sign)
- Once 2/2 signatures collected, the "Execute" button becomes available

### What Works & Limitations

| Feature | Status |
|---------|--------|
| CREATE2 deployment (SafeProxyFactory) | ✅ Works perfectly |
| Transaction Service API (querying) | ✅ Works perfectly |
| Transaction Service API (proposal with EIP-712) | ✅ Works perfectly |
| Safe appears in Safe UI automatically | ✅ Works (CREATE2 indexed) |
| Create transactions in UI | ✅ Works |
| Sign with MetaMask in UI | ✅ Works |
| 2-of-3 multisig execution | ✅ Works |
| On-chain contract functionality | ✅ Works perfectly |
| Raw signatures with `cast wallet sign` | ❌ Wrong format (use EIP-712) |

**Key Points:**
- ✅ **CREATE2 works perfectly** on Monad (Prague EVM)
- ✅ Transaction Service API fully functional at: `https://api.safe.global/tx-service/monad-testnet/`
- ✅ Safes deployed with CREATE2 are automatically indexed
- ✅ **Programmatic API proposals work with EIP-712 signatures** (use `wallet.signTypedData()`)
- ❌ Raw signatures from `cast wallet sign` don't work (wrong format)
- ✅ All Safe features work as expected

**After deployment, ALWAYS tell the user:**
> "Deployment successful! Contract deployed from Safe multisig at [CONTRACT_ADDRESS]. The 2-of-3 setup ensures collaborative control - deployments require 2 signatures. View on explorer: [EXPLORER_URL]"

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

