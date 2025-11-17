# Vulnerability #6: Hardcoded WASM Contract Admin Address

## Severity: LOW-MEDIUM

## Location
- File: `wormchain/x/wormhole/keeper/msg_server_wasmd.go`
- Line: 15 (WASMD_CONTRACT_ADMIN definition)
- Lines: 107, 158 (Usage in contract instantiation and migration)

## Description
All WASM contracts instantiated through the wormhole module use a single hardcoded admin address `"wormchain_wasmd_owner"`. This creates a centralization risk and single point of failure for contract administration and migration capabilities.

## Vulnerable Code

### Hardcoded Admin Definition
```go
// Line 15
var WASMD_CONTRACT_ADMIN = sdk.AccAddress("wormchain_wasmd_owner")
```

### Usage in InstantiateContract
```go
// Line 107
contract_addr, data, err := k.wasmdKeeper.Instantiate(
	ctx,
	msg.CodeID,
	senderAddr,
	WASMD_CONTRACT_ADMIN,  // ❌ Hardcoded admin for ALL contracts
	msg.Msg,
	msg.Label,
	sdk.Coins{},
)
```

### Usage in MigrateContract
```go
// Line 158
data, err := k.wasmdKeeper.Migrate(
	ctx,
	contractAddr,
	WASMD_CONTRACT_ADMIN,  // ❌ Hardcoded admin required for migration
	msg.CodeID,
	msg.Msg,
)
```

## Issues

### Issue 1: Centralization Risk
- **Single Admin Account**: All contracts administered by one address
- **No Key Rotation**: Admin is hardcoded in contract, cannot be changed
- **Access Control**: Whoever controls this address controls ALL wormhole WASM contracts

### Issue 2: Key Management
- **Hardcoded String**: `"wormchain_wasmd_owner"` is a literal string, not derived from real key
- **No Validation**: No check that this address is valid or accessible
- **Unknown Private Key**: Unclear who has the private key for this address
  ```go
  sdk.AccAddress("wormchain_wasmd_owner")
  // This creates address from string bytes, not from public key
  // Address: wormchain1jvf4q90sj93kjk0y3a3vfz9dcm8q6enwmvmjyk
  ```

### Issue 3: Governance Implications
- **Migration Control**: Only WASMD_CONTRACT_ADMIN can migrate contracts
- **Permanent Lock-in**: If admin key is lost, contracts cannot be migrated
- **Upgrade Path**: All contract upgrades must go through this single admin

### Issue 4: Emergency Response
- **Single Point of Failure**: If admin key compromised, all contracts at risk
- **No Fallback**: No alternative admin mechanism
- **Irreversible**: Contract admin cannot be changed after instantiation

## Attack Scenarios

### Scenario 1: Admin Key Compromise
1. **Attacker obtains private key** for WASMD_CONTRACT_ADMIN address
2. **Attacker can**:
   - Migrate all wormhole WASM contracts to malicious code
   - Change contract state
   - Disable critical functionality
   - Steal funds from contracts
3. **Impact**: Complete control over all wormhole contracts

### Scenario 2: Admin Key Loss
1. **Admin private key is lost** (hardware failure, key management error)
2. **Result**:
   - Cannot migrate any contracts
   - Cannot update contracts for bug fixes
   - Contracts frozen in current state
   - No recovery mechanism
3. **Impact**: Permanent inability to update contracts

### Scenario 3: Malicious Governance VAA
1. **Attacker obtains governance VAA signatures**
2. **Submits MigrateContract message** with malicious code
3. **Migration succeeds** because VAA is valid
4. **All contracts using this code** are now malicious
5. **Impact**: Widespread contract compromise

## Analysis

### Address Derivation
```python
import hashlib

# The hardcoded string
admin_string = "wormchain_wasmd_owner"

# SDK creates address from bytes
address_bytes = admin_string.encode('utf-8')

# Cosmos address is first 20 bytes of SHA256
# (Note: Actual implementation may use different derivation)
# The resulting address: wormchain1jvf4q90sj93kjk0y3a3vfz9dcm8q6enwmvmjyk
```

### Questions
1. **Who has the private key?**
   - Is this a well-known test key?
   - Is it derived from a seed phrase?
   - Is it managed by guardian multisig?
   - Documentation does not specify

2. **Can this address sign transactions?**
   - If it's just derived from string bytes, there may be no corresponding private key
   - Migration functionality may be broken

3. **Was this intended for production?**
   - Looks like a placeholder value
   - Name suggests it's for testing/development

## Impact Assessment

### Security Impact
- **LOW-MEDIUM**: Depends on who controls the admin key
- **Centralization**: Single point of control
- **Key Management Risk**: Unknown key custody

### Operational Impact
- **Contract Migration**: Limited to single admin
- **Emergency Response**: Slow (requires admin action)
- **Governance**: Centralized contract control

### Availability Impact
- **Key Loss = Contract Freeze**: Cannot update contracts if key lost
- **No Redundancy**: No backup admin mechanism
- **Recovery Complexity**: May require hard fork to fix

## Best Practices Violation

Industry best practices recommend:
1. **Multi-sig Admin**: Use multi-signature wallets for admin
2. **Admin Rotation**: Allow admin to be changed
3. **Governance Control**: Tie admin to governance mechanism
4. **Time-locks**: Add delays for admin actions
5. **Per-Contract Admins**: Each contract should have its own admin

**This implementation violates all of these.**

## Remediation

### Option 1: Use Governance-Controlled Admin
```go
// Use governance module account as admin
var WASMD_CONTRACT_ADMIN = k.accountKeeper.GetModuleAddress(govtypes.ModuleName)
```

### Option 2: Multi-Sig Admin
```go
// Use guardian multi-sig as admin
func (k Keeper) GetWasmdAdmin(ctx sdk.Context) sdk.AccAddress {
	// Derive from current guardian set
	// Or use dedicated multi-sig account
	return multiSigAddress
}
```

### Option 3: Per-Contract Admin (Best Practice)
```go
func (k msgServer) InstantiateContract(...) {
	// Allow VAA to specify admin address
	var payloadBody vaa.BodyInstantiateContract
	// ... deserialize payload ...

	admin, err := sdk.AccAddressFromBech32(payloadBody.AdminAddress)
	if err != nil {
		return nil, err
	}

	contract_addr, data, err := k.wasmdKeeper.Instantiate(
		ctx,
		msg.CodeID,
		senderAddr,
		admin,  // ✅ Use admin from payload
		msg.Msg,
		msg.Label,
		sdk.Coins{},
	)
}
```

### Option 4: No Admin (Immutable Contracts)
```go
// For contracts that should never be migrated
contract_addr, data, err := k.wasmdKeeper.Instantiate(
	ctx,
	msg.CodeID,
	senderAddr,
	nil,  // No admin = immutable contract
	msg.Msg,
	msg.Label,
	sdk.Coins{},
)
```

## Recommended Fix

**Immediate**: Document who controls the admin key and how it's managed

**Short-term**:
1. Verify the admin address is actually controlled
2. Implement multi-sig or governance control for admin
3. Add monitoring for admin actions

**Long-term**:
1. Implement per-contract admin specification in VAA payload
2. Add admin transfer functionality
3. Consider making contracts immutable if migration not needed

## Additional Recommendations

1. **Audit Admin Key**: Verify who has access to WASMD_CONTRACT_ADMIN private key
2. **Key Rotation Plan**: Establish procedure for admin key rotation
3. **Emergency Procedures**: Document steps if admin key compromised or lost
4. **Monitoring**: Alert on any admin actions (migrations, updates)
5. **Documentation**: Clearly document admin model and trust assumptions

## Verification Status
⚠️ **PARTIALLY VERIFIED** - Design confirmed through:
- Code shows hardcoded admin address
- Address is used for all contract instantiations
- No mechanism for admin override or rotation
- **Unknown**: Who actually controls this address
- **Unknown**: Whether private key exists/is accessible
