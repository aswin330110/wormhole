# Vulnerability #5: Guardian Can Silently Overwrite Validator Registration

## Severity: MEDIUM

## Location
- File: `wormchain/x/wormhole/keeper/msg_server_register_account_as_guardian.go`
- Lines: 19-93 (RegisterAccountAsGuardian function)
- File: `wormchain/x/wormhole/keeper/guardian_validator.go`
- Lines: 10-16 (SetGuardianValidator function)

## Description
The guardian validator registration mechanism allows a guardian to re-register with a different validator address, silently overwriting their previous registration. There is no check to prevent re-registration, no event emitted for overwrites, and the old validator is orphaned without notification. This can lead to accidental or malicious validator displacement.

## Vulnerable Code

### RegisterAccountAsGuardian (msg_server_register_account_as_guardian.go)
```go
func (k msgServer) RegisterAccountAsGuardian(goCtx context.Context, msg *types.MsgRegisterAccountAsGuardian) (*types.MsgRegisterAccountAsGuardianResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	signer, err := sdk.AccAddressFromBech32(msg.Signer)
	if err != nil {
		return nil, err
	}

	// recover guardian key from signature
	signerHash := crypto.Keccak256Hash(wormholesdk.SignedWormchainAddressPrefix, signer)
	guardianKey, err := crypto.Ecrecover(signerHash.Bytes(), msg.Signature)
	// ... key derivation ...

	guardianKeyAddr := common.BytesToAddress(crypto.Keccak256(guardianKey[1:])[12:])

	// Check if guardian key is in latest guardian set
	latestGuardianSetIndex := k.Keeper.GetLatestGuardianSetIndex(ctx)
	latestGuardianSet, guardianSetFound := k.Keeper.GetGuardianSet(ctx, latestGuardianSetIndex)
	// ...

	if !latestGuardianSet.ContainsKey(guardianKeyAddr) {
		return nil, types.ErrGuardianNotFound
	}

	// ❌ ONLY checks if VALIDATOR ADDRESS was already registered
	// Does NOT check if GUARDIAN KEY was already registered!
	for _, gv := range k.GetAllGuardianValidator(ctx) {
		if bytes.Equal(gv.ValidatorAddr, signer) {
			return nil, types.ErrSignerAlreadyRegistered
		}
	}

	// ❌ OVERWRITES existing registration if guardian re-registers
	// No warning, no event for overwrite
	k.Keeper.SetGuardianValidator(ctx, types.GuardianValidator{
		GuardianKey:   guardianKeyAddr.Bytes(),
		ValidatorAddr: signer,
	})

	// Event emitted, but same event for new registration and overwrite
	err = ctx.EventManager().EmitTypedEvent(&types.EventGuardianRegistered{
		GuardianKey:  guardianKeyAddr.Bytes(),
		ValidatorKey: signer,
	})
	// ...
}
```

### SetGuardianValidator Uses Guardian Key as Primary Key
```go
func (k Keeper) SetGuardianValidator(ctx sdk.Context, guardianValidator types.GuardianValidator) {
	store := prefix.NewStore(ctx.KVStore(k.storeKey), types.KeyPrefix(types.GuardianValidatorKeyPrefix))
	b := k.cdc.MustMarshal(&guardianValidator)
	store.Set(types.GuardianValidatorKey(
		guardianValidator.GuardianKey,  // ← Uses guardian key as store key
	), b)
}
```

## Attack Scenarios

### Scenario 1: Accidental Validator Orphaning
1. **Initial State**: Guardian G registers with validator V1
   - Store: `guardianKey(G) → ValidatorAddr(V1)`
2. **Guardian Loses Access**: Guardian G loses access to validator V1 (key lost, node down, etc.)
3. **Re-registration**: Guardian G re-registers with new validator V2
   - Store: `guardianKey(G) → ValidatorAddr(V2)` (OVERWRITES V1)
4. **Result**:
   - Validator V1 is now orphaned (no longer associated with guardian G)
   - V1 operator doesn't receive notification
   - V1 loses guardian voting power
   - Only one validator can be active per guardian at a time

### Scenario 2: Malicious Re-registration After Key Compromise
1. **Initial State**: Guardian G legitimately registered with validator V1
2. **Key Compromise**: Attacker obtains guardian G's private key
3. **Malicious Re-registration**:
   - Attacker creates new validator V_malicious
   - Attacker re-registers guardian G with V_malicious using compromised key
   - Store: `guardianKey(G) → ValidatorAddr(V_malicious)` (OVERWRITES V1)
4. **Impact**:
   - Legitimate validator V1 loses guardian association
   - Malicious validator V_malicious now represents guardian G
   - Original validator operator may not notice immediately
   - Attacker can perform actions as guardian G through V_malicious

### Scenario 3: Validator Takeover via Social Engineering
1. **Setup**: Attacker convinces guardian that they need to "update" their registration
2. **Execution**: Guardian signs registration for attacker's validator address
3. **Result**: Attacker's validator becomes the official validator for that guardian
4. **Impact**: Original validator is displaced without recourse

## Why This Happens

### Root Cause Analysis
1. **Guardian Key as Primary Key**: Storage uses guardian key as the unique identifier
   ```go
   store.Set(types.GuardianValidatorKey(guardianValidator.GuardianKey), b)
   ```
   - This means only ONE validator per guardian key can exist
   - New registration OVERWRITES old registration

2. **Check Only Validates Validator Address**:
   ```go
   for _, gv := range k.GetAllGuardianValidator(ctx) {
       if bytes.Equal(gv.ValidatorAddr, signer) {  // Checks validator, not guardian
           return nil, types.ErrSignerAlreadyRegistered
       }
   }
   ```
   - This prevents one validator from being associated with multiple guardians
   - But does NOT prevent one guardian from re-registering with a new validator

3. **No Overwrite Detection**:
   - No check to see if guardian key already has a registration
   - Same event emitted for new registration and overwrite
   - No way to distinguish between first registration and re-registration

## Impact

### Operational Impact
- **Validator Displacement**: Legitimate validators can be orphaned
- **Loss of Voting Power**: Displaced validators lose guardian-associated voting rights
- **Silent Failures**: No notification to affected parties
- **Difficult Recovery**: Requires guardian to re-register original validator

### Security Impact
- **Medium Severity**: Requires guardian key compromise OR guardian cooperation
- **Limited Scope**: Only affects specific guardian-validator mapping
- **Reversible**: Guardian can re-register back to original validator
- **Social Engineering Risk**: Guardians may be tricked into re-registering

## Evidence of Design Intent

The check at lines 65-69 suggests this behavior might be intentional to allow guardians to change validators:

```go
// Check if the tx signer was already registered as a guardian validator.
for _, gv := range k.GetAllGuardianValidator(ctx) {
	if bytes.Equal(gv.ValidatorAddr, signer) {
		return nil, types.ErrSignerAlreadyRegistered
	}
}
```

However, the lack of:
1. Explicit overwrite event
2. Old validator notification
3. Documentation of this behavior

Suggests this may be an oversight rather than intentional design.

## Remediation

### Option 1: Prevent Re-registration (Strict)
```go
// Check if guardian key is already registered
existingValidator, found := k.Keeper.GetGuardianValidator(ctx, guardianKeyAddr.Bytes())
if found {
	return nil, types.ErrGuardianAlreadyRegistered
}

// Check if validator address is already registered
for _, gv := range k.GetAllGuardianValidator(ctx) {
	if bytes.Equal(gv.ValidatorAddr, signer) {
		return nil, types.ErrSignerAlreadyRegistered
	}
}

// Proceed with registration...
```

### Option 2: Allow Re-registration with Warnings (Flexible)
```go
// Check if guardian key is already registered
existingValidator, found := k.Keeper.GetGuardianValidator(ctx, guardianKeyAddr.Bytes())

if found {
	// Emit event that registration is being overwritten
	err := ctx.EventManager().EmitTypedEvent(&types.EventGuardianValidatorOverwritten{
		GuardianKey:       guardianKeyAddr.Bytes(),
		OldValidatorAddr:  existingValidator.ValidatorAddr,
		NewValidatorAddr:  signer,
	})
	if err != nil {
		return nil, err
	}
}

// Check if validator address is already registered
for _, gv := range k.GetAllGuardianValidator(ctx) {
	if bytes.Equal(gv.ValidatorAddr, signer) {
		return nil, types.ErrSignerAlreadyRegistered
	}
}

// Proceed with registration...
k.Keeper.SetGuardianValidator(ctx, types.GuardianValidator{
	GuardianKey:   guardianKeyAddr.Bytes(),
	ValidatorAddr: signer,
})
```

### Option 3: Require Explicit Unregister (Safest)
```go
// Add new message type: MsgUnregisterGuardianValidator

// In RegisterAccountAsGuardian:
existingValidator, found := k.Keeper.GetGuardianValidator(ctx, guardianKeyAddr.Bytes())
if found {
	return nil, types.ErrGuardianMustUnregisterFirst
}

// Require explicit unregister before re-registering
```

## Recommended Fix

**Use Option 2** (Allow re-registration with clear events):
1. Add event type for overwrite scenarios
2. Emit different events for new registration vs. overwrite
3. Add documentation explaining re-registration behavior
4. Consider adding query endpoint to check current registration
5. Add timestamp to guardian validator mapping for audit trail

### Additional Recommendations
1. **Add Grace Period**: Allow old validator to remain valid for N blocks after re-registration
2. **Add Validator Notification**: Create mechanism to notify old validator of displacement
3. **Add Audit Log**: Log all registration changes with timestamps
4. **Document Behavior**: Clearly document that re-registration overwrites

## Verification Status
✅ **VERIFIED** - Behavior confirmed through:
- Code analysis showing guardian key as primary key
- Analysis of check logic (only validates validator address)
- Trace through SetGuardianValidator showing overwrite behavior
- Lack of overwrite-specific events or notifications
- Design pattern analysis suggesting this may be unintended
