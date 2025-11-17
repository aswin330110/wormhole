# Vulnerability #1: Unchecked Deserialization Errors in Gateway Governance VAA Handler

## Severity: HIGH

## Location
- File: `wormchain/x/wormhole/keeper/msg_server_execute_gateway_governance_vaa.go`
- Lines: 66, 88, 113
- File: `wormchain/x/wormhole/keeper/msg_server_wasm_instantiate_allowlist.go`
- Line: 60

## Description
Multiple governance VAA message handlers call `Deserialize()` methods but fail to check the returned error. This allows malformed VAA payloads to be processed with default/zero values, potentially causing:

1. **Arbitrary upgrade scheduling** with empty name or zero height
2. **Invalid contract addresses** being set as IBC composability middleware
3. **Zero values for slashing parameters** that could disable slashing entirely
4. **Invalid WASM allowlist entries** with zero values

## Vulnerable Code

### scheduleUpgrade (Line 66)
```go
func (k msgServer) scheduleUpgrade(
	ctx sdk.Context,
	payload []byte,
) (*types.EmptyResponse, error) {
	// Deserialize payload to get the name and height for the upgrade plan
	var payloadBody vaa.BodyGatewayScheduleUpgrade
	payloadBody.Deserialize(payload)  // ❌ ERROR NOT CHECKED

	plan := upgradetypes.Plan{
		Name:   payloadBody.Name,    // Could be empty string if deserialization fails
		Height: int64(payloadBody.Height),  // Could be 0 if deserialization fails
	}
	k.upgradeKeeper.ScheduleUpgrade(ctx, plan)

	return &types.EmptyResponse{}, nil
}
```

### setIbcComposabilityMwContract (Line 88)
```go
func (k msgServer) setIbcComposabilityMwContract(
	ctx sdk.Context,
	payload []byte,
) (*types.EmptyResponse, error) {
	var payloadBody vaa.BodyGatewayIbcComposabilityMwContract
	payloadBody.Deserialize(payload)  // ❌ ERROR NOT CHECKED

	// convert bytes to bech32 address
	contractAddr, err := sdk.Bech32ifyAddressBytes(
		sdk.GetConfig().GetBech32AccountAddrPrefix(),
		payloadBody.ContractAddr[:],  // Could be zero bytes if deserialization fails
	)
	// ...
}
```

### setSlashingParams (Line 113)
```go
func (k msgServer) setSlashingParams(
	ctx sdk.Context,
	payload []byte,
) (*types.EmptyResponse, error) {
	var payloadBody vaa.BodyGatewaySlashingParamsUpdate
	payloadBody.Deserialize(payload)  // ❌ ERROR NOT CHECKED

	// Update slashing params
	params := slashingtypes.NewParams(
		int64(payloadBody.SignedBlocksWindow),      // Could be 0
		sdk.NewDecWithPrec(int64(payloadBody.MinSignedPerWindow), 18),  // Could be 0
		time.Duration(int64(payloadBody.DowntimeJailDuration)),  // Could be 0
		sdk.NewDecWithPrec(int64(payloadBody.SlashFractionDoubleSign), 18),  // Could be 0
		sdk.NewDecWithPrec(int64(payloadBody.SlashFractionDowntime), 18),  // Could be 0
	)
	k.slashingKeeper.SetParams(ctx, params)  // Sets potentially all-zero slashing params!
}
```

## Attack Scenario

### Scenario 1: Disable Slashing via Malformed Payload
1. Attacker obtains a valid governance VAA signature for `ActionSlashingParamsUpdate`
2. VAA includes a malformed payload (wrong length or format)
3. `Deserialize()` fails and returns error, but error is ignored
4. `payloadBody` retains zero values for all fields
5. Slashing parameters are set to all zeros:
   - `SignedBlocksWindow = 0`
   - `MinSignedPerWindow = 0`
   - `DowntimeJailDuration = 0`
   - `SlashFractionDoubleSign = 0`
   - `SlashFractionDowntime = 0`
6. **Result: Slashing is effectively disabled**, validators cannot be penalized for misbehavior

### Scenario 2: Malicious Upgrade with Empty Name
1. Attacker obtains governance VAA for `ActionScheduleUpgrade`
2. Provides malformed payload
3. Upgrade is scheduled with empty name and height = 0
4. **Result: Potential chain halt or unexpected upgrade behavior**

## Proof of Concept

The Deserialize implementations return errors for invalid payloads:

```go
// From sdk/vaa/payloads.go:442
func (r *BodyGatewaySlashingParamsUpdate) Deserialize(bz []byte) error {
	if len(bz) != 40 {
		return fmt.Errorf("incorrect payload length, should be 40, is %d", len(bz))
	}
	// ...
}

// From sdk/vaa/payloads.go:420
func (r *BodyGatewayIbcComposabilityMwContract) Deserialize(bz []byte) error {
	if len(bz) != 32 {
		return fmt.Errorf("incorrect payload length, should be 32, is %d", len(bz))
	}
	// ...
}
```

But these errors are **never checked** by the callers.

## Impact
- **HIGH**: Can disable critical chain security features (slashing)
- **MEDIUM**: Can set invalid contract addresses or upgrade plans
- Affects chain stability and security guarantees

## Remediation
Add error checking after all `Deserialize()` calls:

```go
// FIXED VERSION
var payloadBody vaa.BodyGatewaySlashingParamsUpdate
if err := payloadBody.Deserialize(payload); err != nil {
	return nil, err
}
```

Apply this fix to:
1. Line 66: `scheduleUpgrade()`
2. Line 88: `setIbcComposabilityMwContract()`
3. Line 113: `setSlashingParams()`
4. Line 60 in `msg_server_wasm_instantiate_allowlist.go`

## Verification Status
✅ **VERIFIED** - Vulnerability confirmed through code analysis
- Deserialize methods return errors
- Callers do not check these errors
- Zero values are used when deserialization fails
- Critical parameters can be set to unsafe values
