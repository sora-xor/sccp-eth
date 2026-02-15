# sccp-eth

SORA Cross-Chain Protocol (SCCP) contracts for EVM chains (Ethereum).

This repo provides:
- `SccpRouter`: burn wrapped ERC-20s to create an on-chain SCCP burn message + `messageId`
- `SccpToken`: minimal ERC-20 used as the wrapped representation of a SORA asset
- `ISccpVerifier`: pluggable on-chain verifier interface (light client / consensus proofs)

`mintFromProof` is **fail-closed** until a real verifier contract is configured.
Router hardening is also fail-closed for unsupported domains: burn/mint/incident-control calls reject unknown domain IDs.

## Build

```bash
./scripts/compile.sh
```

## Deploy (high level)

1. Deploy `SccpRouter` with:
   - `localDomain = 1` (ETH)
   - `governor = <your on-chain governance address>`
2. For each SORA `asset_id` you want to bridge, deploy/register a wrapped ERC-20:
   - call `SccpRouter.deployToken(soraAssetId, name, symbol, decimals)`
3. On SORA (runtime pallet `sccp`):
   - call `set_domain_endpoint(SCCP_DOMAIN_ETH, <router address bytes>)`
   - call `set_remote_token(asset_id, SCCP_DOMAIN_ETH, <token address bytes>)`
   - after setting all required domains, call `activate_token(asset_id)`

## Burn (ETH -> X)

1. `approve(router, amount)` on the wrapped token
2. `SccpRouter.burnToDomain(soraAssetId, amount, destDomain, recipient32)`

The burn emits `SccpBurned(messageId, ..., payload)` where `payload` is SCALE-encoded
`BurnPayloadV1` (97 bytes). Target chains compute:

`messageId = keccak256(b"sccp:burn:v1" || payload)`.

## Mint (Any -> ETH, Via SORA Finality)

Minting on this chain is always driven by **SORA finality**:

- For `SORA -> ETH`, SORA burns and commits `messageId` into its auxiliary digest, and users call:
  - `SccpRouter.mintFromProof(DOMAIN_SORA, payload, soraBeefyMmrProof)`
- For `X -> ETH` where `X != SORA`, SORA must first verify the source-chain burn and commit its `messageId` into the
  auxiliary digest (SORA runtime extrinsic `sccp.attest_burn`). Then users call:
  - `SccpRouter.mintFromProof(sourceDomain = X, payload, soraBeefyMmrProof)`

## Verifier Security Properties (SORA -> ETH)

`SoraBeefyLightClientVerifier` enforces:

- `>= 2/3` validator signatures for each imported BEEFY commitment
- validator merkle-membership proofs against the stored validator set root
- duplicate signer-key rejection in one commitment proof
- ECDSA signature validity checks (`r != 0`, `s != 0`, and low-`s`)

## Proofs To SORA (ETH As Source Chain)

Inbound proofs from ETH to SORA are finalized on SORA by domain-specific finality mode:

- default mode: `EthBeaconLightClient` for `DOMAIN_ETH` (currently not integrated on SORA, fail-closed)
- required runtime controls on SORA:
  - `sccp.set_inbound_finality_mode(DOMAIN_ETH, EvmAnchor)` (temporary override)
  - `sccp.set_evm_anchor_mode_enabled(DOMAIN_ETH, true)`
  - `sccp.set_evm_inbound_anchor(DOMAIN_ETH, block_number, block_hash, state_root)`
- alternative temporary override: `AttesterQuorum` (CCTP-style threshold ECDSA signatures over `messageId`)
- long-term target mode remains `EthBeaconLightClient` (trustless beacon finality)

So today, ETH -> SORA minting/attestation is secured by governance-provided finalized execution roots plus on-chain MPT proof verification.

## Proof Generation (bridge-relayer)

Use `bridge-relayer` to build on-chain proof inputs:

1. Export verifier init sets:
   - `sccp evm init`
2. Import finalized SORA MMR roots:
   - `sccp evm import-root --justification-block <beefy_block>`
3. Build mint proof payload for `verifyBurnProof` / `mintFromProof`:
   - `sccp evm mint-proof --burn-block <burn_block> --beefy-block <beefy_block> --message-id 0x... --abi`

`--abi` returns the exact ABI bytes expected by `SoraBeefyLightClientVerifier.verifyBurnProof`.
