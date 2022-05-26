<img src="https://svgur.com/i/gyQ.svg" width="200"/>

## Ownership of web2 social media profiles verified on-chain.

### This [master contract](./verified.sol) can be found live on the BSC testnet :
[0x894389Ab1c579E6a98fe4B99FC6c4EfaeADD0A62](https://testnet.bscscan.com/address/0x894389Ab1c579E6a98fe4B99FC6c4EfaeADD0A62)

### Disclamer
This contract requires a transfer of $LINK to operate (0.1 for the `requestVerification()` method and 0.1 per each call of the `verify()` method)

⚠️ Do not transfer $LINK directly to the contract, use the [ERC677 transferAndCall() method](https://github.com/ethereum/EIPs/issues/677)

### Recommended usage
The recommended way of interaction with the contract is to use the following dapp :
[verified.nescrypto.com](https://verified.nescrypto.com)

### Manual usage for URL verification
- 1:  `transferAndCall()` to transfer $LINK tokens to the contract balance
- 2: `requestVerification()` to create the request
- 3: subscribe for the `ValidationUpdate()` event to get the randomly-generated challenge
- 4:  `verify()` to finalize the process
- 5: subscribe to the `VerificationResult()` event to get the verification result

### Manual usage for getting a verification report
- 1: `getVerificationsForAddress(address)` with a valid BSC Testnet address
- 2: subscribe to the `VerificationForAddress()` event to get each verification

### Notes if you wish to deploy this contract 
- at deploy the contract creates a [VRF subscription](https://vrf.chain.link), its recommended to manually transfer at least 1 $LINK at deploy, to avoid issues with getting "pending" stuck RNG requests
