A browser can complete a wallet sign-in — first-time enrolment, returning login, account linking and `acr` emission are all covered end-to-end against a mock wallet speaking OID4VP 1.0 over the wire. Set `WALLET_FEDERATION_ENABLED=true` to register the routes; **the whole surface is inert while it is off**, which is the default. Validated so far only against the `oid4vp-1.0-base` profile and a mock wallet. See the [wallet sign-in guide](./docs/wallet-login.md).
Note: `WalletProvider.verify()` — the generic `CredentialProvider`-registry entry point — still throws by design (#232). Wallet login does **not** go through it; it runs on the dedicated `/ui/wallet-login` + `/oid4vp/response` seam.

- **Open:** HAIP profile wiring (#377), key-storage assurance into the assurance policy (#379), the real-wallet interoperability pass (#376), and the tracking epic (#231).

**📋 Not started — deferred beyond T4**
