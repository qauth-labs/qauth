# Repo layout

Legend: ✅ implemented · 🚧 in progress · 📋 planned

```
qauth/
├── apps/
│   ├── auth-server/         ✅ Fastify OAuth 2.1 / OIDC 1.0 server
│   ├── auth-ui/             📋 planned — brandable login UI, Phase 2/4
│   └── admin-panel/         📋 planned — Phase 6+
├── libs/
│   ├── server/federation/   ✅ wallet federation, OID4VP verification
│   ├── core/crypto/         ✅ post-quantum backend via @noble
│   ├── core/oauth/          📋 planned extraction — inlined in auth-server
│   └── sdk/                 📋 planned — Phase 3
```
