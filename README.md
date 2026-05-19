# Circles Builder Org Manager

A miniapp for the [Circles](https://aboutcircles.com) ecosystem that lets users create and manage
dedicated **Circles Organization** avatars from inside the Circles app. 
## What it does

The app walks through four steps once an organization is created:

1. **Accepted CRC Tokens** — trust the personal or group CRC tokens the org will accept as payment.
2. **External Signers** — add an EOA as a Safe owner so a backend can sign transactions on the
   org's behalf (e.g. automatic payouts).
3. **Fund Signers** — top up signer EOAs with xDAI for gas via the on-chain faucet.
4. **Withdraw CRC** — withdraw the org's CRC balance to the connected wallet or another address,
   batched across all held tokens.

Organizations can also be edited (name, description, image) after creation. Profile images are
resized and pinned to IPFS via the Circles SDK before being written on-chain.

## Tech

- Vanilla JS + [Vite](https://vitejs.dev)
- [viem](https://viem.sh) for chain interactions
- [@aboutcircles/sdk](https://www.npmjs.com/package/@aboutcircles/sdk),
  [@aboutcircles/sdk-utils](https://www.npmjs.com/package/@aboutcircles/sdk-utils),
  [@aboutcircles/miniapp-sdk](https://www.npmjs.com/package/@aboutcircles/miniapp-sdk)
- [@safe-global/safe-deployments](https://github.com/safe-global/safe-deployments) for the
  canonical Safe singleton, proxy factory, fallback handler, and MultiSendCallOnly addresses
- Network: [Gnosis Chain](https://www.gnosis.io) (RPC: `rpc.aboutcircles.com`, falling back to
  `rpc.gnosischain.com`)

## Running locally

```bash
npm install
npm run dev      # http://localhost:5183
```

```bash
npm run build    # production bundle in dist/
npm run preview  # serve the production build
```

The wallet connection is provided by the host Circles app via `@aboutcircles/miniapp-sdk`, so
the full flow is best exercised from inside the Circles miniapp container. Outside that context
the UI loads but the login step will stay in the "Not connected" state.

## Project layout

```
index.html        Markup + section structure for each step
main.js           All app logic: wallet, Safe deployment, trust, faucet, withdraw
style.css         Styles
vite.config.js    Vite + buffer polyfill for browser builds
```

There is no framework and no router — sections are swapped by toggling a `hidden` class on the
relevant `<div>`s in `index.html`.
