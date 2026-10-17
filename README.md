# axon-tor

> **USE AT YOUR OWN RISK.** This is a personal project, not a product. Much of
> the code and nearly all of the documentation were written with AI, so the
> documentation may contain mistakes; the code and its tests are the reference.
> Nobody has reviewed it for security, nothing here is guaranteed to be stable,
> correct or fit for any purpose, and the license gives no warranty. Whatever
> you do with it is at your own risk. It does not make anyone anonymous; do not
> use it to protect anyone.

A Tor client built on [Axon](https://github.com/NeuroMarshal/axon). It joins
the real Tor network and reaches websites through exit relays and onion
services through rendezvous points, behind a local SOCKS5 or HTTP proxy.

It is a proof of concept: it shows that an Axon node can speak another
network's own protocols. The client is an Axon `NodeCore`; Tor's link
protocol, circuits, directory and onion service protocols are written in this
crate on top of Axon's interfaces. It lacks much of what keeps Tor users
anonymous.

## What works

- Links to relays over TLS, with the relay's RSA and Ed25519 identities
  checked through the CERTS cell
- The microdescriptor consensus, accepted only with valid signatures from a
  majority of the directory authorities, and the relays' microdescriptors
- Three-hop circuits with the ntor handshake, streams with flow control and
  authenticated SENDMEs
- Connections through exit relays, including HTTPS through CONNECT
- Onion services v3: blinded keys, the descriptor directory ring, both
  descriptor layers, introduction and rendezvous

It has loaded www.torproject.org, check.torproject.org and the Tor
Project's onion site.

## What it leaves out

It is a client only and does not relay traffic or host onion services. It
keeps one random guard per run and saves no guard state, and it weights
relays by bandwidth alone, without the consensus's position weights. It does
not use relay families, conflux, congestion control, padding or client
authorization for onion services.

## Running it

Axon is a path dependency, so clone both repositories side by side:

```bash
git clone https://github.com/NeuroMarshal/axon
git clone https://github.com/NeuroMarshal/axon-tor
cd axon-tor
cp axon-tor.example.toml axon-tor.toml
cargo run --release -- axon-tor.toml
```

Then, from another terminal:

```bash
curl -x http://127.0.0.1:8118 https://check.torproject.org/api/ip
curl --socks5-hostname 127.0.0.1:9150 http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/
```

Starting takes about ten seconds while the client downloads the consensus
and microdescriptors.

## Tests

`cargo test` runs the offline tests. `cargo test --test live -- --ignored`
runs the checks against the real network: the directory documents and their
signatures, a page through an exit, and an onion site.

## License

MIT or Apache-2.0, at your option: you may use the code under either license
(`LICENSE-MIT`, `LICENSE-APACHE`).
