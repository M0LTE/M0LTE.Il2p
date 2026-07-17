# Provenance

`M0LTE.Il2p` is a managed IL2P (Improved Layer 2 Protocol) v0.6 codec, extracted from the
[pdn-soundmodem](https://github.com/packet-net/pdn-soundmodem) packet-radio modem. It is
licensed **GPL-3.0-or-later** because parts of it are derived from Dire Wolf's GPL source
(see below) — this is a copyleft obligation, not a choice.

| Aspect | Provenance |
| --- | --- |
| Hamming encode/decode tables, block-size computations, sync word, RS parameters | Transcribed **verbatim from the IL2P v0.6 specification**. |
| The scrambler's exact bit expressions and initial states (`0x00F`/`0x1F0`, 5-bit Galois delay, flush) and the header's bit-field placement | **From Dire Wolf's source** — the specification presents these only as figures, so the operative bit-level detail comes from the reference implementation (GPL-2.0-or-later, © John Langner WB2OSZ). This is what makes the package GPL. |
| Reed-Solomon FEC | Via the [`M0LTE.Fec`](https://www.nuget.org/packages/M0LTE.Fec) dependency (independent implementation). |

Validated byte-exact against the IL2P specification's three example packets (S / UI / I
frames) and cross-checked for interoperability against Dire Wolf and NinoTNC behaviour in the
originating repo.

## Dependency

- **`M0LTE.Fec`** (AGPL-3.0-or-later) — Reed-Solomon, Hamming and CRC primitives. A GPL-3.0
  work may depend on an AGPL-3.0 one under GPLv3 §13; AGPL §13's network-source requirement
  then applies to the combined work.
