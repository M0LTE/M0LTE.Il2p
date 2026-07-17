# M0LTE.Il2p

A managed **IL2P (Improved Layer 2 Protocol) v0.6 codec** for .NET, extracted from the
[pdn-soundmodem](https://github.com/packet-net/pdn-soundmodem) packet-radio modem. It maps
AX.25 frames to and from the IL2P wire format — Type 0/1 headers, the packet-synchronous
scrambler, Reed-Solomon FEC and block segmentation — including the **IL2P+CRC** extension,
and provides a streaming bit-level deframer for a demodulator to feed. Dire Wolf / NinoTNC
interoperable.

- **Targets** `net10.0`. Depends only on [`M0LTE.Fec`](https://www.nuget.org/packages/M0LTE.Fec).
- Public API is **locked by a build-time test**; the package follows
  [Semantic Versioning](https://semver.org/) (see [`docs/versioning.md`](docs/versioning.md)).

## Install

```sh
dotnet add package M0LTE.Il2p
```

## Encode / decode a frame

```csharp
using M0LTE.Il2p;

byte[] ax25 = /* an AX.25 frame: addresses + control + PID + info, no flags/FCS */;

// Encode to the IL2P wire bytes (header + payload blocks [+ CRC]), sync word excluded.
byte[] wire = Il2pCodec.Encode(ax25, appendCrc: true);

// Decode back. A CRC mismatch doesn't fail the decode — it's reported in info.CrcValid.
if (Il2pCodec.TryDecode(wire, hasTrailingCrc: true, out byte[] decoded, out Il2pDecodeInfo info))
{
    // decoded == ax25 ; info.CrcValid tells you whether the IL2P+CRC checked out
}
```

## Streaming receive

A demodulator pushes raw bits; the deframer hunts the sync word, collects the header and
payload, RS-corrects and raises complete AX.25 frames:

```csharp
var deframer = new Il2pDeframer(
    frameReceived: (frame, info) => { /* a recovered AX.25 frame + decode diagnostics */ },
    crcMode: true);
foreach (int bit in demodulatedBits)
    deframer.PushBit(bit);
```

(Exact constructor/event/method signatures are in the XML docs shipped with the package.)

## Licence & provenance

GPL-3.0-or-later (see [`LICENSE`](LICENSE)) — parts of the scrambler and header bit-field
placement are derived from Dire Wolf's GPL source; the rest is transcribed from the IL2P
specification. See [`PROVENANCE.md`](PROVENANCE.md).
