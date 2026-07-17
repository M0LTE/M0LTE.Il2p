using M0LTE.Fec;

namespace M0LTE.Il2p;

/// <summary>Outcome details for a successful <see cref="Il2pCodec.TryDecode"/>.</summary>
/// <param name="HeaderType">Which IL2P header mapping the frame used.</param>
/// <param name="CorrectedSymbols">Total bytes repaired by Reed-Solomon FEC across the
/// header and all payload blocks (0 for a clean frame).</param>
/// <param name="CrcValid">Result of the optional trailing CRC check: true/false when a
/// CRC was present, null when decoding without one. A false value means RS decoding
/// "succeeded" but produced a frame whose CRC disagrees — the caller decides whether to
/// enforce (NinoTNC il2p_crc bit-1 semantics).</param>
public readonly record struct Il2pDecodeInfo(
    Il2pHeaderType HeaderType, int CorrectedSymbols, bool? CrcValid);

/// <summary>
/// Whole-frame IL2P encoder/decoder (spec draft v0.6), covering both header types, the
/// always-16-parity payload blocks, and the optional Hamming-protected trailing CRC
/// ("IL2P+CRC", the NinoTNC extension standardised in v0.6). Operates on the bytes
/// between the sync word and the end of the frame — preamble, sync word detection and
/// bit recovery belong to the modem layer.
/// </summary>
/// <remarks>
/// Encoding is byte-exact against all three example packets in the spec (S-frame,
/// UI-frame, I-frame, provided by G4KLX) when <c>legacyMaxFecBit</c> is false. The
/// default keeps that pre-v0.6 bit set for interop: Dire Wolf's decoder (empirically,
/// via atest cross-validation) selects the legacy variable-parity plan when it is clear
/// and rejects 16-parity frames — the NinoTNC lineage is expected to match, bench-gated.
/// Our decoder ignores the bit and accepts either form.
/// </remarks>
public static class Il2pCodec
{
    /// <summary>The 24-bit IL2P sync word 0xF15E48 (± 1 bit tolerance at the receiver).</summary>
    public const int SyncWord = 0xF15E48;

    /// <summary>Wire length of the header: 13 bytes + 2 RS parity.</summary>
    public const int HeaderWireLength = Il2pHeaderCodec.HeaderLength + HeaderParitySymbols;

    /// <summary>RS parity symbols protecting the header.</summary>
    public const int HeaderParitySymbols = 2;

    /// <summary>Largest payload the 10-bit byte count can describe.</summary>
    public const int MaxPayloadBytes = 1023;

    /// <summary>Wire length of the optional Hamming-encoded trailing CRC.</summary>
    public const int TrailingCrcWireLength = 4;

    private static readonly ReedSolomon HeaderRs = new(HeaderParitySymbols, firstConsecutiveRoot: 0);
    private static readonly ReedSolomon PayloadRs = new(Il2pBlockLayout.ParitySymbolsPerBlock, firstConsecutiveRoot: 0);

    /// <summary>
    /// Encodes an AX.25 frame (addresses + control [+ PID + info], no flags, no FCS,
    /// not bit-stuffed) as IL2P wire bytes, excluding preamble and sync word.
    /// Uses Type 1 translated encapsulation when the header allows it, falling back to
    /// Type 0 transparent encapsulation otherwise.
    /// </summary>
    /// <param name="ax25Frame">The AX.25 frame to encapsulate.</param>
    /// <param name="appendCrc">Append the optional Hamming-encoded CRC-16/X-25 trailer
    /// ("IL2P+CRC"). Both stations must agree on its presence.</param>
    /// <param name="legacyMaxFecBit">Set the pre-v0.6 "max FEC" header bit (RESERVED in
    /// v0.6). Default true: Dire Wolf (and the NinoTNC lineage) reject 16-parity frames
    /// without it. Pass false only to produce byte-exact v0.6 spec-example output.</param>
    /// <exception cref="ArgumentException">The frame is empty or too large to encapsulate.</exception>
    public static byte[] Encode(ReadOnlySpan<byte> ax25Frame, bool appendCrc, bool legacyMaxFecBit = true)
    {
        if (ax25Frame.IsEmpty)
        {
            throw new ArgumentException("cannot encode an empty frame", nameof(ax25Frame));
        }

        Span<byte> header = stackalloc byte[Il2pHeaderCodec.HeaderLength];
        ReadOnlySpan<byte> payload;
        if (Il2pHeaderCodec.TryEncodeType1(ax25Frame, header, legacyMaxFecBit, out int payloadOffset))
        {
            payload = ax25Frame[payloadOffset..];
        }
        else
        {
            if (ax25Frame.Length > MaxPayloadBytes)
            {
                throw new ArgumentException(
                    $"frame of {ax25Frame.Length} bytes exceeds the IL2P maximum of {MaxPayloadBytes}",
                    nameof(ax25Frame));
            }

            Il2pHeaderCodec.EncodeType0(ax25Frame.Length, header, legacyMaxFecBit);
            payload = ax25Frame;
        }

        var layout = Il2pBlockLayout.Compute(payload.Length);
        int totalLength = HeaderWireLength + layout.WireLength + (appendCrc ? TrailingCrcWireLength : 0);
        var output = new byte[totalLength];
        var outSpan = output.AsSpan();

        Il2pScrambler.Scramble(header, outSpan[..Il2pHeaderCodec.HeaderLength]);
        HeaderRs.Encode(
            outSpan[..Il2pHeaderCodec.HeaderLength],
            outSpan.Slice(Il2pHeaderCodec.HeaderLength, HeaderParitySymbols));

        int inPos = 0;
        int outPos = HeaderWireLength;
        for (int block = 0; block < layout.BlockCount; block++)
        {
            int size = block < layout.LargeBlockCount ? layout.LargeBlockSize : layout.SmallBlockSize;
            Il2pScrambler.Scramble(payload.Slice(inPos, size), outSpan.Slice(outPos, size));
            PayloadRs.Encode(
                outSpan.Slice(outPos, size),
                outSpan.Slice(outPos + size, Il2pBlockLayout.ParitySymbolsPerBlock));
            inPos += size;
            outPos += size + Il2pBlockLayout.ParitySymbolsPerBlock;
        }

        if (appendCrc)
        {
            ushort crc = Crc16X25.Compute(ax25Frame);
            output[outPos++] = Hamming74.Encode(crc >> 12);
            output[outPos++] = Hamming74.Encode(crc >> 8);
            output[outPos++] = Hamming74.Encode(crc >> 4);
            output[outPos] = Hamming74.Encode(crc);
        }

        return output;
    }

    /// <summary>
    /// Decodes the 15 header wire bytes that follow a sync word, yielding the header type
    /// and payload byte count a streaming receiver needs to collect the rest of the frame
    /// (payload wire length = <see cref="Il2pBlockLayout.WireLength"/> of
    /// <see cref="Il2pBlockLayout.Compute"/>, plus <see cref="TrailingCrcWireLength"/> when
    /// the link uses IL2P+CRC).
    /// </summary>
    public static bool TryDecodeHeader(
        ReadOnlySpan<byte> headerWire, out Il2pHeaderType headerType, out int payloadByteCount,
        out int correctedSymbols)
    {
        headerType = Il2pHeaderType.Type0;
        payloadByteCount = 0;
        correctedSymbols = 0;
        if (headerWire.Length < HeaderWireLength)
        {
            return false;
        }

        Span<byte> block = stackalloc byte[HeaderWireLength];
        headerWire[..HeaderWireLength].CopyTo(block);
        int corrected = HeaderRs.Decode(block);
        if (corrected < 0)
        {
            return false;
        }

        Span<byte> header = block[..Il2pHeaderCodec.HeaderLength];
        Il2pScrambler.Descramble(header);
        headerType = Il2pHeaderCodec.GetHeaderType(header);
        payloadByteCount = Il2pHeaderCodec.GetPayloadByteCount(header);
        correctedSymbols = corrected;
        return true;
    }

    /// <summary>
    /// Decodes a complete IL2P frame (sync word excluded) back to its AX.25 frame.
    /// </summary>
    /// <param name="il2pWire">Header, payload blocks and — when
    /// <paramref name="hasTrailingCrc"/> — the 4-byte encoded CRC, exactly as received.</param>
    /// <param name="hasTrailingCrc">Whether the link uses IL2P+CRC. A CRC mismatch does not
    /// fail the decode; it surfaces as <see cref="Il2pDecodeInfo.CrcValid"/> = false for the
    /// caller to enforce or ignore.</param>
    /// <param name="ax25Frame">The reconstructed AX.25 frame (no flags, no FCS).</param>
    /// <param name="info">Decode diagnostics.</param>
    /// <returns>False when RS decoding fails, the length is inconsistent with the header's
    /// payload count, or the header fields are not those of a conforming encoder.</returns>
    public static bool TryDecode(
        ReadOnlySpan<byte> il2pWire, bool hasTrailingCrc, out byte[] ax25Frame, out Il2pDecodeInfo info)
    {
        ax25Frame = [];
        info = default;

        if (il2pWire.Length < HeaderWireLength)
        {
            return false;
        }

        Span<byte> headerBlock = stackalloc byte[HeaderWireLength];
        il2pWire[..HeaderWireLength].CopyTo(headerBlock);
        int corrected = HeaderRs.Decode(headerBlock);
        if (corrected < 0)
        {
            return false;
        }

        Span<byte> header = headerBlock[..Il2pHeaderCodec.HeaderLength];
        Il2pScrambler.Descramble(header);
        var headerType = Il2pHeaderCodec.GetHeaderType(header);
        int payloadCount = Il2pHeaderCodec.GetPayloadByteCount(header);

        var layout = Il2pBlockLayout.Compute(payloadCount);
        int expectedLength =
            HeaderWireLength + layout.WireLength + (hasTrailingCrc ? TrailingCrcWireLength : 0);
        if (il2pWire.Length != expectedLength)
        {
            return false;
        }

        var payload = new byte[payloadCount];
        int inPos = HeaderWireLength;
        int outPos = 0;
        Span<byte> blockBuffer = stackalloc byte[Il2pBlockLayout.MaxBlockDataSize + Il2pBlockLayout.ParitySymbolsPerBlock];
        for (int block = 0; block < layout.BlockCount; block++)
        {
            int size = block < layout.LargeBlockCount ? layout.LargeBlockSize : layout.SmallBlockSize;
            int wireSize = size + Il2pBlockLayout.ParitySymbolsPerBlock;
            var codeword = blockBuffer[..wireSize];
            il2pWire.Slice(inPos, wireSize).CopyTo(codeword);
            int blockCorrected = PayloadRs.Decode(codeword);
            if (blockCorrected < 0)
            {
                return false;
            }

            corrected += blockCorrected;
            Il2pScrambler.Descramble(codeword[..size]);
            codeword[..size].CopyTo(payload.AsSpan(outPos));
            inPos += wireSize;
            outPos += size;
        }

        if (headerType == Il2pHeaderType.Type0)
        {
            if (payloadCount == 0)
            {
                return false; // a Type 0 frame is nothing but payload
            }

            ax25Frame = payload;
        }
        else
        {
            if (!Il2pHeaderCodec.TryDecodeType1(header, out byte[] ax25Header))
            {
                return false;
            }

            var frame = new byte[ax25Header.Length + payloadCount];
            ax25Header.CopyTo(frame, 0);
            payload.CopyTo(frame, ax25Header.Length);
            ax25Frame = frame;
        }

        bool? crcValid = null;
        if (hasTrailingCrc)
        {
            var trailer = il2pWire[^TrailingCrcWireLength..];
            int received =
                (Hamming74.Decode(trailer[0]) << 12) |
                (Hamming74.Decode(trailer[1]) << 8) |
                (Hamming74.Decode(trailer[2]) << 4) |
                Hamming74.Decode(trailer[3]);
            crcValid = received == Crc16X25.Compute(ax25Frame);
        }

        info = new Il2pDecodeInfo(headerType, corrected, crcValid);
        return true;
    }
}
