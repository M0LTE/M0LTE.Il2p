using M0LTE.Fec;

namespace M0LTE.Il2p;

/// <summary>Outcome details for a successful
/// <see cref="Il2pCodec.TryDecode(ReadOnlySpan{byte}, bool, out byte[], out Il2pDecodeInfo)"/>.</summary>
/// <param name="HeaderType">Which IL2P header mapping the frame used.</param>
/// <param name="CorrectedSymbols">Total bytes repaired by Reed-Solomon FEC across the
/// header and all payload blocks (0 for a clean frame).</param>
/// <param name="CrcValid">Result of the optional trailing CRC check: true/false when a
/// CRC was present, null when decoding without one. A false value means RS decoding
/// "succeeded" but produced a frame whose CRC disagrees — the caller decides whether to
/// enforce (NinoTNC il2p_crc bit-1 semantics).</param>
/// <param name="ErasedSymbols">Bytes the decode flagged as erasures from the caller's
/// confidence hints before Reed-Solomon repaired the frame - non-zero only on the
/// confidence-aware path, and only when errors-only decoding had already failed. A frame
/// recovered this way leaned on receiver confidence as well as parity; the count is the
/// honest measure of how hard.</param>
/// <param name="ChasedBits">Received bits the decode flipped outright on the caller's
/// confidence hints - chase decoding, tried when errors-only decoding fails, before
/// erasures. A correct flip costs no parity at all where an erasure costs one symbol and an
/// unlocated error two, which is what rescues a block sitting one or two scattered bit
/// errors past the budget - and it is the 2-parity header's only rescue.</param>
public readonly record struct Il2pDecodeInfo(
    Il2pHeaderType HeaderType, int CorrectedSymbols, bool? CrcValid, int ErasedSymbols = 0,
    int ChasedBits = 0);

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
        if (Il2pHeaderCodec.TryEncodeType1(ax25Frame, header, legacyMaxFecBit, out int payloadOffset)
            && (!appendCrc || Type1RoundTripsExactly(header, ax25Frame[..payloadOffset])))
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

    // The Type 1 translation is lossy: IL2P carries a single C bit (the degenerate AX.25
    // equal-C-bit forms decode as the complementary v2.2 pair) and canonicalises the
    // layer-3 PID group to 0x20. Harmless on a plain IL2P link — but the trailing CRC is
    // computed here over the ORIGINAL frame while the receiver checks it against its
    // RECONSTRUCTION, so any lossy translation makes every such frame fail the CRC and
    // (under NinoTNC il2p_crc semantics) be dropped. When the CRC rides along, only a
    // byte-exact header roundtrip may use Type 1; everything else falls back to Type 0
    // transparent encapsulation, which reproduces the frame byte-for-byte under either
    // convention. (A NinoTNC transmits Type 0 throughout, so this also matches the
    // interop ground truth for the frames it can send.)
    private static bool Type1RoundTripsExactly(ReadOnlySpan<byte> header, ReadOnlySpan<byte> ax25Header) =>
        Il2pHeaderCodec.TryDecodeType1(header, out byte[] roundTripped)
        && ax25Header.SequenceEqual(roundTripped);

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
        => TryDecodeHeader(headerWire, [], out headerType, out payloadByteCount, out correctedSymbols, out _);

    /// <summary>
    /// <see cref="TryDecodeHeader(ReadOnlySpan{byte}, out Il2pHeaderType, out int, out int)"/>
    /// with per-byte receiver confidence: when errors-only decoding fails, the weakest wire
    /// bytes are retried as Reed-Solomon erasures (see the confidence-aware
    /// <see cref="TryDecode(ReadOnlySpan{byte}, bool, ReadOnlySpan{float}, out byte[], out Il2pDecodeInfo)"/>
    /// for the contract). The header's 2-parity code corrects one unlocated error; with the
    /// two damaged bytes flagged it corrects both, which decides whether a short frame is
    /// collected at all.
    /// </summary>
    /// <param name="headerWire">The 15 header wire bytes following the sync word.</param>
    /// <param name="confidence">Per-byte confidence aligned to <paramref name="headerWire"/>
    /// (lower = less reliable), or empty for hard-decision decoding.</param>
    /// <param name="headerType">Which IL2P header mapping the frame uses.</param>
    /// <param name="payloadByteCount">Payload bytes the header says follow.</param>
    /// <param name="correctedSymbols">Bytes Reed-Solomon repaired in the header block.</param>
    /// <param name="erasedSymbols">Bytes erased from the confidence hints to get there.</param>
    public static bool TryDecodeHeader(
        ReadOnlySpan<byte> headerWire, ReadOnlySpan<float> confidence,
        out Il2pHeaderType headerType, out int payloadByteCount,
        out int correctedSymbols, out int erasedSymbols)
    {
        headerType = Il2pHeaderType.Type0;
        payloadByteCount = 0;
        correctedSymbols = 0;
        erasedSymbols = 0;
        if (headerWire.Length < HeaderWireLength)
        {
            return false;
        }

        Span<byte> block = stackalloc byte[HeaderWireLength];
        headerWire[..HeaderWireLength].CopyTo(block);
        SplitConfidence(confidence, headerWire.Length,
            out ReadOnlySpan<float> headerBytes, out ReadOnlySpan<float> headerBits);
        int corrected = DecodeBlock(
            HeaderRs, block, headerWire[..HeaderWireLength],
            headerBytes.IsEmpty ? [] : headerBytes[..HeaderWireLength],
            headerBits.IsEmpty ? [] : headerBits[..(HeaderWireLength * 8)],
            HeaderErasureLadder, HeaderChaseBits, HeaderChaseErrorCap,
            out int erased, out _);
        if (corrected < 0)
        {
            return false;
        }

        Span<byte> header = block[..Il2pHeaderCodec.HeaderLength];
        Il2pScrambler.Descramble(header);
        headerType = Il2pHeaderCodec.GetHeaderType(header);
        payloadByteCount = Il2pHeaderCodec.GetPayloadByteCount(header);
        correctedSymbols = corrected;
        erasedSymbols = erased;
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
        => TryDecode(il2pWire, hasTrailingCrc, [], out ax25Frame, out info);

    /// <summary>
    /// <see cref="TryDecode(ReadOnlySpan{byte}, bool, out byte[], out Il2pDecodeInfo)"/> with
    /// per-byte receiver confidence: whenever a block fails errors-only Reed-Solomon
    /// decoding, its weakest bytes are retried as erasures. Each erasure costs one parity
    /// symbol where an unlocated error costs two, so a block whose damage the confidence
    /// flags actually cover corrects up to twice as many bytes - the difference between
    /// losing and keeping a frame that took a fade through one block. The retry ladder tries
    /// progressively fewer erasures (leaving tolerance for damage the flags missed), and
    /// every attempt is still bound by the code's own re-syndrome check; on an IL2P+CRC link
    /// the trailing CRC remains the end-to-end arbiter of the whole frame.
    /// </summary>
    /// <param name="il2pWire">Header, payload blocks and optional CRC trailer, as received.</param>
    /// <param name="hasTrailingCrc">Whether the link uses IL2P+CRC.</param>
    /// <param name="byteConfidence">Per-byte confidence aligned to <paramref name="il2pWire"/>
    /// (lower = less reliable; the scale is the caller's, only the ordering matters), or
    /// empty for hard-decision decoding.</param>
    /// <param name="ax25Frame">The reconstructed AX.25 frame (no flags, no FCS).</param>
    /// <param name="info">Decode diagnostics, including how many bytes were erased.</param>
    public static bool TryDecode(
        ReadOnlySpan<byte> il2pWire, bool hasTrailingCrc, ReadOnlySpan<float> byteConfidence,
        out byte[] ax25Frame, out Il2pDecodeInfo info)
    {
        ax25Frame = [];
        info = default;

        if (il2pWire.Length < HeaderWireLength
            || (!byteConfidence.IsEmpty
                && byteConfidence.Length != il2pWire.Length
                && byteConfidence.Length != il2pWire.Length * 8))
        {
            return false;
        }

        SplitConfidence(byteConfidence, il2pWire.Length,
            out ReadOnlySpan<float> bytesConf, out ReadOnlySpan<float> bitsConf);

        Span<byte> headerBlock = stackalloc byte[HeaderWireLength];
        il2pWire[..HeaderWireLength].CopyTo(headerBlock);
        int corrected = DecodeBlock(
            HeaderRs, headerBlock, il2pWire[..HeaderWireLength],
            bytesConf.IsEmpty ? [] : bytesConf[..HeaderWireLength],
            bitsConf.IsEmpty ? [] : bitsConf[..(HeaderWireLength * 8)],
            HeaderErasureLadder, HeaderChaseBits, HeaderChaseErrorCap,
            out int erased, out int chased);
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
            int blockCorrected = DecodeBlock(
                PayloadRs, codeword, il2pWire.Slice(inPos, wireSize),
                bytesConf.IsEmpty ? [] : bytesConf.Slice(inPos, wireSize),
                bitsConf.IsEmpty ? [] : bitsConf.Slice(inPos * 8, wireSize * 8),
                PayloadErasureLadder, PayloadChaseBits, PayloadChaseErrorCap,
                out int blockErased, out int blockChased);
            if (blockCorrected < 0)
            {
                return false;
            }

            corrected += blockCorrected;
            erased += blockErased;
            chased += blockChased;
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

        info = new Il2pDecodeInfo(headerType, corrected, crcValid, erased, chased);
        return true;
    }

    /// <summary>
    /// The caller's confidence span is either per-byte (length n, erasures only) or per-bit
    /// (length 8n, erasures and chase); a per-bit span also yields the per-byte view, each
    /// byte's confidence being the minimum of its bits' - a byte is wrong if any bit is.
    /// The derived per-byte values live in a rented-free heap array only on the bit path,
    /// which only runs when a block already failed.
    /// </summary>
    private static void SplitConfidence(
        ReadOnlySpan<float> confidence, int wireLength,
        out ReadOnlySpan<float> bytes, out ReadOnlySpan<float> bits)
    {
        if (confidence.IsEmpty)
        {
            bytes = [];
            bits = [];
            return;
        }

        if (confidence.Length == wireLength)
        {
            bytes = confidence;
            bits = [];
            return;
        }

        if (confidence.Length != wireLength * 8)
        {
            // A mismatched span is a caller bug; decode hard rather than misindex.
            bytes = [];
            bits = [];
            return;
        }

        var byteMins = new float[wireLength];
        for (int i = 0; i < wireLength; i++)
        {
            float min = float.MaxValue;
            for (int b = 0; b < 8; b++)
            {
                float c = confidence[(i * 8) + b];
                if (c < min)
                {
                    min = c;
                }
            }

            byteMins[i] = min;
        }

        bytes = byteMins;
        bits = confidence;
    }

    /// <summary>
    /// (Erasures, additional-error cap) pairs tried, in order, when a payload block fails
    /// errors-only decoding. Every rung satisfies erasures + 2·cap = 14, two parity symbols
    /// short of the code's 16: an attempt that spent the whole budget would have no residual
    /// syndromes to check itself against (with all sixteen erased it is pure interpolation
    /// and always "succeeds"), while two in reserve put a wrong rung's false-accept near a
    /// 16-bit CRC's. Descending erasures: the first rungs trust the confidence ranking
    /// most; the later ones trade flagged coverage for tolerance of damage the flags
    /// missed. Seven cheap attempts, and only for a block that was headed for the bin.
    /// </summary>
    private static readonly (int Erasures, int MaxErrors)[] PayloadErasureLadder =
        [(14, 0), (12, 1), (10, 2), (8, 3), (6, 4), (4, 5), (2, 6)];

    /// <summary>
    /// The header's 2-parity code affords no speculative erasures at all: any rung would
    /// spend both parity symbols and accept whatever interpolation produced - a hallucinated
    /// header that sizes a bogus collection. The header's rescue is chase, below.
    /// </summary>
    private static readonly (int Erasures, int MaxErrors)[] HeaderErasureLadder = [];

    /// <summary>Weakest bits chased in a failed payload block: 31 flip patterns. Chase runs
    /// before the erasure ladder because a correct flip costs no parity at all - it is what
    /// rescues a block one or two scattered bit errors past the budget, the AWGN-knee
    /// pattern erasures cannot reach.</summary>
    private const int PayloadChaseBits = 5;

    /// <summary>Payload chase candidates decode with the code's full error budget: each
    /// attempt carries exactly a plain errors-only decode's bounded-distance guarantee, and
    /// the ~31x multiplier is why this is <b>CRC-arbitrated</b> chase - on an IL2P+CRC link
    /// the trailing CRC judges the frame, and a plain-only reading reaches a host only
    /// through the corroboration and acceptPlainIl2p gates that already price RS-only
    /// evidence.</summary>
    private const int PayloadChaseErrorCap = -1;

    /// <summary>Weakest bits chased in a failed header: 63 flip patterns.</summary>
    private const int HeaderChaseBits = 6;

    /// <summary>Header chase candidates must decode to an <em>exact</em> codeword (zero
    /// located errors), keeping both parity symbols as pure check - a 2-parity decode that
    /// spent one on an error would have no margin left, and 63 attempts at no margin would
    /// hallucinate headers that size bogus collections.</summary>
    private const int HeaderChaseErrorCap = 0;

    /// <summary>
    /// Decodes one Reed-Solomon block: errors-only first; when that fails and the caller
    /// supplied per-bit confidence, chase - retry from <paramref name="original"/> with the
    /// weakest bits flipped, patterns in ascending flip count; when that fails too and
    /// per-byte confidence exists, the erasure ladder. <paramref name="working"/> holds the
    /// decoded block on success.
    /// </summary>
    /// <returns>Corrected byte count, or -1 when every attempt fails.</returns>
    private static int DecodeBlock(
        ReedSolomon rs, Span<byte> working, ReadOnlySpan<byte> original,
        ReadOnlySpan<float> confidence, ReadOnlySpan<float> bitConfidence,
        (int Erasures, int MaxErrors)[] ladder, int chaseBits, int chaseErrorCap,
        out int erased, out int chased)
    {
        erased = 0;
        chased = 0;
        int corrected = rs.Decode(working);
        if (corrected >= 0 || (confidence.IsEmpty && bitConfidence.IsEmpty))
        {
            return corrected;
        }

        if (!bitConfidence.IsEmpty && chaseBits > 0)
        {
            // The chaseBits weakest bit positions, weakest first (partial selection sort -
            // salvage path, not a hot one).
            Span<int> weakBits = stackalloc int[chaseBits];
            int totalBits = original.Length * 8;
            for (int k = 0; k < chaseBits; k++)
            {
                int best = -1;
                for (int i = 0; i < totalBits; i++)
                {
                    if (weakBits[..k].Contains(i))
                    {
                        continue;
                    }

                    if (best < 0 || bitConfidence[i] < bitConfidence[best])
                    {
                        best = i;
                    }
                }

                weakBits[k] = best;
            }

            // Flip patterns in ascending flip count: one wrong bit is likelier than three.
            for (int flips = 1; flips <= chaseBits; flips++)
            {
                for (int mask = 1; mask < (1 << chaseBits); mask++)
                {
                    if (System.Numerics.BitOperations.PopCount((uint)mask) != flips)
                    {
                        continue;
                    }

                    original.CopyTo(working);
                    for (int k = 0; k < chaseBits; k++)
                    {
                        if ((mask & (1 << k)) != 0)
                        {
                            int bit = weakBits[k];
                            working[bit / 8] ^= (byte)(0x80 >> (bit % 8));
                        }
                    }

                    corrected = rs.Decode(working, [], chaseErrorCap);
                    if (corrected >= 0)
                    {
                        chased = flips;
                        return corrected;
                    }
                }
            }
        }

        if (confidence.IsEmpty)
        {
            original.CopyTo(working);
            return -1;
        }

        Span<int> weakest = stackalloc int[Il2pBlockLayout.ParitySymbolsPerBlock];
        foreach ((int erasureCount, int maxErrors) in ladder)
        {
            if (erasureCount > original.Length)
            {
                continue;
            }

            // Partial selection sort for the erasureCount lowest-confidence indices - the
            // block already failed, so this is a salvage path, not a hot one.
            Span<int> picks = weakest[..erasureCount];
            for (int k = 0; k < erasureCount; k++)
            {
                int best = -1;
                for (int i = 0; i < original.Length; i++)
                {
                    if (picks[..k].Contains(i))
                    {
                        continue;
                    }

                    if (best < 0 || confidence[i] < confidence[best])
                    {
                        best = i;
                    }
                }

                picks[k] = best;
            }

            original.CopyTo(working);
            corrected = rs.Decode(working, picks, maxErrors);
            if (corrected >= 0)
            {
                erased = erasureCount;
                return corrected;
            }
        }

        original.CopyTo(working);
        return -1;
    }
}
