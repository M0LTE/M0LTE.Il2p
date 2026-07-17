namespace M0LTE.Il2p;

/// <summary>
/// Segmentation of an IL2P payload into Reed-Solomon code blocks, per the spec's
/// Payload Block Size Computations (draft v0.6): payloads are split into
/// ceil(count / 239) nearly-equal blocks, larger blocks first, and every payload
/// block carries exactly 16 RS parity symbols.
/// </summary>
public readonly record struct Il2pBlockLayout
{
    /// <summary>RS parity symbols appended to every payload block.</summary>
    public const int ParitySymbolsPerBlock = 16;

    /// <summary>Largest number of data bytes a single RS block can carry (255 - 16 parity).</summary>
    public const int MaxBlockDataSize = 239;

    private Il2pBlockLayout(int payloadByteCount, int blockCount, int smallBlockSize, int largeBlockCount)
    {
        PayloadByteCount = payloadByteCount;
        BlockCount = blockCount;
        SmallBlockSize = smallBlockSize;
        LargeBlockCount = largeBlockCount;
    }

    /// <summary>Total payload data bytes across all blocks (0–1023).</summary>
    public int PayloadByteCount { get; }

    /// <summary>Number of payload blocks (0 when the payload is empty).</summary>
    public int BlockCount { get; }

    /// <summary>Data bytes in each small block.</summary>
    public int SmallBlockSize { get; }

    /// <summary>Data bytes in each large block (<see cref="SmallBlockSize"/> + 1).</summary>
    public int LargeBlockSize => SmallBlockSize + 1;

    /// <summary>Number of large blocks; these are transmitted closest to the header.</summary>
    public int LargeBlockCount { get; }

    /// <summary>Number of small blocks, transmitted after the large blocks.</summary>
    public int SmallBlockCount => BlockCount - LargeBlockCount;

    /// <summary>Bytes the payload occupies on the wire, including per-block parity.</summary>
    public int WireLength => PayloadByteCount + BlockCount * ParitySymbolsPerBlock;

    /// <summary>Computes the layout for a payload of <paramref name="payloadByteCount"/> bytes.</summary>
    public static Il2pBlockLayout Compute(int payloadByteCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(payloadByteCount);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(payloadByteCount, Il2pCodec.MaxPayloadBytes);

        if (payloadByteCount == 0)
        {
            return new Il2pBlockLayout(0, 0, 0, 0);
        }

        int blockCount = (payloadByteCount + MaxBlockDataSize - 1) / MaxBlockDataSize;
        int smallBlockSize = payloadByteCount / blockCount;
        int largeBlockCount = payloadByteCount - blockCount * smallBlockSize;
        return new Il2pBlockLayout(payloadByteCount, blockCount, smallBlockSize, largeBlockCount);
    }
}
