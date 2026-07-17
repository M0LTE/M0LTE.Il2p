namespace M0LTE.Il2p;

/// <summary>
/// IL2P packet-synchronous multiplicative scrambling (spec draft v0.6 § Data Scrambling):
/// a Galois-configured LFSR with feedback polynomial x⁹ + x⁴ + 1, reset to fixed initial
/// conditions at the start of every header and payload block. The Galois arrangement has a
/// 5-bit delay, so the transmit side discards the first 5 output bits and flushes 5 zero-fed
/// bits at the end of each block — output length equals input length. Bit-exact against the
/// spec's example packets (initial states 0x00F transmit / 0x1F0 receive match the spec's
/// schematic figures as implemented by Dire Wolf and NinoTNC).
/// </summary>
public static class Il2pScrambler
{
    private const int InitialTxState = 0x00F;
    private const int InitialRxState = 0x1F0;

    /// <summary>Scrambles one block. <paramref name="output"/> must be the same length as
    /// <paramref name="input"/>. Bits are processed most-significant first.</summary>
    public static void Scramble(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (output.Length != input.Length)
        {
            throw new ArgumentException("output must be the same length as input", nameof(output));
        }

        output.Clear();
        int state = InitialTxState;
        int outBit = 0;
        bool skipping = true;

        for (int ib = 0; ib < input.Length; ib++)
        {
            for (int mask = 0x80; mask != 0; mask >>= 1)
            {
                int s = ScrambleBit((input[ib] & mask) != 0 ? 1 : 0, ref state);
                if (ib == 0 && mask == 0x04)
                {
                    skipping = false; // the Galois LFSR's 5-bit delay has elapsed
                }

                if (!skipping)
                {
                    if (s != 0)
                    {
                        output[outBit >> 3] |= (byte)(0x80 >> (outBit & 7));
                    }

                    outBit++;
                }
            }
        }

        for (int n = 0; n < 5; n++)
        {
            int s = ScrambleBit(0, ref state);
            if (s != 0)
            {
                output[outBit >> 3] |= (byte)(0x80 >> (outBit & 7));
            }

            outBit++;
        }
    }

    /// <summary>Descrambles one block in place. The receive LFSR has no bit delay, so this is
    /// a straight bit-for-bit transform. Bits are processed most-significant first.</summary>
    public static void Descramble(Span<byte> block)
    {
        int state = InitialRxState;
        for (int ib = 0; ib < block.Length; ib++)
        {
            byte result = 0;
            for (int mask = 0x80; mask != 0; mask >>= 1)
            {
                int inBit = (block[ib] & mask) != 0 ? 1 : 0;
                int outBit = (inBit ^ state) & 1;
                state = ((state >> 1) | (inBit << 8)) ^ (inBit << 3);
                if (outBit != 0)
                {
                    result |= (byte)mask;
                }
            }

            block[ib] = result;
        }
    }

    private static int ScrambleBit(int inBit, ref int state)
    {
        int outBit = ((state >> 4) ^ state) & 1;
        state = ((((inBit ^ state) & 1) << 9) | (state ^ ((state & 1) << 4))) >> 1;
        return outBit;
    }
}
