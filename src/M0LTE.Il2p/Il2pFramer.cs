namespace M0LTE.Il2p;

/// <summary>
/// Builds the transmit-side IL2P bit stream: preamble, the 24-bit sync word, then the
/// encoded frame bytes most-significant-bit first (spec draft v0.6 § Packet Structure).
/// The preamble pattern depends on the physical layer: alternating bits for AFSK/FSK,
/// zeros for PSK (to cause carrier phase reversals). Back-to-back frames omit the
/// preamble but each keeps its sync word.
/// </summary>
public static class Il2pFramer
{
    /// <summary>Preamble styles per the spec's symbol-map recommendations.</summary>
    public enum PreambleStyle
    {
        /// <summary>Alternating 0/1 — AFSK and FSK links.</summary>
        Alternating,

        /// <summary>All zeros — BPSK/QPSK links (each zero is a phase reversal).</summary>
        Zeros,
    }

    /// <summary>Produces the logical bit stream for one frame.</summary>
    /// <param name="il2pWire">Encoded frame from <see cref="Il2pCodec.Encode"/>.</param>
    /// <param name="preambleBits">Preamble length in bits (0 for back-to-back frames).</param>
    /// <param name="style">Preamble bit pattern.</param>
    public static byte[] FrameBits(
        ReadOnlySpan<byte> il2pWire, int preambleBits, PreambleStyle style = PreambleStyle.Alternating)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(preambleBits);
        var bits = new byte[preambleBits + 24 + il2pWire.Length * 8];
        int position = 0;

        for (int i = 0; i < preambleBits; i++)
        {
            bits[position++] = style == PreambleStyle.Alternating ? (byte)(i & 1) : (byte)0;
        }

        for (int i = 23; i >= 0; i--)
        {
            bits[position++] = (byte)((Il2pCodec.SyncWord >> i) & 1);
        }

        foreach (byte value in il2pWire)
        {
            for (int i = 7; i >= 0; i--)
            {
                bits[position++] = (byte)((value >> i) & 1);
            }
        }

        return bits;
    }
}
