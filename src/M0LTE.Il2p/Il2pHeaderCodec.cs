namespace M0LTE.Il2p;

/// <summary>IL2P header type (spec draft v0.6 § IL2P Header Types).</summary>
public enum Il2pHeaderType
{
    /// <summary>Transparent encapsulation: the whole AX.25 frame travels in the payload.</summary>
    Type0 = 0,

    /// <summary>Translated encapsulation: a compressed AX.25 header in the 13-byte
    /// Control &amp; Addressing field.</summary>
    Type1 = 1,
}

/// <summary>
/// Builds and parses the 13-byte IL2P Control &amp; Addressing field (spec draft v0.6
/// § Control and Addressing Field Map). Field placement follows the spec exactly:
/// six-bit DEC SIXBIT callsign characters in bits 0–5 of bytes 0–11; UI in bit 6 of
/// byte 0; PID in bit 6 of bytes 1–4; CONTROL in bit 6 of bytes 5–11; RESERVED in
/// bit 7 of byte 0; header type in bit 7 of byte 1; the 10-bit payload byte count in
/// bit 7 of bytes 2–11 (MSB nearest the header start); byte 12 carries destination
/// SSID (high nibble) and source SSID (low nibble).
/// </summary>
internal static class Il2pHeaderCodec
{
    internal const int HeaderLength = 13;

    // IL2P 4-bit PID ↔ AX.25 8-bit PID (spec § IL2P AX.25 PID Code Mapping).
    // Nibble 2 covers the AX.25 "layer 3" patterns yy01yyyy / yy10yyyy and decodes to
    // the canonical 0x20 (lossy, matching Dire Wolf / NinoTNC behaviour).
    private static readonly byte[] PidNibbleToAx25 =
        [0xF0, 0xF0, 0x20, 0x01, 0x06, 0x07, 0x08, 0xF0, 0xF0, 0xF0, 0xF0, 0xCC, 0xCD, 0xCE, 0xCF, 0xF0];

    // AX.25 U-frame control opcodes (P/F bit masked out) indexed by the IL2P 3-bit opcode.
    private static readonly byte[] UOpcodeToControl = [0x2F, 0x43, 0x0F, 0x63, 0x87, 0x03, 0xAF, 0xE3];

    /// <summary>
    /// Attempts to translate an AX.25 frame's header into a Type 1 IL2P header.
    /// Returns false when the frame needs Type 0 transparent encapsulation instead
    /// (digipeater addressing, non-SIXBIT callsign characters, unmappable PID,
    /// SABME/unknown control, or a malformed header).
    /// </summary>
    internal static bool TryEncodeType1(
        ReadOnlySpan<byte> ax25Frame, Span<byte> header, bool legacyMaxFecBit, out int payloadOffset)
    {
        payloadOffset = 0;
        if (header.Length != HeaderLength)
        {
            throw new ArgumentException($"header must be {HeaderLength} bytes", nameof(header));
        }

        header.Clear();

        // Need dest(7) + src(7) + control, with no digipeaters (source address ends the list).
        if (ax25Frame.Length < 15 || (ax25Frame[6] & 0x01) != 0 || (ax25Frame[13] & 0x01) == 0)
        {
            return false;
        }

        for (int i = 0; i < 6; i++)
        {
            if (!TrySixbit(ax25Frame[i], out byte d) || !TrySixbit(ax25Frame[7 + i], out byte s))
            {
                return false;
            }

            header[i] = d;
            header[6 + i] = s;
        }

        int destSsid = (ax25Frame[6] >> 1) & 0xF;
        int srcSsid = (ax25Frame[13] >> 1) & 0xF;
        header[12] = (byte)((destSsid << 4) | srcSsid);

        // IL2P has a single C bit; copy the destination address C bit (v2.2: dst=1/src=0
        // command, dst=0/src=1 response; the degenerate equal-C cases map lossily).
        int command = ax25Frame[6] >> 7;

        byte control = ax25Frame[14];
        int pf = (control >> 4) & 1;

        if ((control & 0x01) == 0)
        {
            // I frame (modulo-8 assumed; modulo-128 sessions must use Type 0).
            if (ax25Frame.Length < 16 || !TryEncodePid(ax25Frame[15], out int pid))
            {
                return false;
            }

            int nr = control >> 5;
            int ns = (control >> 1) & 7;
            SetField(header, 6, 4, 4, pid);
            SetField(header, 6, 11, 7, (pf << 6) | (nr << 3) | ns);
            payloadOffset = 16;
        }
        else if ((control & 0x02) == 0)
        {
            // S frame: RR/RNR/REJ/SREJ. IL2P control = P/F N(R) C SS; PID nibble 0.
            int nr = control >> 5;
            int ss = (control >> 2) & 3;
            SetField(header, 6, 11, 7, (pf << 6) | (nr << 3) | (command << 2) | ss);
            payloadOffset = 15;
        }
        else
        {
            // U frame: 3-bit opcode; SABME and unknown opcodes are not representable.
            int opcode = Array.IndexOf(UOpcodeToControl, (byte)(control & 0xEF));
            if (opcode < 0)
            {
                return false;
            }

            if (opcode == 5)
            {
                // UI carries a PID and sets the UI bit.
                if (ax25Frame.Length < 16 || !TryEncodePid(ax25Frame[15], out int pid))
                {
                    return false;
                }

                SetField(header, 6, 0, 1, 1);
                SetField(header, 6, 4, 4, pid);
                payloadOffset = 16;
            }
            else
            {
                SetField(header, 6, 4, 4, 1); // PID nibble 1 = U frame without PID
                payloadOffset = 15;
            }

            SetField(header, 6, 11, 7, (pf << 6) | (opcode << 3) | (command << 2));
        }

        int payloadCount = ax25Frame.Length - payloadOffset;
        if (payloadCount > Il2pCodec.MaxPayloadBytes)
        {
            return false;
        }

        SetField(header, 7, 1, 1, 1); // header type 1
        // The RESERVED bit (bit 7 of byte 0) is the pre-v0.6 "max FEC" flag. Spec v0.6
        // reserves it (its example packets have it clear), but Dire Wolf's decoder — and
        // the NinoTNC lineage the flag came from — still select the parity plan from it:
        // clear means the legacy 2/4/6/8-parity payload blocks, so a cleared bit with
        // 16-parity blocks is rejected by those decoders. Interop therefore wants it set.
        SetField(header, 7, 0, 1, legacyMaxFecBit ? 1 : 0);
        SetField(header, 7, 11, 10, payloadCount);
        return true;
    }

    /// <summary>Builds a Type 0 (transparent) header: all fields zero except the
    /// payload byte count.</summary>
    internal static void EncodeType0(int payloadByteCount, Span<byte> header, bool legacyMaxFecBit)
    {
        ArgumentOutOfRangeException.ThrowIfGreaterThan(payloadByteCount, Il2pCodec.MaxPayloadBytes);
        ArgumentOutOfRangeException.ThrowIfLessThan(payloadByteCount, 1);
        header.Clear();
        SetField(header, 7, 0, 1, legacyMaxFecBit ? 1 : 0);
        SetField(header, 7, 11, 10, payloadByteCount);
    }

    /// <summary>Reads the header type bit from a descrambled header.</summary>
    internal static Il2pHeaderType GetHeaderType(ReadOnlySpan<byte> header) =>
        (Il2pHeaderType)GetField(header, 7, 1, 1);

    /// <summary>Reads the 10-bit payload byte count from a descrambled header.</summary>
    internal static int GetPayloadByteCount(ReadOnlySpan<byte> header) =>
        GetField(header, 7, 11, 10);

    /// <summary>
    /// Reconstructs the AX.25 header bytes (addresses, control, and PID when present)
    /// described by a descrambled Type 1 IL2P header. Returns false for field
    /// combinations no conforming encoder produces.
    /// </summary>
    internal static bool TryDecodeType1(ReadOnlySpan<byte> header, out byte[] ax25Header)
    {
        ax25Header = [];
        int ui = GetField(header, 6, 0, 1);
        int pid = GetField(header, 6, 4, 4);
        int control = GetField(header, 6, 11, 7);
        int pf = (control >> 6) & 1;

        byte ax25Control;
        byte? ax25Pid = null;
        int command;

        if (pid == 0 && ui == 0)
        {
            // S frame: control subfield = P/F N(R) C SS.
            int nr = (control >> 3) & 7;
            command = (control >> 2) & 1;
            int ss = control & 3;
            ax25Control = (byte)((nr << 5) | (pf << 4) | (ss << 2) | 0x01);
        }
        else if (pid == 1 && ui == 0)
        {
            // U frame without PID.
            int opcode = (control >> 3) & 7;
            if (opcode == 5)
            {
                return false; // UI opcode without the UI bit / PID
            }

            command = (control >> 2) & 1;
            ax25Control = (byte)(UOpcodeToControl[opcode] | (pf << 4));
        }
        else if (ui == 1)
        {
            if (pid < 2)
            {
                return false; // UI frames always carry a translatable PID
            }

            command = (control >> 2) & 1;
            ax25Control = (byte)(0x03 | (pf << 4));
            ax25Pid = PidNibbleToAx25[pid];
        }
        else
        {
            // I frame: control subfield = P/F N(R) N(S); always a command.
            int nr = (control >> 3) & 7;
            int ns = control & 7;
            command = 1;
            ax25Control = (byte)((nr << 5) | (pf << 4) | (ns << 1));
            ax25Pid = PidNibbleToAx25[pid];
        }

        var result = new byte[ax25Pid is null ? 15 : 16];
        for (int i = 0; i < 6; i++)
        {
            result[i] = (byte)((header[i] & 0x3F) + 0x20 << 1);
            result[7 + i] = (byte)((header[6 + i] & 0x3F) + 0x20 << 1);
        }

        int destSsid = header[12] >> 4;
        int srcSsid = header[12] & 0xF;
        result[6] = (byte)((command << 7) | 0x60 | (destSsid << 1));
        result[13] = (byte)(((command ^ 1) << 7) | 0x60 | (srcSsid << 1) | 0x01);
        result[14] = ax25Control;
        if (ax25Pid is byte p)
        {
            result[15] = p;
        }

        ax25Header = result;
        return true;
    }

    private static bool TrySixbit(byte addressByte, out byte sixbit)
    {
        // AX.25 address characters are ASCII shifted left one bit; SIXBIT covers 0x20–0x5F.
        int ch = addressByte >> 1;
        if (ch < 0x20 || ch > 0x5F || (addressByte & 0x01) != 0)
        {
            sixbit = 0;
            return false;
        }

        sixbit = (byte)(ch - 0x20);
        return true;
    }

    private static bool TryEncodePid(byte ax25Pid, out int nibble)
    {
        switch (ax25Pid)
        {
            case 0x01: nibble = 0x3; return true;
            case 0x06: nibble = 0x4; return true;
            case 0x07: nibble = 0x5; return true;
            case 0x08: nibble = 0x6; return true;
            case 0xCC: nibble = 0xB; return true;
            case 0xCD: nibble = 0xC; return true;
            case 0xCE: nibble = 0xD; return true;
            case 0xCF: nibble = 0xE; return true;
            case 0xF0: nibble = 0xF; return true;
            default:
                if ((ax25Pid & 0x30) == 0x10 || (ax25Pid & 0x30) == 0x20)
                {
                    nibble = 0x2; // AX.25 layer 3: yy01yyyy or yy10yyyy
                    return true;
                }

                nibble = 0;
                return false;
        }
    }

    /// <summary>Writes <paramref name="width"/> bits of <paramref name="value"/> into bit
    /// <paramref name="bit"/> of consecutive header bytes, least-significant bit at index
    /// <paramref name="lsbIndex"/>, walking toward byte 0 (spec: "MSB on the left").</summary>
    private static void SetField(Span<byte> header, int bit, int lsbIndex, int width, int value)
    {
        while (width > 0 && value != 0)
        {
            if ((value & 1) != 0)
            {
                header[lsbIndex] |= (byte)(1 << bit);
            }

            value >>= 1;
            lsbIndex--;
            width--;
        }
    }

    private static int GetField(ReadOnlySpan<byte> header, int bit, int lsbIndex, int width)
    {
        int result = 0;
        for (int i = lsbIndex - width + 1; i <= lsbIndex; i++)
        {
            result = (result << 1) | ((header[i] >> bit) & 1);
        }

        return result;
    }
}
