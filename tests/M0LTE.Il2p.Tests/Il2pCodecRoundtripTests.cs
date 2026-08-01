using M0LTE.Il2p;

namespace M0LTE.Il2p.Tests;

public class Il2pCodecRoundtripTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Random_Valid_Frames_Roundtrip(bool withCrc)
    {
        var random = new Random(20260714);
        for (int trial = 0; trial < 300; trial++)
        {
            byte[] frame = MakeRandomFrame(random);

            byte[] wire = Il2pCodec.Encode(frame, appendCrc: withCrc);
            bool ok = Il2pCodec.TryDecode(wire, hasTrailingCrc: withCrc, out byte[] decoded, out var info);

            ok.Should().BeTrue($"trial {trial}");
            decoded.Should().Equal(frame, $"trial {trial}");
            info.HeaderType.Should().Be(Il2pHeaderType.Type1, $"trial {trial}");
            if (withCrc)
            {
                info.CrcValid.Should().BeTrue($"trial {trial}");
            }
        }
    }

    [Fact]
    public void Multi_Block_Payloads_Roundtrip()
    {
        var random = new Random(42);
        foreach (int infoLength in new[] { 238, 239, 240, 241, 500, 700, 1007 })
        {
            byte[] frame = MakeUiFrame(random, infoLength);

            byte[] wire = Il2pCodec.Encode(frame, appendCrc: true);
            bool ok = Il2pCodec.TryDecode(wire, hasTrailingCrc: true, out byte[] decoded, out var info);

            ok.Should().BeTrue($"info length {infoLength}");
            decoded.Should().Equal(frame, $"info length {infoLength}");
            info.CrcValid.Should().BeTrue($"info length {infoLength}");
        }
    }

    [Fact]
    public void Digipeater_Addressing_Falls_Back_To_Type0_And_Roundtrips()
    {
        // dest, src (not end-of-address), one digipeater, UI control + PID + info.
        byte[] frame =
        [
            .. Address("KA2DEW", 2, last: false, cBit: 1),
            .. Address("KK4HEJ", 7, last: false, cBit: 0),
            .. Address("WIDE1", 1, last: true, cBit: 0),
            0x03, 0xF0, (byte)'h', (byte)'i',
        ];

        byte[] wire = Il2pCodec.Encode(frame, appendCrc: true);
        bool ok = Il2pCodec.TryDecode(wire, hasTrailingCrc: true, out byte[] decoded, out var info);

        ok.Should().BeTrue();
        info.HeaderType.Should().Be(Il2pHeaderType.Type0);
        decoded.Should().Equal(frame);
    }

    [Fact]
    public void Unmappable_Pid_Falls_Back_To_Type0()
    {
        byte[] frame = MakeUiFrame(new Random(7), 10);
        frame[15] = 0xCA; // not in the IL2P PID table, and not an AX.25 L3 pattern

        byte[] wire = Il2pCodec.Encode(frame, appendCrc: false);
        bool ok = Il2pCodec.TryDecode(wire, hasTrailingCrc: false, out byte[] decoded, out var info);

        ok.Should().BeTrue();
        info.HeaderType.Should().Be(Il2pHeaderType.Type0);
        decoded.Should().Equal(frame);
    }

    [Fact]
    public void Sabme_Falls_Back_To_Type0()
    {
        byte[] frame =
        [
            .. Address("KA2DEW", 2, last: false, cBit: 1),
            .. Address("KK4HEJ", 7, last: true, cBit: 0),
            0x7F, // SABME, P=1
        ];

        byte[] wire = Il2pCodec.Encode(frame, appendCrc: false);
        bool ok = Il2pCodec.TryDecode(wire, hasTrailingCrc: false, out byte[] decoded, out var info);

        ok.Should().BeTrue();
        info.HeaderType.Should().Be(Il2pHeaderType.Type0);
        decoded.Should().Equal(frame);
    }

    [Fact]
    public void Raw_Blob_Type0_At_Maximum_Size_Roundtrips()
    {
        var blob = new byte[1023];
        new Random(3).NextBytes(blob);
        blob[6] |= 0x01; // ensure it cannot parse as a translatable header

        byte[] wire = Il2pCodec.Encode(blob, appendCrc: true);
        bool ok = Il2pCodec.TryDecode(wire, hasTrailingCrc: true, out byte[] decoded, out var info);

        ok.Should().BeTrue();
        info.HeaderType.Should().Be(Il2pHeaderType.Type0);
        decoded.Should().Equal(blob);
        info.CrcValid.Should().BeTrue();
    }

    [Fact]
    public void Oversized_Frames_Are_Rejected()
    {
        var blob = new byte[1024];
        blob[6] |= 0x01;
        var act = () => Il2pCodec.Encode(blob, appendCrc: false);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Empty_Frames_Are_Rejected()
    {
        var act = () => Il2pCodec.Encode([], appendCrc: false);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Equal_C_Bits_Decode_As_The_Canonical_Response_Form()
    {
        // IL2P has one C bit, so dst=0/src=0 cannot be represented; it comes back as a
        // response (dst=0, src=1). This lossy mapping is called out by the spec's own
        // U-frame example discussion in Dire Wolf and matches its behaviour.
        byte[] frame =
        [
            .. Address("CQ", 0, last: false, cBit: 0),
            .. Address("KK4HEJ", 15, last: true, cBit: 0),
            0x03, 0xF0,
        ];

        byte[] wire = Il2pCodec.Encode(frame, appendCrc: false);
        bool ok = Il2pCodec.TryDecode(wire, hasTrailingCrc: false, out byte[] decoded, out _);

        ok.Should().BeTrue();
        byte[] expected = (byte[])frame.Clone();
        expected[13] |= 0x80; // source C bit asserted on the way back
        decoded.Should().Equal(expected);
    }

    private static byte[] MakeRandomFrame(Random random)
    {
        int kind = random.Next(3);
        bool command = random.Next(2) == 0;
        var dest = Address(RandomCall(random), random.Next(16), last: false, cBit: command ? 1 : 0);
        var src = Address(RandomCall(random), random.Next(16), last: true, cBit: command ? 0 : 1);

        byte[] mappablePids = [0x01, 0x06, 0x07, 0x08, 0xCC, 0xCD, 0xCE, 0xCF, 0xF0];
        switch (kind)
        {
            case 0: // I frame (always a command in the IL2P mapping)
            {
                dest = Address(RandomCall(random), random.Next(16), last: false, cBit: 1);
                src = Address(RandomCall(random), random.Next(16), last: true, cBit: 0);
                int nr = random.Next(8);
                int ns = random.Next(8);
                int pf = random.Next(2);
                byte control = (byte)((nr << 5) | (pf << 4) | (ns << 1));
                byte pid = mappablePids[random.Next(mappablePids.Length)];
                var information = new byte[random.Next(0, 257)];
                random.NextBytes(information);
                return [.. dest, .. src, control, pid, .. information];
            }

            case 1: // S frame
            {
                int nr = random.Next(8);
                int pf = random.Next(2);
                int ss = random.Next(4);
                byte control = (byte)((nr << 5) | (pf << 4) | (ss << 2) | 0x01);
                return [.. dest, .. src, control];
            }

            default: // U frame
            {
                byte[] opcodes = [0x2F, 0x43, 0x0F, 0x63, 0x87, 0x03, 0xAF, 0xE3];
                byte opcode = opcodes[random.Next(opcodes.Length)];
                int pf = random.Next(2);
                byte control = (byte)(opcode | (pf << 4));
                if (opcode == 0x03)
                {
                    byte pid = mappablePids[random.Next(mappablePids.Length)];
                    var information = new byte[random.Next(0, 257)];
                    random.NextBytes(information);
                    return [.. dest, .. src, control, pid, .. information];
                }

                return [.. dest, .. src, control];
            }
        }
    }

    private static byte[] MakeUiFrame(Random random, int infoLength)
    {
        var information = new byte[infoLength];
        random.NextBytes(information);
        return
        [
            .. Address("KA2DEW", 2, last: false, cBit: 1),
            .. Address("KK4HEJ", 7, last: true, cBit: 0),
            0x03, 0xF0, .. information,
        ];
    }

    private static string RandomCall(Random random)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        int length = random.Next(3, 7);
        return new string([.. Enumerable.Range(0, length).Select(_ => alphabet[random.Next(alphabet.Length)])]);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(1, 1)]
    public void Equal_C_Bits_With_Crc_Fall_Back_To_Type0_And_Roundtrip(int destC, int srcC)
    {
        // The trailing CRC is computed over the original frame but checked against the
        // receiver's reconstruction, so the lossy equal-C Type 1 mapping would fail it on
        // every such frame (NinoTNC il2p_crc semantics then drop the frame). Under CRC the
        // encoder must take Type 0, which reproduces the frame byte-exactly.
        byte[] frame =
        [
            .. Address("QST", 0, last: false, cBit: destC),
            .. Address("M0LTE", 1, last: true, cBit: srcC),
            0x03, 0xF0, (byte)'h', (byte)'i',
        ];

        byte[] wire = Il2pCodec.Encode(frame, appendCrc: true);
        bool ok = Il2pCodec.TryDecode(wire, hasTrailingCrc: true, out byte[] decoded, out var info);

        ok.Should().BeTrue();
        decoded.Should().Equal(frame);
        info.HeaderType.Should().Be(Il2pHeaderType.Type0);
        info.CrcValid.Should().BeTrue();
    }

    [Fact]
    public void Proper_Command_Response_Frames_With_Crc_Stay_Type1()
    {
        foreach ((int destC, int srcC) in new[] { (1, 0), (0, 1) })
        {
            byte[] frame =
            [
                .. Address("QST", 0, last: false, cBit: destC),
                .. Address("M0LTE", 1, last: true, cBit: srcC),
                0x03, 0xF0, (byte)'h', (byte)'i',
            ];

            byte[] wire = Il2pCodec.Encode(frame, appendCrc: true);
            bool ok = Il2pCodec.TryDecode(wire, hasTrailingCrc: true, out byte[] decoded, out var info);

            ok.Should().BeTrue($"C bits {destC}/{srcC}");
            decoded.Should().Equal(frame, $"C bits {destC}/{srcC}");
            info.HeaderType.Should().Be(Il2pHeaderType.Type1, $"C bits {destC}/{srcC}");
            info.CrcValid.Should().BeTrue($"C bits {destC}/{srcC}");
        }
    }

    [Fact]
    public void Lossy_Layer3_Pid_With_Crc_Falls_Back_To_Type0()
    {
        // The layer-3 PID group canonicalises to 0x20 on decode: 0x10 is lossy (must
        // fall back under CRC), 0x20 is its own canonical form (Type 1 stays exact).
        static byte[] IFrame(byte pid) =>
        [
            .. Address("QST", 0, last: false, cBit: 1),
            .. Address("M0LTE", 1, last: true, cBit: 0),
            0x00, pid, (byte)'h', (byte)'i',
        ];

        byte[] lossyWire = Il2pCodec.Encode(IFrame(0x10), appendCrc: true);
        Il2pCodec.TryDecode(lossyWire, hasTrailingCrc: true, out byte[] lossyDecoded, out var lossyInfo)
            .Should().BeTrue();
        lossyDecoded.Should().Equal(IFrame(0x10));
        lossyInfo.HeaderType.Should().Be(Il2pHeaderType.Type0);
        lossyInfo.CrcValid.Should().BeTrue();

        byte[] exactWire = Il2pCodec.Encode(IFrame(0x20), appendCrc: true);
        Il2pCodec.TryDecode(exactWire, hasTrailingCrc: true, out byte[] exactDecoded, out var exactInfo)
            .Should().BeTrue();
        exactDecoded.Should().Equal(IFrame(0x20));
        exactInfo.HeaderType.Should().Be(Il2pHeaderType.Type1);
        exactInfo.CrcValid.Should().BeTrue();
    }

    private static byte[] Address(string callsign, int ssid, bool last, int cBit)
    {
        var bytes = new byte[7];
        for (int i = 0; i < 6; i++)
        {
            char c = i < callsign.Length ? callsign[i] : ' ';
            bytes[i] = (byte)(c << 1);
        }

        bytes[6] = (byte)((cBit << 7) | 0x60 | (ssid << 1) | (last ? 1 : 0));
        return bytes;
    }
}
