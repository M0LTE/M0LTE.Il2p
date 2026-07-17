using M0LTE.Il2p;

namespace M0LTE.Il2p.Tests;

/// <summary>
/// The three example encoded packets from IL2P spec draft v0.6 (provided by G4KLX):
/// AX.25 bytes lack flags and FCS and are not bit-stuffed; IL2P bytes include the
/// trailing CRC and lack the sync word.
/// </summary>
public class Il2pSpecVectorTests
{
    public static TheoryData<string, string, string> Vectors => new()
    {
        // name, AX.25 hex, IL2P hex
        {
            "S-frame KA2DEW-2>KK4HEJ-7 RR",
            "968264888AAEE4969668908A946F81",
            "26574D57F1D2A8F06AF27BAD23BDC07F001D2B"
        },
        {
            "UI-frame CQ>KK4HEJ-15",
            "86A24040404060969668908A94FF03F0",
            "6AEA9CC20111FC141FDA6EF25391BD476C5454"
        },
        {
            "I-frame KA2DEW-2>KK4HEJ-2 TheNET",
            "968264888AAEE4969668908A9465B8CF303132333435363738",
            "26136D028CFEFBE8AA942D6A3443353C699F0C755A38A17FA5DAD8F6EA57373DB12AB0DE44A820D01D5A2B38"
        },
    };

    [Theory]
    [MemberData(nameof(Vectors))]
    public void Encode_Is_Byte_Exact_Against_The_Spec(string name, string ax25Hex, string il2pHex)
    {
        byte[] ax25 = Convert.FromHexString(ax25Hex);

        byte[] encoded = Il2pCodec.Encode(ax25, appendCrc: true, legacyMaxFecBit: false);

        Convert.ToHexString(encoded).Should().Be(il2pHex.ToUpperInvariant(), name);
    }

    [Theory]
    [MemberData(nameof(Vectors))]
    public void Decode_Recovers_The_Original_Ax25_Frame(string name, string ax25Hex, string il2pHex)
    {
        byte[] il2p = Convert.FromHexString(il2pHex);

        bool ok = Il2pCodec.TryDecode(il2p, hasTrailingCrc: true, out byte[] ax25, out var info);

        ok.Should().BeTrue(name);
        Convert.ToHexString(ax25).Should().Be(ax25Hex.ToUpperInvariant(), name);
        info.HeaderType.Should().Be(Il2pHeaderType.Type1, name);
        info.CorrectedSymbols.Should().Be(0, name);
        info.CrcValid.Should().BeTrue(name);
    }

    [Fact]
    public void Header_Decode_Reports_Type_And_Payload_Count()
    {
        byte[] il2p = Convert.FromHexString(
            "26136D028CFEFBE8AA942D6A3443353C699F0C755A38A17FA5DAD8F6EA57373DB12AB0DE44A820D01D5A2B38");

        bool ok = Il2pCodec.TryDecodeHeader(
            il2p, out var headerType, out int payloadByteCount, out int corrected);

        ok.Should().BeTrue();
        headerType.Should().Be(Il2pHeaderType.Type1);
        payloadByteCount.Should().Be(9);
        corrected.Should().Be(0);
    }

    [Fact]
    public void A_Corrupted_Header_Byte_Is_Repaired()
    {
        byte[] il2p = Convert.FromHexString(
            "26136D028CFEFBE8AA942D6A3443353C699F0C755A38A17FA5DAD8F6EA57373DB12AB0DE44A820D01D5A2B38");
        il2p[4] ^= 0x5A;

        bool ok = Il2pCodec.TryDecode(il2p, hasTrailingCrc: true, out byte[] ax25, out var info);

        ok.Should().BeTrue();
        Convert.ToHexString(ax25).Should().Be("968264888AAEE4969668908A9465B8CF303132333435363738");
        info.CorrectedSymbols.Should().Be(1);
        info.CrcValid.Should().BeTrue();
    }

    [Fact]
    public void Eight_Corrupted_Payload_Bytes_Are_Repaired()
    {
        byte[] il2p = Convert.FromHexString(
            "26136D028CFEFBE8AA942D6A3443353C699F0C755A38A17FA5DAD8F6EA57373DB12AB0DE44A820D01D5A2B38");
        for (int i = 0; i < 8; i++)
        {
            il2p[15 + i * 3] ^= (byte)(0x11 + i); // spread across the 25-byte payload block
        }

        bool ok = Il2pCodec.TryDecode(il2p, hasTrailingCrc: true, out byte[] ax25, out var info);

        ok.Should().BeTrue();
        Convert.ToHexString(ax25).Should().Be("968264888AAEE4969668908A9465B8CF303132333435363738");
        info.CorrectedSymbols.Should().Be(8);
        info.CrcValid.Should().BeTrue();
    }

    [Fact]
    public void Single_Bit_Errors_In_The_Crc_Trailer_Are_Absorbed_By_Hamming()
    {
        byte[] il2p = Convert.FromHexString("26574D57F1D2A8F06AF27BAD23BDC07F001D2B");
        il2p[^4] ^= 0x01;
        il2p[^2] ^= 0x40;

        bool ok = Il2pCodec.TryDecode(il2p, hasTrailingCrc: true, out _, out var info);

        ok.Should().BeTrue();
        info.CrcValid.Should().BeTrue();
    }

    [Fact]
    public void Decoding_Without_Crc_Expectation_Rejects_The_Length_Mismatch()
    {
        byte[] il2p = Convert.FromHexString("26574D57F1D2A8F06AF27BAD23BDC07F001D2B");

        Il2pCodec.TryDecode(il2p, hasTrailingCrc: false, out _, out _).Should().BeFalse();
    }
}
