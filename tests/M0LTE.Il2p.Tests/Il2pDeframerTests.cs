using M0LTE.Il2p;

namespace M0LTE.Il2p.Tests;

public class Il2pDeframerTests
{
    private static IEnumerable<int> ToBits(IEnumerable<byte> bytes) =>
        bytes.SelectMany(b => Enumerable.Range(0, 8).Select(i => (b >> (7 - i)) & 1));

    private static IEnumerable<int> SyncBits(int flippedBit = -1)
    {
        for (int i = 0; i < 24; i++)
        {
            int bit = (Il2pCodec.SyncWord >> (23 - i)) & 1;
            yield return i == flippedBit ? bit ^ 1 : bit;
        }
    }

    [Fact]
    public void A_Spec_Vector_Frame_Decodes_From_The_Bit_Stream()
    {
        byte[] ax25 = Convert.FromHexString("968264888AAEE4969668908A946F81");
        byte[] wire = Il2pCodec.Encode(ax25, appendCrc: true);

        var received = new List<byte[]>();
        var deframer = new Il2pDeframer((frame, _) => received.Add(frame), crcMode: true);
        // Preamble of alternating bits, sync word, frame.
        foreach (int bit in Enumerable.Repeat(new[] { 0, 1 }, 32).SelectMany(x => x)
                     .Concat(SyncBits())
                     .Concat(ToBits(wire)))
        {
            deframer.PushBit(bit);
        }

        received.Should().ContainSingle().Which.Should().Equal(ax25);
    }

    [Fact]
    public void A_Single_Bit_Error_In_The_Sync_Word_Is_Tolerated()
    {
        byte[] ax25 = Convert.FromHexString("86A24040404060969668908A94FF03F0");
        byte[] wire = Il2pCodec.Encode(ax25, appendCrc: false);

        var received = new List<byte[]>();
        var deframer = new Il2pDeframer((frame, _) => received.Add(frame), crcMode: false);
        foreach (int bit in SyncBits(flippedBit: 11).Concat(ToBits(wire)))
        {
            deframer.PushBit(bit);
        }

        received.Should().ContainSingle().Which.Should().Equal(ax25);
    }

    [Fact]
    public void Back_To_Back_Frames_Without_Preamble_Both_Decode()
    {
        // Spec: when packets are sent back-to-back, the preamble of subsequent packets is
        // omitted; each still has its own sync word.
        byte[] first = Convert.FromHexString("968264888AAEE4969668908A946F81");
        byte[] second = Convert.FromHexString("968264888AAEE4969668908A9465B8CF303132333435363738");

        var received = new List<byte[]>();
        var deframer = new Il2pDeframer((frame, _) => received.Add(frame), crcMode: true);
        foreach (int bit in SyncBits().Concat(ToBits(Il2pCodec.Encode(first, appendCrc: true)))
                     .Concat(SyncBits()).Concat(ToBits(Il2pCodec.Encode(second, appendCrc: true))))
        {
            deframer.PushBit(bit);
        }

        received.Should().HaveCount(2);
        received[0].Should().Equal(first);
        received[1].Should().Equal(second);
    }

    [Fact]
    public void Corrupted_Payload_Within_Fec_Capacity_Still_Decodes()
    {
        byte[] ax25 = Convert.FromHexString("968264888AAEE4969668908A9465B8CF303132333435363738");
        byte[] wire = Il2pCodec.Encode(ax25, appendCrc: true);
        wire[20] ^= 0xFF;
        wire[25] ^= 0x0F;

        var received = new List<(byte[] Frame, Il2pDecodeInfo Info)>();
        var deframer = new Il2pDeframer((frame, info) => received.Add((frame, info)), crcMode: true);
        foreach (int bit in SyncBits().Concat(ToBits(wire)))
        {
            deframer.PushBit(bit);
        }

        received.Should().ContainSingle();
        received[0].Frame.Should().Equal(ax25);
        received[0].Info.CorrectedSymbols.Should().Be(2);
    }

    [Fact]
    public void An_Unrecoverable_Header_Counts_As_An_Rs_Failure()
    {
        byte[] wire = Il2pCodec.Encode(
            Convert.FromHexString("968264888AAEE4969668908A946F81"), appendCrc: true);
        wire[1] ^= 0xA5;
        wire[7] ^= 0x5A; // two header errors, beyond the 2-parity header code's capacity

        var received = new List<byte[]>();
        var deframer = new Il2pDeframer((frame, _) => received.Add(frame), crcMode: true);
        foreach (int bit in SyncBits().Concat(ToBits(wire)))
        {
            deframer.PushBit(bit);
        }

        received.Should().BeEmpty();
        deframer.RsFailures.Should().Be(1);
    }

    [Fact]
    public void Random_Noise_Produces_No_Frames()
    {
        var random = new Random(20260714);
        var received = new List<byte[]>();
        var deframer = new Il2pDeframer((frame, _) => received.Add(frame), crcMode: true);
        for (int i = 0; i < 200_000; i++)
        {
            deframer.PushBit(random.Next(2));
        }

        received.Should().BeEmpty();
    }
}
