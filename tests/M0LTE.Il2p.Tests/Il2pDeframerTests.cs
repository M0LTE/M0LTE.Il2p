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
        // At least one: the backtracking re-hunt may find further near-sync images inside
        // the corrupted bits and legitimately count their failed collections too.
        deframer.RsFailures.Should().BeGreaterThanOrEqualTo(1);
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

    [Fact]
    public void A_Frame_Inside_A_Failed_Garbage_Collection_Is_Recovered()
    {
        // A false sync followed by garbage starts a bogus header collection; the real
        // frame's own sync lands inside those 15 bytes. A non-backtracking deframer
        // consumes the real sync as bogus header bytes and loses the frame.
        byte[] ax25 = Convert.FromHexString("968264888AAEE4969668908A946F81");
        byte[] wire = Il2pCodec.Encode(ax25, appendCrc: true);

        var received = new List<byte[]>();
        var deframer = new Il2pDeframer((frame, _) => received.Add(frame), crcMode: true);

        // Self-calibrating garbage: the bogus header the deframer will assemble is the 5
        // garbage bytes + the 3 real sync bytes + the first 7 wire bytes. Pick a first
        // garbage byte that makes that 15-byte header fail RS, so the bogus collection is
        // guaranteed to fail (a header that happened to pass would stall in body
        // collection instead, which is a different scenario, covered separately).
        byte[] syncBytes = [0xF1, 0x5E, 0x48];
        byte[] garbageHeaderStart = [0x00, 0x00, 0xAA, 0x55, 0xF0];
        for (int candidate = 0; candidate < 256; candidate++)
        {
            garbageHeaderStart[0] = (byte)candidate;
            byte[] bogus = [.. garbageHeaderStart, .. syncBytes, .. wire[..7]];
            if (!Il2pCodec.TryDecodeHeader(bogus, out _, out _, out _))
            {
                break;
            }
        }

        foreach (int bit in SyncBits()
                     .Concat(ToBits(garbageHeaderStart))
                     .Concat(SyncBits())
                     .Concat(ToBits(wire)))
        {
            deframer.PushBit(bit);
        }

        received.Should().ContainSingle().Which.Should().Equal(ax25);
    }

    [Fact]
    public void A_Frame_Inside_A_Header_Passing_Garbage_Body_Is_Recovered()
    {
        // Worse case: the bogus collection's header passes RS (here: a REAL header for a
        // large frame, truncated), committing the deframer to collect a large body — and
        // the real frame transmits entirely inside that span. Backtracking recovers it
        // after the bogus body fails RS.
        byte[] bigFrame = new byte[300];
        Convert.FromHexString("968264888AAEE4969668908A946F81").CopyTo(bigFrame, 0);
        byte[] bigWire = Il2pCodec.Encode(bigFrame, appendCrc: true);

        byte[] ax25 = Convert.FromHexString("86A24040404060969668908A94E103F0");
        byte[] wire = Il2pCodec.Encode(ax25, appendCrc: true);

        var received = new List<byte[]>();
        var deframer = new Il2pDeframer((frame, _) => received.Add(frame), crcMode: true);
        // Enough filler that the bogus collection COMPLETES (its expected length is the
        // big frame's full wire size) and fails body RS — only then does the deframer
        // backtrack and recover the real frame from inside the failed span.
        int bogusExpected = bigWire.Length;
        int fedInsideBogus = 40 + 3 + wire.Length; // truncated body + real sync + real frame
        int fillerBytes = bogusExpected - Il2pCodec.HeaderWireLength - fedInsideBogus + 8;
        foreach (int bit in SyncBits()
                     .Concat(ToBits(bigWire.AsSpan(0, Il2pCodec.HeaderWireLength + 40).ToArray()))
                     .Concat(SyncBits())
                     .Concat(ToBits(wire))
                     .Concat(ToBits(new byte[fillerBytes])))
        {
            deframer.PushBit(bit);
        }

        received.Should().ContainSingle().Which.Should().Equal(ax25);
        deframer.RsFailures.Should().BeGreaterThan(0);
    }

    [Fact]
    public void A_Frame_After_Ones_Biased_Garbage_Decodes()
    {
        // Idle-channel garbage from a railed 4-level slicer is ~75% ones, and the C4FSK
        // sync is 18/24 ones — false near-syncs are dense, so a gate-less receiver leans
        // entirely on backtracking to stay live. No false frames may emerge either.
        var random = new Random(20260801);
        byte[] ax25 = Convert.FromHexString("968264888AAEE4969668908A946F81");
        byte[] wire = Il2pCodec.Encode(ax25, appendCrc: true);
        int c4Sync = 0x57DF7F;

        var received = new List<byte[]>();
        var deframer = new Il2pDeframer((frame, _) => received.Add(frame), crcMode: true, syncWord: c4Sync);
        for (int i = 0; i < 100_000; i++)
        {
            deframer.PushBit(random.NextDouble() < 0.75 ? 1 : 0);
        }

        foreach (int bit in Enumerable.Range(0, 24).Select(i => (c4Sync >> (23 - i)) & 1)
                     .Concat(ToBits(wire)))
        {
            deframer.PushBit(bit);
        }

        received.Should().ContainSingle().Which.Should().Equal(ax25);
    }
}
