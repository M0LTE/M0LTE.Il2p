using M0LTE.Il2p;

namespace M0LTE.Il2p.Tests;

/// <summary>
/// Confidence-aware decoding: when a Reed-Solomon block fails errors-only decoding, the
/// weakest bytes are retried as erasures - up to twice the correction span when the
/// receiver's confidence flags cover the damage. These tests drive both the codec surface
/// and the deframer's bit-level confidence plumbing.
/// </summary>
public class Il2pErasureTests
{
    private static byte[] TestFrame()
    {
        // A Type 0 frame with a payload comfortably inside one 16-parity block.
        var ax25 = new byte[80];
        new Random(42).NextBytes(ax25);
        ax25[0] = 0x8E; // keep the lead byte a plausible address character either way
        return ax25;
    }

    [Fact]
    public void Twelve_Damaged_Bytes_In_One_Block_Recover_When_Flagged()
    {
        // Errors-only tops out at 8 per block; 12 flagged damaged bytes decode via the
        // 14-erasure rung (the 2 healthy bytes it also erases cost budget, not correctness).
        byte[] ax25 = TestFrame();
        byte[] wire = Il2pCodec.Encode(ax25, appendCrc: true);
        var confidence = new float[wire.Length];
        Array.Fill(confidence, 1f);
        var random = new Random(7);
        for (int i = 0; i < 12; i++)
        {
            int position = Il2pCodec.HeaderWireLength + 2 + (i * 5);
            wire[position] ^= (byte)random.Next(1, 256);
            confidence[position] = 0.1f;
        }

        Il2pCodec.TryDecode(wire, hasTrailingCrc: true, out _, out _)
            .Should().BeFalse("twelve errors exceed the errors-only budget");

        Il2pCodec.TryDecode(wire, hasTrailingCrc: true, confidence, out byte[] decoded, out var info)
            .Should().BeTrue("the confidence flags cover the damage");
        decoded.Should().Equal(ax25);
        info.CrcValid.Should().BeTrue();
        info.ErasedSymbols.Should().Be(14, "the top rung erases 14 with no error tolerance, "
            + "and the flags cover all the damage");
        info.CorrectedSymbols.Should().Be(12, "only the genuinely damaged bytes changed");
    }

    [Fact]
    public void The_Ladder_Steps_Down_When_Some_Damage_Is_Unflagged()
    {
        // Ten flagged plus two unflagged damaged bytes: the 14- and 12-erasure rungs cannot
        // cover the unflagged pair within their error caps and are refused by the reserved
        // check symbols; the (10 erasures, 2 errors) rung fits exactly.
        byte[] ax25 = TestFrame();
        byte[] wire = Il2pCodec.Encode(ax25, appendCrc: true);
        var confidence = new float[wire.Length];
        Array.Fill(confidence, 1f);
        var random = new Random(11);
        for (int i = 0; i < 10; i++)
        {
            int position = Il2pCodec.HeaderWireLength + (i * 3);
            wire[position] ^= (byte)random.Next(1, 256);
            confidence[position] = 0.1f;
        }

        // The unflagged pair sits at the block's tail so the tied-confidence healthy picks
        // (taken in index order) cannot accidentally cover them.
        foreach (int position in new[] { wire.Length - 6, wire.Length - 5 })
        {
            wire[position] ^= (byte)random.Next(1, 256);
        }

        Il2pCodec.TryDecode(wire, hasTrailingCrc: true, confidence, out byte[] decoded, out var info)
            .Should().BeTrue();
        decoded.Should().Equal(ax25);
        info.ErasedSymbols.Should().Be(10, "the ladder walks down to the rung whose error cap "
            + "covers the unflagged pair");
        info.CorrectedSymbols.Should().Be(12);
    }

    [Fact]
    public void Header_Damage_Is_Never_Rescued_By_Erasures()
    {
        // Deliberate: the header's 2-parity code affords no speculative erasures - a rung
        // spending both parity symbols is pure interpolation and would accept hallucinated
        // headers that size bogus collections. Two damaged header bytes stay fatal however
        // confidently they are flagged; the header's future is CRC-arbitrated chase, not
        // erasures.
        byte[] ax25 = TestFrame();
        byte[] wire = Il2pCodec.Encode(ax25, appendCrc: true);
        var confidence = new float[wire.Length];
        Array.Fill(confidence, 1f);
        wire[3] ^= 0x41;
        wire[9] ^= 0x0F;
        confidence[3] = 0.2f;
        confidence[9] = 0.1f;

        Il2pCodec.TryDecode(wire, hasTrailingCrc: true, confidence, out _, out _)
            .Should().BeFalse("the header ladder is empty by design");
    }

    [Fact]
    public void The_Deframer_Carries_Bit_Confidence_Into_Byte_Erasures()
    {
        // End to end through the bit stream: a burst of damage beyond the errors-only
        // budget decodes when the damaged bits arrive with low confidence, and does not
        // when the same bits arrive hard. A byte's confidence is the minimum of its bits',
        // so flagging one bit of a byte is enough to mark the byte.
        byte[] ax25 = TestFrame();
        byte[] wire = Il2pCodec.Encode(ax25, appendCrc: true);
        var damaged = (byte[])wire.Clone();
        var byteConfidence = new float[wire.Length];
        Array.Fill(byteConfidence, 1f);
        var random = new Random(13);
        for (int i = 0; i < 12; i++)
        {
            int position = Il2pCodec.HeaderWireLength + 1 + (i * 4);
            damaged[position] ^= (byte)random.Next(1, 256);
            byteConfidence[position] = 0.1f;
        }

        List<byte[]> Run(bool withConfidence)
        {
            var received = new List<byte[]>();
            var deframer = new Il2pDeframer((frame, _) => received.Add(frame), crcMode: true);
            foreach (int bit in Sync())
            {
                deframer.PushBit(bit);
            }

            for (int i = 0; i < damaged.Length; i++)
            {
                for (int b = 0; b < 8; b++)
                {
                    int bit = (damaged[i] >> (7 - b)) & 1;
                    // Flag only the byte's first bit: min-aggregation must mark the byte.
                    float confidence = withConfidence && b == 0 ? byteConfidence[i] : 1f;
                    deframer.PushBit(bit, confidence);
                }
            }

            return received;
        }

        Run(withConfidence: false).Should().BeEmpty("hard decisions cannot cross the errors-only budget");
        Run(withConfidence: true).Should().ContainSingle().Which.Should().Equal(ax25);
    }

    private static IEnumerable<int> Sync()
    {
        for (int i = 0; i < 24; i++)
        {
            yield return (Il2pCodec.SyncWord >> (23 - i)) & 1;
        }
    }
}
