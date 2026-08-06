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

    [Fact]
    public void One_Chased_Bit_Rescues_A_Block_One_Error_Past_The_Budget()
    {
        // Nine damaged bytes against an errors-only budget of eight - but one of them is a
        // single flipped bit the receiver's confidence fingers exactly. Chase flips it back
        // for free, the remaining eight fit the budget, and neither erasure spends a symbol.
        byte[] ax25 = TestFrame();
        byte[] wire = Il2pCodec.Encode(ax25, appendCrc: true);
        var bitConfidence = new float[wire.Length * 8];
        Array.Fill(bitConfidence, 1f);
        var random = new Random(17);
        for (int i = 0; i < 8; i++)
        {
            int position = Il2pCodec.HeaderWireLength + 3 + (i * 6);
            wire[position] ^= (byte)random.Next(1, 256);   // deep damage, unflagged
        }

        int flippedBit = ((Il2pCodec.HeaderWireLength + 60) * 8) + 5;
        wire[flippedBit / 8] ^= (byte)(0x80 >> (flippedBit % 8));
        bitConfidence[flippedBit] = 0.05f;

        Il2pCodec.TryDecode(wire, hasTrailingCrc: true, out _, out _)
            .Should().BeFalse("nine errors exceed the errors-only budget");

        Il2pCodec.TryDecode(wire, hasTrailingCrc: true, bitConfidence, out byte[] decoded, out var info)
            .Should().BeTrue("one chased bit brings the block back inside the budget");
        decoded.Should().Equal(ax25);
        info.ChasedBits.Should().Be(1);
        info.ErasedSymbols.Should().Be(0, "chase runs before erasures and cost no parity");
        info.CorrectedSymbols.Should().Be(8);
        info.CrcValid.Should().BeTrue();
    }

    [Fact]
    public void Two_Chased_Bits_Rescue_A_Header_Erasures_Cannot_Touch()
    {
        // The 2-parity header corrects one unlocated error and gets no erasure ladder; two
        // damaged bits are fatal unless the confidence fingers them for chase - which must
        // then decode to an exact codeword, both parity symbols spent as pure check.
        byte[] ax25 = TestFrame();
        byte[] wire = Il2pCodec.Encode(ax25, appendCrc: true);
        var bitConfidence = new float[wire.Length * 8];
        Array.Fill(bitConfidence, 1f);
        foreach (int bit in new[] { (3 * 8) + 2, (9 * 8) + 6 })
        {
            wire[bit / 8] ^= (byte)(0x80 >> (bit % 8));
            bitConfidence[bit] = 0.1f;
        }

        Il2pCodec.TryDecode(wire, hasTrailingCrc: true, out _, out _)
            .Should().BeFalse("two header errors exceed the header code");

        Il2pCodec.TryDecode(wire, hasTrailingCrc: true, bitConfidence, out byte[] decoded, out var info)
            .Should().BeTrue("both damaged bits are among the chased weakest");
        decoded.Should().Equal(ax25);
        info.ChasedBits.Should().Be(2);
        info.CrcValid.Should().BeTrue();
    }

    [Fact]
    public void Wrongly_Flagged_Bits_Do_Not_Hallucinate_A_Header()
    {
        // Confidence pointing at healthy bits must not conjure a decode: header chase
        // accepts exact codewords only, so flipping healthy bits just fails 63 times.
        byte[] ax25 = TestFrame();
        byte[] wire = Il2pCodec.Encode(ax25, appendCrc: true);
        var bitConfidence = new float[wire.Length * 8];
        Array.Fill(bitConfidence, 1f);
        wire[3] ^= 0x41;
        wire[9] ^= 0x0F;   // multi-bit header damage, none of it flagged
        for (int b = 0; b < 6; b++)
        {
            bitConfidence[(12 * 8) + b] = 0.1f;   // flags on a healthy byte instead
        }

        Il2pCodec.TryDecode(wire, hasTrailingCrc: true, bitConfidence, out _, out _)
            .Should().BeFalse("chase cannot invent a header from wrong flags");
    }

    [Fact]
    public void The_Deframer_Chases_Header_Bits_End_To_End()
    {
        byte[] ax25 = TestFrame();
        byte[] wire = Il2pCodec.Encode(ax25, appendCrc: true);
        var damaged = (byte[])wire.Clone();
        int[] headerBits = [(2 * 8) + 4, (11 * 8) + 1];
        foreach (int bit in headerBits)
        {
            damaged[bit / 8] ^= (byte)(0x80 >> (bit % 8));
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
                    int bitIndex = (i * 8) + b;
                    int bit = (damaged[i] >> (7 - b)) & 1;
                    float confidence =
                        withConfidence && Array.IndexOf(headerBits, bitIndex) >= 0 ? 0.05f : 1f;
                    deframer.PushBit(bit, confidence);
                }
            }

            return received;
        }

        Run(withConfidence: false).Should().BeEmpty("two header bit errors are fatal unflagged");
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
