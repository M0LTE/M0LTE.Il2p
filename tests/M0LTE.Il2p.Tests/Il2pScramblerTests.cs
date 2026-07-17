using M0LTE.Il2p;

namespace M0LTE.Il2p.Tests;

public class Il2pScramblerTests
{
    [Fact]
    public void Descramble_Then_Scramble_Reproduces_Spec_Wire_Bytes()
    {
        // First 13 wire bytes of the spec's S-frame example = the scrambled header
        // (RS is systematic, so data bytes travel unchanged).
        byte[] wire = Convert.FromHexString("26574D57F1D2A8F06AF27BAD23");

        var descrambled = (byte[])wire.Clone();
        Il2pScrambler.Descramble(descrambled);
        var rescrambled = new byte[descrambled.Length];
        Il2pScrambler.Scramble(descrambled, rescrambled);

        rescrambled.Should().Equal(wire);
    }

    [Fact]
    public void Scramble_Then_Descramble_Is_The_Identity()
    {
        var random = new Random(20260714);
        for (int trial = 0; trial < 100; trial++)
        {
            var input = new byte[random.Next(1, 300)];
            random.NextBytes(input);

            var scrambled = new byte[input.Length];
            Il2pScrambler.Scramble(input, scrambled);
            Il2pScrambler.Descramble(scrambled);

            scrambled.Should().Equal(input, $"trial {trial}");
        }
    }

    [Fact]
    public void Scrambling_Preserves_Block_Length()
    {
        var input = new byte[239];
        var output = new byte[239];
        Il2pScrambler.Scramble(input, output);

        // An all-zero block must scramble to something non-zero (that is the point of it).
        output.Should().NotEqual(input);
    }

    [Fact]
    public void Each_Block_Restarts_From_Initial_Conditions()
    {
        byte[] input = [0xDE, 0xAD, 0xBE, 0xEF];
        var first = new byte[4];
        var second = new byte[4];
        Il2pScrambler.Scramble(input, first);
        Il2pScrambler.Scramble(input, second);

        second.Should().Equal(first);
    }
}
