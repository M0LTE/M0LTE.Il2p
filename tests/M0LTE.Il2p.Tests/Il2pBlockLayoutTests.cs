using M0LTE.Il2p;

namespace M0LTE.Il2p.Tests;

public class Il2pBlockLayoutTests
{
    [Theory]
    [InlineData(0, 0, 0, 0, 0)]
    [InlineData(1, 1, 1, 0, 1)]
    [InlineData(9, 1, 9, 0, 1)]
    [InlineData(239, 1, 239, 0, 1)]
    [InlineData(240, 2, 120, 0, 2)]
    [InlineData(241, 2, 120, 1, 1)]
    [InlineData(478, 2, 239, 0, 2)]
    [InlineData(1023, 5, 204, 3, 2)]
    public void Layouts_Match_The_Spec_Computations(
        int payload, int blocks, int smallSize, int largeCount, int smallCount)
    {
        var layout = Il2pBlockLayout.Compute(payload);

        layout.BlockCount.Should().Be(blocks);
        layout.SmallBlockSize.Should().Be(smallSize);
        layout.LargeBlockCount.Should().Be(largeCount);
        layout.SmallBlockCount.Should().Be(smallCount);
        layout.WireLength.Should().Be(payload + blocks * 16);
    }

    [Fact]
    public void Block_Sizes_Always_Sum_To_The_Payload_Count()
    {
        for (int payload = 0; payload <= 1023; payload++)
        {
            var layout = Il2pBlockLayout.Compute(payload);
            int total = layout.LargeBlockCount * layout.LargeBlockSize
                + layout.SmallBlockCount * layout.SmallBlockSize;
            total.Should().Be(payload, $"payload {payload}");
            if (layout.BlockCount > 0)
            {
                layout.SmallBlockSize.Should().BeGreaterThan(0);
            }

            if (layout.LargeBlockCount > 0)
            {
                layout.LargeBlockSize.Should().BeLessThanOrEqualTo(Il2pBlockLayout.MaxBlockDataSize);
            }
        }
    }

    [Fact]
    public void Payloads_Beyond_The_Ten_Bit_Count_Are_Rejected()
    {
        var act = () => Il2pBlockLayout.Compute(1024);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }
}
