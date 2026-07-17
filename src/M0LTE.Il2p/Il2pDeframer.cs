using System.Numerics;

namespace M0LTE.Il2p;

/// <summary>
/// Streaming IL2P receiver: hunts the 24-bit sync word 0xF15E48 in a logical-bit stream
/// (spec draft v0.6 recommends declaring a match with up to one bit in error), then
/// collects the 15 header wire bytes, sizes the payload from the decoded header, collects
/// the payload blocks (and CRC trailer when the link runs IL2P+CRC), and emits the decoded
/// AX.25 frame. Bits arrive most-significant-bit first, as IL2P transmits them.
/// One instance per receive bit stream; not thread-safe.
/// </summary>
public sealed class Il2pDeframer
{
    private enum State
    {
        Hunting,
        CollectingHeader,
        CollectingBody,
    }

    private readonly bool _crcMode;
    private readonly int _syncWord;
    private readonly Action<byte[], Il2pDecodeInfo> _frameReceived;
    private readonly byte[] _buffer;

    private State _state = State.Hunting;
    private int _syncShift;
    private int _byteShift;
    private int _bitCount;
    private int _length;
    private int _expectedLength;
    private int _invert;

    /// <summary>Creates a deframer delivering decoded AX.25 frames to
    /// <paramref name="frameReceived"/>.</summary>
    /// <param name="frameReceived">Called synchronously from <see cref="PushBit"/> with the
    /// AX.25 frame and decode diagnostics for every frame that decodes.</param>
    /// <param name="crcMode">True when the link uses IL2P+CRC (both stations must agree).
    /// CRC-invalid frames are dropped and counted, per NinoTNC "check CRC" semantics.</param>
    public Il2pDeframer(Action<byte[], Il2pDecodeInfo> frameReceived, bool crcMode)
        : this(frameReceived, crcMode, Il2pCodec.SyncWord)
    {
    }

    /// <summary>Creates a deframer hunting a non-standard 24-bit sync word. The MMDVM-TNC
    /// "Mode 2" C4FSK framing is IL2P in every respect except its sync (0x5D57DF7F's low
    /// 24 bits — chosen to be outer-symbol-only in the 4-level constellation); the NinoTNC
    /// C4FSK modes inherit it.</summary>
    public Il2pDeframer(Action<byte[], Il2pDecodeInfo> frameReceived, bool crcMode, int syncWord)
    {
        ArgumentNullException.ThrowIfNull(frameReceived);
        _syncWord = syncWord & 0xFFFFFF;
        _frameReceived = frameReceived;
        _crcMode = crcMode;

        int maxBody = Il2pBlockLayout.Compute(Il2pCodec.MaxPayloadBytes).WireLength
            + Il2pCodec.TrailingCrcWireLength;
        _buffer = new byte[Il2pCodec.HeaderWireLength + maxBody];
    }

    /// <summary>Frames that failed Reed-Solomon decoding after a sync match (diagnostics).</summary>
    public long RsFailures { get; private set; }

    /// <summary>Frames dropped because the trailing CRC disagreed (diagnostics).</summary>
    public long CrcFailures { get; private set; }

    /// <summary>Pushes one received bit (0/1) through the deframer.</summary>
    public void PushBit(int bit)
    {
        bit &= 1;

        if (_state == State.Hunting)
        {
            _syncShift = ((_syncShift << 1) | bit) & 0xFFFFFF;
            // Hunt the sync word and its complement: the spec's FSK symbol maps note some
            // radios invert the signal and recommend checking for inverted data. A
            // complemented match latches inversion for the rest of that frame.
            bool direct = BitOperations.PopCount((uint)(_syncShift ^ _syncWord)) <= 1;
            bool inverted = BitOperations.PopCount(
                (uint)((~_syncShift & 0xFFFFFF) ^ _syncWord)) <= 1;
            if (direct || inverted)
            {
                _invert = inverted ? 1 : 0;
                _state = State.CollectingHeader;
                _byteShift = 0;
                _bitCount = 0;
                _length = 0;
            }

            return;
        }

        bit ^= _invert;
        _byteShift = (_byteShift << 1) | bit; // MSB first
        if (++_bitCount < 8)
        {
            return;
        }

        _bitCount = 0;
        _buffer[_length++] = (byte)_byteShift;
        _byteShift = 0;

        if (_state == State.CollectingHeader)
        {
            if (_length < Il2pCodec.HeaderWireLength)
            {
                return;
            }

            if (!Il2pCodec.TryDecodeHeader(
                    _buffer.AsSpan(0, Il2pCodec.HeaderWireLength), out _, out int payloadByteCount, out _))
            {
                RsFailures++;
                ReturnToHunt();
                return;
            }

            int bodyLength = Il2pBlockLayout.Compute(payloadByteCount).WireLength
                + (_crcMode ? Il2pCodec.TrailingCrcWireLength : 0);
            _expectedLength = Il2pCodec.HeaderWireLength + bodyLength;
            if (bodyLength == 0)
            {
                Complete();
                return;
            }

            _state = State.CollectingBody;
            return;
        }

        if (_length == _expectedLength)
        {
            Complete();
        }
    }

    private void Complete()
    {
        if (!Il2pCodec.TryDecode(
                _buffer.AsSpan(0, _length), _crcMode, out byte[] frame, out var info))
        {
            RsFailures++;
        }
        else if (info.CrcValid == false)
        {
            CrcFailures++;
        }
        else
        {
            _frameReceived(frame, info);
        }

        ReturnToHunt();
    }

    private void ReturnToHunt()
    {
        _state = State.Hunting;
        _syncShift = 0;
    }

    /// <summary>Abandons any frame in progress and returns to hunting for a sync word. For
    /// receive paths with hard stream boundaries (e.g. one IL2P stream per FreeDV burst):
    /// without a reset, a frame truncated by the end of one stream would silently consume
    /// the head of the next as its missing body.</summary>
    public void Reset() => ReturnToHunt();
}
