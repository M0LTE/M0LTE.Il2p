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
/// <remarks>
/// A false sync match (channel garbage can image the sync word, and some modes' idle
/// garbage is statistically biased toward it) starts a bogus collection of up to a
/// maximum-size frame — and a REAL sync arriving during that collection would be consumed
/// as payload. Reed-Solomon and the CRC reject the bogus frame, but rejection alone would
/// leave the deframer deaf for the collection's duration. This deframer is instead
/// backtracking: every physical bit also lands in a ring buffer, and when a collection
/// fails (header RS, length, body RS) the read cursor rewinds to one bit past the failed
/// sync and re-hunts — bit-for-bit equivalent to never having locked at all, so a frame
/// inside a failed collection is always recovered. Collection start positions advance
/// strictly monotonically, so processing always terminates; the ring covers a
/// maximum-size collection plus the sync, so a rewind can never underrun.
/// </remarks>
public sealed class Il2pDeframer
{
    private enum State
    {
        Hunting,
        CollectingHeader,
        CollectingBody,
    }

    // Power of two, > max collection bits (header + max body + CRC ≈ 8.5k) + sync slack.
    private const int RingSize = 16384;

    private readonly bool _crcMode;
    private readonly int _syncWord;
    private readonly Action<byte[], Il2pDecodeInfo> _frameReceived;
    private readonly byte[] _buffer;
    private readonly float[] _bufferBitConfidence;
    private readonly byte[] _ring = new byte[RingSize];
    private readonly float[] _confidenceRing = new float[RingSize];

    private State _state = State.Hunting;
    private int _syncShift;
    private int _byteShift;
    private int _bitCount;
    private int _length;
    private int _expectedLength;
    private int _invert;
    private long _writePos;
    private long _readPos;
    private long _syncEndPos;
    private int _huntWarmup = 23;
    private bool _confidenceSeen;

    /// <summary>Creates a deframer delivering decoded AX.25 frames to
    /// <paramref name="frameReceived"/>.</summary>
    /// <param name="frameReceived">Called synchronously from <see cref="PushBit(int, float)"/> with the
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
        _bufferBitConfidence = new float[_buffer.Length * 8];
    }

    /// <summary>Frames that failed Reed-Solomon decoding after a sync match (diagnostics).</summary>
    public long RsFailures { get; private set; }

    /// <summary>Frames dropped because the trailing CRC disagreed (diagnostics).</summary>
    public long CrcFailures { get; private set; }

    /// <summary>Pushes one received bit (0/1) through the deframer.</summary>
    public void PushBit(int bit) => PushBit(bit, 1f);

    /// <summary>
    /// Pushes one received bit with the demodulator's confidence in it (lower = less
    /// reliable; the scale is the caller's, only the ordering matters). Confidence buys
    /// nothing while a frame decodes on parity alone; when a Reed-Solomon block fails, the
    /// weakest bytes are retried as erasures - see the confidence-aware
    /// <see cref="Il2pCodec.TryDecode(ReadOnlySpan{byte}, bool, ReadOnlySpan{float}, out byte[], out Il2pDecodeInfo)"/>.
    /// A byte's confidence is the minimum of its bits' - a byte is wrong if any bit is.
    /// </summary>
    public void PushBit(int bit, float confidence)
    {
        _confidenceSeen |= confidence < 1f;
        _ring[(int)(_writePos & (RingSize - 1))] = (byte)(bit & 1);
        _confidenceRing[(int)(_writePos & (RingSize - 1))] = confidence;
        _writePos++;
        while (_readPos < _writePos)
        {
            // Consume-then-step: a Backtrack inside Step rewrites _readPos wholesale, and
            // the next iteration picks up exactly at the rewound position.
            int next = _ring[(int)(_readPos & (RingSize - 1))];
            float nextConfidence = _confidenceRing[(int)(_readPos & (RingSize - 1))];
            _readPos++;
            Step(next, nextConfidence);
        }
    }

    private void Step(int bit, float confidence)
    {
        if (_state == State.Hunting)
        {
            _syncShift = ((_syncShift << 1) | bit) & 0xFFFFFF;

            // No match until the register holds 24 real bits (23 skips — the first full
            // window completes on the 24th): a partially-refilled register's leading
            // zeros can otherwise count as the one tolerated error and re-match the very
            // sync a Backtrack just failed — collection start would stop advancing and
            // the rewind loop would never terminate.
            if (_huntWarmup > 0)
            {
                _huntWarmup--;
                return;
            }
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
                _syncEndPos = _readPos - 1; // the bit just consumed is the sync's last
            }

            return;
        }

        bit ^= _invert;
        _byteShift = (_byteShift << 1) | bit; // MSB first
        _bufferBitConfidence[(_length * 8) + _bitCount] = confidence;
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
                    _buffer.AsSpan(0, Il2pCodec.HeaderWireLength),
                    _confidenceSeen
                        ? _bufferBitConfidence.AsSpan(0, Il2pCodec.HeaderWireLength * 8) : [],
                    out _, out int payloadByteCount, out _, out _))
            {
                RsFailures++;
                Backtrack();
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
                _buffer.AsSpan(0, _length), _crcMode,
                _confidenceSeen ? _bufferBitConfidence.AsSpan(0, _length * 8) : [],
                out byte[] frame, out var info))
        {
            RsFailures++;
            Backtrack();
            return;
        }

        if (info.CrcValid == false)
        {
            CrcFailures++;
            Backtrack();
            return;
        }

        _frameReceived(frame, info);
        _state = State.Hunting;
        _syncShift = 0;
        _huntWarmup = 23;
    }

    /// <summary>
    /// A collection failed: rewind to re-hunt from one bit past the start of the sync that
    /// began it. The 23 bits before that point re-prime the hunter's shift register, so the
    /// first new match candidate ends exactly one bit after the failed one — overlapping
    /// syncs are never skipped. The failure's own bits are reconsidered in full, which is
    /// what recovers a real frame swallowed by a bogus collection. The Step/rewind loop in
    /// <see cref="PushBit(int, float)"/> terminates because each collection starts strictly after the
    /// previous failed one.
    /// </summary>
    private void Backtrack()
    {
        _state = State.Hunting;
        _syncShift = 0;
        _huntWarmup = 23;
        long resume = _syncEndPos - 22;
        long floor = _writePos - RingSize;
        _readPos = resume > floor ? resume : (floor > 0 ? floor : 0);
    }

    /// <summary>Abandons any frame in progress and returns to hunting for a sync word. For
    /// receive paths with hard stream boundaries (e.g. one IL2P stream per FreeDV burst):
    /// without a reset, a frame truncated by the end of one stream would silently consume
    /// the head of the next as its missing body. The bit backlog is discarded with it.</summary>
    public void Reset()
    {
        _state = State.Hunting;
        _syncShift = 0;
        _huntWarmup = 23;
        _readPos = _writePos;
    }
}
