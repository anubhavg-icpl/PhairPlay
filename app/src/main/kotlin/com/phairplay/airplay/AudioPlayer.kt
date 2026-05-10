package com.phairplay.airplay

import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioTrack
import android.media.MediaCodec
import android.media.MediaFormat
import com.phairplay.util.Logger
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.SICBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import java.nio.ByteBuffer

/**
 * AudioPlayer — Decrypts and plays the AirPlay audio stream.
 *
 * WHY: AirPlay audio arrives as encrypted RTP packets over UDP.
 * Before the audio can be played, it must be:
 * 1. Received from the UDP socket
 * 2. Decrypted (AES-128-CTR cipher)
 * 3. Decoded (AAC-ELD or ALAC frames → PCM audio)
 * 4. Played through the TV's audio output (AudioTrack)
 *
 * This class handles steps 2-4. Step 1 (UDP receiving) is handled by RtspHandler
 * which calls [playAudioPacket] for each received packet.
 *
 * HOW:
 *   val player = AudioPlayer()
 *   player.initialize(aesKey, aesIv, sampleRate, channels)  // call once with SDP params
 *   player.playAudioPacket(encryptedRtpPayload)              // call for each UDP packet
 *   player.release()                                          // call when done
 */
class AudioPlayer {

    // Android's audio output — writes decoded PCM audio to hardware
    private var audioTrack: AudioTrack? = null

    // AES-128-CTR cipher engine (from Bouncy Castle)
    private var aesCipher: SICBlockCipher? = null

    // MediaCodec for ALAC or AAC-ELD decoding — null when codec is raw PCM (no codec required)
    private var mediaCodec: MediaCodec? = null
    private val codecOutputInfo = MediaCodec.BufferInfo()

    @Volatile
    private var isInitialized = false

    /**
     * Initializes the AudioPlayer with the stream parameters from the SDP.
     *
     * AES key and IV come from the SDP body in the RTSP ANNOUNCE message.
     * When the SDP does not include encryption keys (unencrypted stream), pass null for
     * both — the cipher is skipped entirely and audio payload is written directly to AudioTrack.
     *
     * SECURITY: When provided, both key and IV MUST be exactly 16 bytes each (AES-128).
     * We validate this before use (RULE 4). Passing null skips validation and cipher setup.
     *
     * @param aesKey     16-byte AES-128 key, or null for unencrypted streams
     * @param aesIv      16-byte initialization vector, or null for unencrypted streams
     * @param sampleRate Audio sample rate in Hz (typically 44100 or 48000)
     * @param channels   Number of audio channels (1 = mono, 2 = stereo)
     */
    /**
     * Initializes the AudioPlayer.
     *
     * @param aesKey         16-byte AES-128 key (null = unencrypted)
     * @param aesIv          16-byte IV (null = unencrypted)
     * @param sampleRate     Audio sample rate in Hz
     * @param channels       1 = mono, 2 = stereo
     * @param codec          [AudioCodec] — drives MediaCodec MIME type selection
     * @param alacMagicCookie 24-byte ALAC cookie for MediaCodec CSD-0 (ALAC streams only)
     * @param aacEldConfig   AudioSpecificConfig bytes for MediaCodec CSD-0 (AAC-ELD streams only)
     */
    fun initialize(
        aesKey: ByteArray?,
        aesIv: ByteArray?,
        sampleRate: Int,
        channels: Int,
        codec: AudioCodec = AudioCodec.ALAC,
        alacMagicCookie: ByteArray? = null,
        aacEldConfig: ByteArray? = null
    ) {
        if (isInitialized) {
            Logger.w("AudioPlayer.initialize() called twice — ignoring")
            return
        }

        if (aesKey != null || aesIv != null) {
            // SECURITY: Validate key length before using for cryptography (RULE 4)
            require(aesKey != null && aesKey.size == AES_KEY_LENGTH_BYTES) {
                "AES key must be exactly $AES_KEY_LENGTH_BYTES bytes, got ${aesKey?.size}"
            }
            require(aesIv != null && aesIv.size == AES_KEY_LENGTH_BYTES) {
                "AES IV must be exactly $AES_KEY_LENGTH_BYTES bytes, got ${aesIv?.size}"
            }
            initializeCipher(aesKey!!, aesIv!!)
            Logger.i("Initializing AudioPlayer (encrypted, $codec): ${sampleRate}Hz, $channels ch")
        } else {
            Logger.i("Initializing AudioPlayer (unencrypted, $codec): ${sampleRate}Hz, $channels ch")
        }

        // Set up MediaCodec decoder for ALAC or AAC-ELD
        when (codec) {
            AudioCodec.ALAC    -> initializeAlacDecoder(sampleRate, channels, alacMagicCookie)
            AudioCodec.AAC_ELD -> initializeAacEldDecoder(sampleRate, channels, aacEldConfig)
            AudioCodec.UNKNOWN -> Unit  // no decoder — caller should not send audio
        }

        initializeAudioTrack(sampleRate, channels)
        isInitialized = true
    }

    /**
     * Decrypts and plays a single audio RTP packet.
     *
     * This method is called from the IO dispatcher (network thread) for each
     * UDP audio packet received from the AirPlay sender.
     *
     * Steps:
     * 1. Strip the RTP header (12 bytes fixed + optional extensions)
     * 2. Decrypt the payload using AES-128-CTR
     * 3. Write the decrypted PCM data to AudioTrack
     *
     * PERFORMANCE: AudioTrack.write() in WRITE_NON_BLOCKING mode returns immediately
     * if the buffer is full, rather than blocking. This prevents network I/O from
     * being stalled by audio output.
     *
     * @param rtpPacket The complete RTP packet bytes (header + encrypted payload)
     */
    fun playAudioPacket(rtpPacket: ByteArray) {
        if (!isInitialized) {
            Logger.w("playAudioPacket() called but AudioPlayer not initialized")
            return
        }

        try {
            if (rtpPacket.size <= RTP_HEADER_MIN_BYTES) {
                Logger.w("RTP packet too small (${rtpPacket.size} bytes), skipping")
                return
            }
            val encryptedPayload = rtpPacket.copyOfRange(RTP_HEADER_MIN_BYTES, rtpPacket.size)
            val payload = decrypt(encryptedPayload)

            val codec = mediaCodec
            if (codec == null) {
                // No MediaCodec — should not happen for ALAC/AAC-ELD, but fail gracefully
                audioTrack?.write(payload, 0, payload.size, AudioTrack.WRITE_NON_BLOCKING)
                return
            }

            // ── Feed compressed frame into MediaCodec ────────────────────────
            val inputIdx = codec.dequeueInputBuffer(CODEC_TIMEOUT_US)
            if (inputIdx >= 0) {
                val inputBuf = codec.getInputBuffer(inputIdx)!!
                inputBuf.clear()
                inputBuf.put(payload)
                codec.queueInputBuffer(inputIdx, 0, payload.size, System.nanoTime() / 1000L, 0)
            }

            // ── Drain all available decoded PCM output ────────────────────────
            drainCodecOutput(codec)

        } catch (e: Exception) {
            Logger.e("Error playing audio packet", e)
        }
    }

    private fun drainCodecOutput(codec: MediaCodec) {
        while (true) {
            val outputIdx = codec.dequeueOutputBuffer(codecOutputInfo, 0L)
            when {
                outputIdx >= 0 -> {
                    val outBuf: ByteBuffer = codec.getOutputBuffer(outputIdx) ?: break
                    val pcm = ByteArray(codecOutputInfo.size)
                    outBuf.position(codecOutputInfo.offset)
                    outBuf.get(pcm, 0, codecOutputInfo.size)
                    audioTrack?.write(pcm, 0, pcm.size, AudioTrack.WRITE_NON_BLOCKING)
                    codec.releaseOutputBuffer(outputIdx, false)
                }
                outputIdx == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED -> { /* format change, OK */ }
                else -> break
            }
        }
    }

    /**
     * Releases all audio resources.
     *
     * MUST be called when streaming ends to free the AudioTrack hardware buffer.
     * After release(), call initialize() again before using the player.
     *
     * RULE 5: All resources released — AudioTrack holds exclusive hardware audio output.
     */
    fun release() {
        Logger.d("Releasing AudioPlayer")
        try {
            mediaCodec?.stop()
            mediaCodec?.release()
            audioTrack?.stop()
            audioTrack?.release()
        } catch (e: Exception) {
            Logger.e("Error releasing audio resources (non-fatal)", e)
        } finally {
            mediaCodec = null
            audioTrack = null
            aesCipher  = null
            isInitialized = false
        }
    }

    /**
     * Initializes an ALAC MediaCodec decoder with the 24-byte magic cookie as CSD-0.
     *
     * WHY: Android's AudioTrack does not accept ALAC frames — they must be decoded to PCM
     * via MediaCodec first. The ALAC magic cookie (built from SDP fmtp parameters) tells
     * MediaCodec the frame size, sample rate, bit depth, and number of channels.
     */
    private fun initializeAlacDecoder(sampleRate: Int, channels: Int, cookie: ByteArray?) {
        if (cookie == null || cookie.size != 24) {
            Logger.w("ALAC: no/invalid magic cookie (${cookie?.size} bytes) — skipping MediaCodec")
            return
        }
        try {
            val format = MediaFormat.createAudioFormat(MIME_ALAC, sampleRate, channels)
            format.setByteBuffer("csd-0", ByteBuffer.wrap(cookie))
            val codec = MediaCodec.createDecoderByType(MIME_ALAC)
            codec.configure(format, null, null, 0)
            codec.start()
            mediaCodec = codec
            Logger.i("ALAC MediaCodec initialized (${sampleRate}Hz, $channels ch)")
        } catch (e: Exception) {
            Logger.e("Failed to initialize ALAC MediaCodec", e)
        }
    }

    /**
     * Initializes an AAC-ELD MediaCodec decoder with the AudioSpecificConfig as CSD-0.
     *
     * WHY: AAC-ELD (profile 39) frames from AirPlay are raw compressed audio — they must
     * be decoded by MediaCodec before AudioTrack can play them.
     */
    private fun initializeAacEldDecoder(sampleRate: Int, channels: Int, aacConfig: ByteArray?) {
        if (aacConfig == null) {
            Logger.w("AAC-ELD: no AudioSpecificConfig from SDP — skipping MediaCodec")
            return
        }
        try {
            val format = MediaFormat.createAudioFormat(MIME_AAC, sampleRate, channels)
            format.setByteBuffer("csd-0", ByteBuffer.wrap(aacConfig))
            val codec = MediaCodec.createDecoderByType(MIME_AAC)
            codec.configure(format, null, null, 0)
            codec.start()
            mediaCodec = codec
            Logger.i("AAC-ELD MediaCodec initialized (${sampleRate}Hz, $channels ch)")
        } catch (e: Exception) {
            Logger.e("Failed to initialize AAC-ELD MediaCodec", e)
        }
    }

    /**
     * Sets up the AES-128-CTR cipher engine.
     *
     * Why CTR (Counter) mode?
     * CTR mode turns a block cipher (AES) into a stream cipher. This means:
     * - We can decrypt any position in the stream without decrypting earlier data
     * - No padding is required (good for streaming audio of variable length)
     * - The IV must be unique per session (guaranteed by the AirPlay protocol)
     *
     * Bouncy Castle's SICBlockCipher implements CTR mode.
     * SIC = Segmented Integer Counter — same as CTR, just a different name.
     *
     * @param key 16-byte AES key
     * @param iv  16-byte initialization vector (starting counter value)
     */
    private fun initializeCipher(key: ByteArray, iv: ByteArray) {
        val keyParam = KeyParameter(key)
        val keyWithIv = ParametersWithIV(keyParam, iv)

        // SICBlockCipher = AES in CTR/SIC mode (stream cipher behavior)
        aesCipher = SICBlockCipher(AESEngine()).also { cipher ->
            // false = decrypt mode (true would be encrypt)
            cipher.init(false, keyWithIv)
        }
        Logger.d("AES-128-CTR cipher initialized")
    }

    /**
     * Configures the AudioTrack for audio output.
     *
     * AudioTrack is Android's low-level audio output API — it writes raw PCM
     * audio data directly to the hardware audio mixer.
     *
     * @param sampleRate Audio sample rate (e.g., 44100 Hz)
     * @param channels   Number of channels (1 = mono, 2 = stereo)
     */
    private fun initializeAudioTrack(sampleRate: Int, channels: Int) {
        // Map channel count to Android's AudioFormat constant
        val channelConfig = when (channels) {
            1 -> AudioFormat.CHANNEL_OUT_MONO
            2 -> AudioFormat.CHANNEL_OUT_STEREO
            else -> {
                Logger.w("Unsupported channel count: $channels — defaulting to stereo")
                AudioFormat.CHANNEL_OUT_STEREO
            }
        }

        // Calculate minimum buffer size — this is the smallest buffer that won't cause dropout
        val minBufferSize = AudioTrack.getMinBufferSize(
            sampleRate,
            channelConfig,
            AudioFormat.ENCODING_PCM_16BIT
        )

        // Use 2x the minimum buffer size for more stability
        val bufferSize = minBufferSize * 2

        audioTrack = AudioTrack.Builder()
            .setAudioAttributes(
                AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_MEDIA)
                    .setContentType(AudioAttributes.CONTENT_TYPE_MOVIE)
                    .build()
            )
            .setAudioFormat(
                AudioFormat.Builder()
                    .setSampleRate(sampleRate)
                    .setChannelMask(channelConfig)
                    .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                    .build()
            )
            .setBufferSizeInBytes(bufferSize)
            .setTransferMode(AudioTrack.MODE_STREAM)  // STREAM = for continuous audio
            .build()

        audioTrack!!.play()
        Logger.d("AudioTrack initialized: ${sampleRate}Hz, $channels ch, buffer=$bufferSize bytes")
    }

    /**
     * Decrypts a byte array using the AES-128-CTR cipher.
     *
     * @param data The encrypted bytes to decrypt.
     * @return The decrypted bytes (same length as input — CTR mode has no padding).
     */
    private fun decrypt(data: ByteArray): ByteArray {
        val cipher = aesCipher ?: return data  // If no cipher, return as-is
        val output = ByteArray(data.size)
        // processBytes handles arbitrary-length data (CTR mode works on any length)
        cipher.processBytes(data, 0, data.size, output, 0)
        return output
    }

    companion object {
        private const val AES_KEY_LENGTH_BYTES = 16
        private const val RTP_HEADER_MIN_BYTES = 12

        // MediaCodec MIME types for AirPlay audio codecs
        private const val MIME_ALAC = "audio/alac"
        private const val MIME_AAC  = "audio/mp4a-latm"

        // dequeueInputBuffer timeout: 10 ms — enough to get a buffer without blocking the RTP thread
        private const val CODEC_TIMEOUT_US = 10_000L
    }
}
