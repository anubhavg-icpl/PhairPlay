package com.phairplay.airplay

import android.content.Context
import android.util.Base64
import com.phairplay.util.Logger
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

/**
 * AirPlayPairing — Implements HAP (HomeKit Accessory Protocol) pairing for AirPlay 2.
 *
 * WHY: iOS 14+ requires HAP pair-setup + pair-verify before it will stream to a receiver.
 * Without this, the device appears in the picker but connections are immediately rejected.
 *
 * HOW: Implements simplified HAP pairing using:
 *   - Ed25519 long-term key pair (LTPK/LTSK) persisted in SharedPreferences
 *   - X25519 ephemeral key pair for pair-verify ECDH
 *   - HKDF-SHA512 session key derivation
 *   - ChaCha20-Poly1305 authenticated encryption for encrypted data fields
 *   - TLV8 encoding/decoding for all HAP messages
 *
 * pair-setup (simplified, no SRP):
 *   M1 { state=1 } → M2 { state=2, pk=LTPK }
 *
 * pair-verify:
 *   M1 { state=1, pk=client_X25519_pub }
 *   → M2 { state=2, pk=server_X25519_pub, encryptedData=ChaCha20(sig) }
 *   M3 { state=3, encryptedData=client_proof } → M4 { state=4 }
 *
 * fp-setup: returns empty 200 OK (FairPlay bypass for unencrypted streams).
 */
class AirPlayPairing(private val context: Context) {

    private val ltpk: ByteArray
    private val ltsk: ByteArray

    // Ephemeral X25519 state kept for the duration of a pair-verify session
    @Volatile private var serverEphemeralPub: ByteArray? = null
    @Volatile private var serverEphemeralPriv: ByteArray? = null

    init {
        val (pub, priv) = loadOrGenerateKeyPair()
        ltpk = pub
        ltsk = priv
        Logger.i("AirPlayPairing ready (LTPK=${ltpk.toHex().take(8)}...)")
    }

    /** Returns the 32-byte Ed25519 long-term public key for use in mDNS TXT records and /info. */
    fun getLtpk(): ByteArray = ltpk.copyOf()

    /**
     * Handles a POST /pair-setup body.
     *
     * Phase 1 only (simplified, no SRP round-trips): return LTPK in M2.
     */
    fun handlePairSetup(body: ByteArray): ByteArray {
        val tlv = Tlv8.decode(body)
        val state = tlv[TLV8_STATE]?.firstOrNull()?.toInt() ?: 0
        Logger.d("pair-setup M$state")
        return Tlv8.encode(mapOf(
            TLV8_STATE to byteArrayOf(2),
            TLV8_PUBLIC_KEY to ltpk
        ))
    }

    /**
     * Handles a POST /pair-verify body (M1 or M3).
     */
    fun handlePairVerify(body: ByteArray): ByteArray {
        val tlv = Tlv8.decode(body)
        val state = tlv[TLV8_STATE]?.firstOrNull()?.toInt() ?: 0
        Logger.d("pair-verify M$state")
        return when (state) {
            1 -> pairVerifyM2(tlv)
            3 -> pairVerifyM4()
            else -> Tlv8.encode(mapOf(TLV8_STATE to byteArrayOf(4)))
        }
    }

    // ─── Private ─────────────────────────────────────────────────────────────

    private fun pairVerifyM2(tlv: Map<Byte, ByteArray>): ByteArray {
        val clientPub = tlv[TLV8_PUBLIC_KEY] ?: run {
            Logger.e("pair-verify M1: missing client public key")
            return errorResponse(ERROR_AUTHENTICATION)
        }
        if (clientPub.size != 32) {
            Logger.e("pair-verify M1: client pub key wrong length ${clientPub.size}")
            return errorResponse(ERROR_AUTHENTICATION)
        }

        // Generate ephemeral X25519 key pair
        val random = SecureRandom()
        val kpGen = X25519KeyPairGenerator()
        kpGen.init(X25519KeyGenerationParameters(random))
        val keyPair = kpGen.generateKeyPair()
        val serverPriv = (keyPair.private as X25519PrivateKeyParameters).encoded
        val serverPub  = (keyPair.public  as X25519PublicKeyParameters).encoded

        serverEphemeralPub  = serverPub
        serverEphemeralPriv = serverPriv

        // ECDH shared secret
        val agreement = X25519Agreement()
        agreement.init(X25519PrivateKeyParameters(serverPriv, 0))
        val sharedSecret = ByteArray(32)
        agreement.calculateAgreement(X25519PublicKeyParameters(clientPub, 0), sharedSecret, 0)

        // Derive encryption key: HKDF-SHA512(sharedSecret, salt, info, 32 bytes)
        val encKey = hkdf(
            ikm  = sharedSecret,
            salt = "Pair-Verify-Encrypt-Salt".toByteArray(),
            info = "Pair-Verify-Encrypt-Info".toByteArray(),
            len  = 32
        )

        // Sign (serverPub || clientPub) with the long-term Ed25519 secret key
        val message = serverPub + clientPub
        val signature = ed25519Sign(ltsk, message)

        // Encrypt signature with ChaCha20-Poly1305
        val nonce = hapNonce("PV-Msg02")
        val encryptedData = chacha20Poly1305Encrypt(encKey, nonce, ByteArray(0), signature)

        return Tlv8.encode(mapOf(
            TLV8_STATE        to byteArrayOf(2),
            TLV8_PUBLIC_KEY   to serverPub,
            TLV8_ENCRYPTED    to encryptedData
        ))
    }

    private fun pairVerifyM4(): ByteArray {
        // Accept all clients (open receiver — no per-device allowlist)
        serverEphemeralPub  = null
        serverEphemeralPriv = null
        return Tlv8.encode(mapOf(TLV8_STATE to byteArrayOf(4)))
    }

    private fun loadOrGenerateKeyPair(): Pair<ByteArray, ByteArray> {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val savedPub  = prefs.getString(KEY_LTPK, null)
        val savedPriv = prefs.getString(KEY_LTSK, null)

        if (savedPub != null && savedPriv != null) {
            return Pair(
                Base64.decode(savedPub,  Base64.DEFAULT),
                Base64.decode(savedPriv, Base64.DEFAULT)
            )
        }

        Logger.i("Generating new Ed25519 LTPK/LTSK pair")
        val gen = Ed25519KeyPairGenerator()
        gen.init(Ed25519KeyGenerationParameters(SecureRandom()))
        val kp = gen.generateKeyPair()
        val pub  = (kp.public  as Ed25519PublicKeyParameters).encoded
        val priv = (kp.private as Ed25519PrivateKeyParameters).encoded

        prefs.edit()
            .putString(KEY_LTPK, Base64.encodeToString(pub,  Base64.DEFAULT))
            .putString(KEY_LTSK, Base64.encodeToString(priv, Base64.DEFAULT))
            .apply()

        return Pair(pub, priv)
    }

    private fun ed25519Sign(privateKey: ByteArray, message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(privateKey, 0))
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    private fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, len: Int): ByteArray {
        val gen = HKDFBytesGenerator(SHA512Digest())
        gen.init(HKDFParameters(ikm, salt, info))
        val out = ByteArray(len)
        gen.generateBytes(out, 0, len)
        return out
    }

    private fun chacha20Poly1305Encrypt(
        key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray
    ): ByteArray {
        val cipher = ChaCha20Poly1305()
        cipher.init(true, AEADParameters(KeyParameter(key), 128, nonce, aad))
        val out = ByteArray(cipher.getOutputSize(plaintext.size))
        var pos = cipher.processBytes(plaintext, 0, plaintext.size, out, 0)
        pos += cipher.doFinal(out, pos)
        return out.copyOf(pos)
    }

    /** Builds a 12-byte HAP nonce: 4 zero bytes + 8-byte ASCII message name. */
    private fun hapNonce(message: String): ByteArray {
        val nonce = ByteArray(12)
        val msg = message.toByteArray(Charsets.US_ASCII)
        require(msg.size == 8) { "HAP nonce message must be 8 bytes" }
        msg.copyInto(nonce, destinationOffset = 4)
        return nonce
    }

    private fun errorResponse(errorCode: Byte): ByteArray = Tlv8.encode(mapOf(
        TLV8_STATE to byteArrayOf(2),
        TLV8_ERROR to byteArrayOf(errorCode)
    ))

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    companion object {
        private const val PREFS_NAME = "airplay_pairing"
        private const val KEY_LTPK   = "ltpk"
        private const val KEY_LTSK   = "ltsk"

        // HAP TLV8 type tags
        val TLV8_METHOD     : Byte = 0x00
        val TLV8_PUBLIC_KEY : Byte = 0x03
        val TLV8_ENCRYPTED  : Byte = 0x05
        val TLV8_STATE      : Byte = 0x06
        val TLV8_ERROR      : Byte = 0x07

        private const val ERROR_AUTHENTICATION: Byte = 0x02
    }
}

// ─── TLV8 codec (shared by pairing + HAP messages) ───────────────────────────

object Tlv8 {

    /**
     * Encodes a map of TLV8 items into a byte array.
     * Values > 255 bytes are split into 255-byte chunks automatically.
     */
    fun encode(items: Map<Byte, ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        for ((type, value) in items) {
            if (value.isEmpty()) {
                out.write(type.toInt() and 0xFF)
                out.write(0)
                continue
            }
            var offset = 0
            while (offset < value.size) {
                val chunk = minOf(255, value.size - offset)
                out.write(type.toInt() and 0xFF)
                out.write(chunk)
                out.write(value, offset, chunk)
                offset += chunk
            }
        }
        return out.toByteArray()
    }

    /**
     * Decodes a TLV8 byte array into a map. Consecutive chunks with the same type are merged.
     */
    fun decode(data: ByteArray): Map<Byte, ByteArray> {
        val result = LinkedHashMap<Byte, ByteArrayOutputStream>()
        var i = 0
        while (i + 1 < data.size) {
            val type   = data[i]
            val length = data[i + 1].toInt() and 0xFF
            i += 2
            val stream = result.getOrPut(type) { ByteArrayOutputStream() }
            if (length > 0 && i + length <= data.size) {
                stream.write(data, i, length)
                i += length
            }
        }
        return result.mapValues { it.value.toByteArray() }
    }
}
