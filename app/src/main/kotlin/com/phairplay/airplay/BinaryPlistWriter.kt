package com.phairplay.airplay

import java.io.ByteArrayOutputStream

/**
 * BinaryPlistWriter — Minimal binary property list (bplist00) encoder.
 *
 * WHY: AirPlay's GET /info endpoint must return device metadata as a binary plist.
 * iOS reads this before initiating a pairing or streaming session. Returning JSON
 * or plain text causes the client to abort immediately.
 *
 * HOW: Implements the Apple binary plist format (magic "bplist00") for a flat
 * dictionary containing String, Long, and ByteArray values — the types required
 * by the /info response. Does NOT support nested dicts, arrays, dates, or floats.
 *
 * Format reference: https://opensource.apple.com/source/CF/CF-550/CFBinaryPList.c
 *
 * Layout:
 *   "bplist00" header (8 bytes)
 *   Object 0: root dictionary (0xDN marker + N key refs + N val refs)
 *   Objects 1..N: key strings
 *   Objects N+1..2N: values
 *   Offset table (4 bytes per object, big-endian)
 *   Trailer (32 bytes)
 */
object BinaryPlistWriter {

    /**
     * Encodes a dict into a binary plist byte array.
     *
     * @param dict Insertion-ordered map of String keys to String/Long/Int/ByteArray values.
     * @return Binary plist bytes, ready to send as HTTP body with
     *         Content-Type: application/x-apple-binary-plist
     */
    fun writeDict(dict: LinkedHashMap<String, Any>): ByteArray {
        val keys   = dict.keys.toList()
        val values = dict.values.toList()
        val n      = keys.size

        // Object index layout:
        //   0         = root dict
        //   1..n      = key strings
        //   n+1..2n   = value objects
        val totalObjects = 2 * n + 1

        // Encode key strings
        val encodedKeys   = keys.map   { encodeString(it) }
        // Encode values (String, Long/Int, ByteArray)
        val encodedValues = values.map { encodeValue(it) }

        // Build root dict object:
        //   0xDN (n < 15) or 0xDF + int
        //   N one-byte key refs (1..n)
        //   N one-byte val refs (n+1..2n)
        val dictBytes = ByteArrayOutputStream().apply {
            if (n < 15) write(0xD0 or n) else { write(0xDF); writeIntObject(this, n.toLong()) }
            for (i in 1..n) write(i)           // key indices
            for (i in (n + 1)..(2 * n)) write(i)  // value indices
        }.toByteArray()

        // Lay out all objects in order
        val allObjects = ArrayList<ByteArray>(totalObjects)
        allObjects.add(dictBytes)
        allObjects.addAll(encodedKeys)
        allObjects.addAll(encodedValues)

        // Serialize and record byte offsets
        val body = ByteArrayOutputStream()
        body.write("bplist00".toByteArray(Charsets.US_ASCII))

        val offsets = IntArray(totalObjects)
        for (i in 0 until totalObjects) {
            offsets[i] = body.size()
            body.write(allObjects[i])
        }

        val offsetTableOffset = body.size()

        // Offset table: each entry is 4 bytes big-endian
        for (off in offsets) {
            body.write((off ushr 24) and 0xFF)
            body.write((off ushr 16) and 0xFF)
            body.write((off ushr  8) and 0xFF)
            body.write( off          and 0xFF)
        }

        // Trailer (32 bytes):
        //   6 bytes: reserved zeros
        //   1 byte: offsetIntSize = 4 (each offset is 4 bytes)
        //   1 byte: objectRefSize = 1 (each ref is 1 byte, totalObjects < 256)
        //   8 bytes: numObjects
        //   8 bytes: topObject = 0
        //   8 bytes: offsetTableOffset
        repeat(6) { body.write(0) }
        body.write(4)  // offsetIntSize
        body.write(1)  // objectRefSize
        writeLong8(body, totalObjects.toLong())
        writeLong8(body, 0L)                      // topObject
        writeLong8(body, offsetTableOffset.toLong())

        return body.toByteArray()
    }

    // ─── Encoders ─────────────────────────────────────────────────────────────

    private fun encodeString(s: String): ByteArray {
        val bytes = s.toByteArray(Charsets.US_ASCII)
        return ByteArrayOutputStream().apply {
            val len = bytes.size
            if (len < 15) write(0x50 or len)
            else { write(0x5F); writeIntObject(this, len.toLong()) }
            write(bytes)
        }.toByteArray()
    }

    private fun encodeInt(value: Long): ByteArray =
        ByteArrayOutputStream().apply {
            write(0x13)   // 0x1N where N=3 → 2^3=8 byte integer
            writeLong8(this, value)
        }.toByteArray()

    private fun encodeData(bytes: ByteArray): ByteArray =
        ByteArrayOutputStream().apply {
            val len = bytes.size
            if (len < 15) write(0x40 or len)
            else { write(0x4F); writeIntObject(this, len.toLong()) }
            write(bytes)
        }.toByteArray()

    private fun encodeValue(value: Any): ByteArray = when (value) {
        is ByteArray -> encodeData(value)
        is Long      -> encodeInt(value)
        is Int       -> encodeInt(value.toLong())
        is String    -> encodeString(value)
        else         -> encodeString(value.toString())
    }

    // ─── Write helpers ────────────────────────────────────────────────────────

    /** Writes a 4-byte big-endian int object (used for lengths ≥ 15). */
    private fun writeIntObject(out: ByteArrayOutputStream, value: Long) {
        out.write(0x12)  // 0x1N where N=2 → 2^2=4 byte integer
        out.write(((value ushr 24) and 0xFF).toInt())
        out.write(((value ushr 16) and 0xFF).toInt())
        out.write(((value ushr  8) and 0xFF).toInt())
        out.write( (value          and 0xFF).toInt())
    }

    /** Writes a raw 8-byte big-endian long (no object type prefix). */
    private fun writeLong8(out: ByteArrayOutputStream, value: Long) {
        out.write(((value ushr 56) and 0xFF).toInt())
        out.write(((value ushr 48) and 0xFF).toInt())
        out.write(((value ushr 40) and 0xFF).toInt())
        out.write(((value ushr 32) and 0xFF).toInt())
        out.write(((value ushr 24) and 0xFF).toInt())
        out.write(((value ushr 16) and 0xFF).toInt())
        out.write(((value ushr  8) and 0xFF).toInt())
        out.write( (value          and 0xFF).toInt())
    }
}
