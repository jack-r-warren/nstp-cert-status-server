import com.google.common.hash.Hashing
import com.goterl.lazycode.lazysodium.LazySodiumJava
import com.goterl.lazycode.lazysodium.SodiumJava
import com.goterl.lazycode.lazysodium.interfaces.Sign
import com.goterl.lazycode.lazysodium.interfaces.Sign.BYTES
import com.sun.jna.Pointer

fun ByteArray.sign(secretKey: ByteArray) = let { input ->
    (LazySodiumJava(SodiumJava()) as Sign.Native).run {
        Sign.StateCryptoSign().let { state ->
            cryptoSignInit(state)
            cryptoSignUpdate(state, input, input.size.toLong())
            ByteArray(BYTES).also {
                cryptoSignFinalCreate(state, it, Pointer.NULL, secretKey)
            }
        }
    }
}


fun ByteArray.verifySign(sign: ByteArray, publicKey: ByteArray) = let { input ->
    (LazySodiumJava(SodiumJava()) as Sign.Native).run {
        Sign.StateCryptoSign().let { state ->
            cryptoSignInit(state)
            cryptoSignUpdate(state, input, input.size.toLong())
            cryptoSignFinalVerify(state, sign, publicKey)
        }
    }
}

@Suppress("UnstableApiUsage")
fun ByteArray.hash(algorithm: NstpV4.HashAlgorithm): ByteArray =
    when (algorithm) {
        NstpV4.HashAlgorithm.IDENTITY -> this.also {
            println("Warning! ByteArray hashed using identity!")
        }
        NstpV4.HashAlgorithm.SHA256 -> Hashing.sha256().hashBytes(this).asBytes()
        NstpV4.HashAlgorithm.SHA512 -> Hashing.sha512().hashBytes(this).asBytes()
        NstpV4.HashAlgorithm.UNRECOGNIZED -> throw IllegalArgumentException("Unknown algorithm $algorithm")
    }