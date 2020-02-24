import NstpV4.HashAlgorithm.SHA512
import com.google.protobuf.ByteString
import io.ktor.utils.io.core.*
import java.nio.ByteBuffer

fun NstpV4.CertificateHashOrBuilder.byteDigest(): ByteArray = let { hash ->
    buildPacket {
        writeFully(hash.value.asReadOnlyByteBuffer())
        writeByte(hash.algorithm.number.toByte())
    }.readBytes()
}

infix fun NstpV4.CertificateHashOrBuilder.isIn(certificates: Iterable<NstpV4.Certificate>) =
    certificates.any { it.matches(this) }

fun NstpV4.CertificateOrBuilder.byteDigest(includeSignature: Boolean = true): ByteArray = let { cert ->
    buildPacket {
        cert.subjectsList.map { it.toByteArray() }.forEach { writeFully(it) }
        ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN.nioOrder).apply {
            putLong(cert.validFrom)
            putInt(cert.validLength)
        }.let { writeFully(it.flip()) }
        cert.usagesList.map { it.number.toByte() }.forEach { writeByte(it) }
        writeFully(cert.encryptionPublicKey.asReadOnlyByteBuffer())
        writeFully(cert.signingPublicKey.asReadOnlyByteBuffer())
        if (cert.hasIssuer()) writeFully(cert.issuer.byteDigest())
        if (includeSignature) writeFully(cert.issuerSignature.asReadOnlyByteBuffer())
    }.readBytes()
}

fun NstpV4.CertificateOrBuilder.hash(algorithm: NstpV4.HashAlgorithm = SHA512): NstpV4.CertificateHash =
    let { certificate ->
        NstpV4.CertificateHash.newBuilder().apply {
            this.algorithm = algorithm
            this.value = ByteString.copyFrom(certificate.byteDigest().hash(algorithm))
        }.build()
    }

fun NstpV4.CertificateOrBuilder.matches(hash: NstpV4.CertificateHashOrBuilder) =
    hash == this.hash(hash.algorithm)

fun NstpV4.CertificateStatusResponseOrBuilder.byteDigest(): ByteArray = let { response ->
    buildPacket {
        writeFully(response.certificate.byteDigest())
        writeByte(response.status.number.toByte())
        ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN.nioOrder).apply {
            putLong(response.validFrom)
            putInt(response.validLength)
        }.let { writeFully(it.flip()) }
        writeFully(response.statusCertificate.byteDigest(false))
    }.readBytes()
}

fun NstpV4.CertificateStatusResponseOrBuilder.sign(privateKey: ByteArray): ByteArray =
    byteDigest().sign(privateKey)

fun NstpV4.CertificateStatusResponse.verifySignature(): Boolean =
    byteDigest().verifySign(statusSignature.toByteArray(), statusCertificate.signingPublicKey.toByteArray())