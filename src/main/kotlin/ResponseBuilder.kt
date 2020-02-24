import NstpV4.CertificateStatus.*
import NstpV4.HashAlgorithm.*
import com.google.protobuf.ByteString
import java.time.Instant
import kotlin.math.roundToLong
import kotlin.random.Random
import kotlin.time.days

sealed class ResponseBuilder {
    abstract fun StatusServer.makeResponse(request: NstpV4.CertificateStatusRequest): NstpV4.CertificateStatusResponse?

    companion object {
        private fun StatusServer.validResponseHelper(request: NstpV4.CertificateStatusRequest): NstpV4.CertificateStatusResponse.Builder {
            return NstpV4.CertificateStatusResponse.newBuilder().apply {
                this.certificate = request.certificate
                status = when {
                    request.certificate isIn denyCerts -> REVOKED
                    request.certificate isIn allowCerts -> VALID
                    else -> UNKNOWN
                }
                validFrom = Instant.now().epochSecond
                validLength = 10
                statusCertificate = selfCertificate
                statusSignature = ByteString.copyFrom(
                    sign(selfPrivateKey.signingPrivateKey.toByteArray())
                )
            }
        }
    }

    object Valid : ResponseBuilder() {
        override fun StatusServer.makeResponse(request: NstpV4.CertificateStatusRequest): NstpV4.CertificateStatusResponse? =
            validResponseHelper(request).build()
    }

    object Ignoring : ResponseBuilder() {
        override fun StatusServer.makeResponse(request: NstpV4.CertificateStatusRequest): NstpV4.CertificateStatusResponse? {
            return null
        }
    }

    object Invalid : ResponseBuilder() {
        private fun <T> T.alsoDescribe(description: String): T {
            println("Intentionally sent an invalid response message: $description")
            return this
        }

        override fun StatusServer.makeResponse(request: NstpV4.CertificateStatusRequest): NstpV4.CertificateStatusResponse? {
            val error = Random.nextInt(12)
            return validResponseHelper(request).apply {
                when (error) {
                    0 -> clearCertificate().alsoDescribe("Empty hash")
                    1 -> certificate = certificate.toBuilder().apply {
                        value = ByteString.copyFrom(value.toByteArray() + "foo".toByteArray())
                    }.build().alsoDescribe("Wrong hash")
                    2 -> certificate = certificate.toBuilder().apply {
                        algorithm = when (algorithm) {
                            SHA512 -> SHA256
                            SHA256 -> SHA512
                            else -> IDENTITY
                        }
                    }.build().alsoDescribe("Opposite certificate hash algorithm")
                    3 -> {
                        statusValue = -1
                        alsoDescribe("Unknown status value (CertificateStatus.UNRECOGNIZED in JVM-land)")
                    }
                    4 -> {
                        validFrom += 1.days.inSeconds.roundToLong()
                        alsoDescribe("Not valid yet")
                    }
                    5 -> {
                        validFrom = Long.MAX_VALUE - 1
                        alsoDescribe("Not valid yet with a slight chance of overflow")
                    }
                    6 -> {
                        validFrom -= 1.days.inSeconds.roundToLong()
                        alsoDescribe("Not valid anymore (very old)")
                    }
                    7 -> {
                        validFrom -= 1
                        validLength = 0
                        alsoDescribe("Not valid anymore (expired a second ago)")
                    }
                    8 -> statusCertificate = statusCertificate.toBuilder().apply {
                        addSubjects("foo")
                    }.build().alsoDescribe("Wrong status cert subjects")
                    9 -> statusCertificate = statusCertificate.toBuilder().apply {
                        issuer = hash()
                    }.build().alsoDescribe("Wrong status cert hash (issuer is itself)")
                    10 -> statusCertificate = statusCertificate.toBuilder().apply {
                        issuerSignature = ByteString.copyFrom(
                            "foo".toByteArray().sign(selfPrivateKey.signingPrivateKey.toByteArray())
                        )
                    }.build().alsoDescribe("Wrong status cert status cert signature")
                }

                // Either fix the signature or mess it up intentionally
                statusSignature =
                    if (error > 10) ByteString.copyFrom(
                        "foo".toByteArray().sign(selfPrivateKey.signingPrivateKey.toByteArray())
                    ).alsoDescribe("Response signature incorrect")
                    else ByteString.copyFrom(
                        sign(selfPrivateKey.signingPrivateKey.toByteArray())
                    )
            }.build()
        }
    }
}