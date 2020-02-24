import NstpV4.CertificateStatus.*
import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.multiple
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.github.ajalt.clikt.parameters.types.file
import com.github.ajalt.clikt.parameters.types.int
import com.google.protobuf.ByteString
import io.ktor.network.selector.ActorSelectorManager
import io.ktor.network.sockets.Datagram
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.isClosed
import io.ktor.utils.io.core.ByteReadPacket
import io.ktor.utils.io.core.readBytes
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import java.net.InetSocketAddress
import java.time.Instant

object StatusServer : CliktCommand(
    help = "Run a rudimentary status server",
    printHelpOnEmptyArgs = true,
    name = "java -jar nstp-cert-status-server.jar"
) {
    private val ip by option(
        help = "The IP to run on (default 0.0.0.0)"
    ).default("0.0.0.0")

    private val port by option(
        help = "The port to run on (default 22301)"
    ).int().default(22301)

    private val allow by option(
        help = "Files containing certs to approve; may be provided multiple times"
    ).file(folderOkay = false, exists = true, readable = true).multiple()

    private val deny by option(
        help = "Files containing certs to deny; may be provided multiple times"
    ).file(folderOkay = false, exists = true, readable = true).multiple()

    private val certificateFile by option(
        help = "The certificate to include with responses (required)",
        names = *arrayOf("--certificate")
    ).file(folderOkay = false, exists = true, readable = true).required()

    private val privateKeyFile by option(
        help = "The private key for the status server certificate (required)",
        names = *arrayOf("--key")
    ).file(folderOkay = false, exists = true, readable = true).required()

    private val allowCerts by lazy { allow.toLoC() }
    private val denyCerts by lazy { deny.toLoC() }
    private val selfCertificate: NstpV4.Certificate by lazy {
        NstpV4.Certificate.parseFrom(certificateFile.readBytes())
    }
    private val selfPrivateKey: NstpV4.PrivateKey by lazy {
        NstpV4.PrivateKey.parseFrom(privateKeyFile.readBytes())
    }


    override fun run() = runBlocking {
        echo("Will mark ${allow.size} certs as valid")
        echo("Will mark ${deny.size} certs as revoked")
        aSocket(ActorSelectorManager(Dispatchers.IO))
            .udp()
            .bind(InetSocketAddress(ip, port))
            .use { socket ->
                while (!socket.isClosed)
                    (try {
                        socket.receive()
                    } catch (_: Throwable) {
                        null
                    })?.let { datagram ->
                        try {
                            NstpV4.CertificateStatusRequest.parseFrom(datagram.packet.readBytes())
                        } catch (_: Throwable) {
                            echo("Couldn't parse message from ${datagram.address}, ignoring")
                            return@let
                        }.let { it ->
                            NstpV4.CertificateStatusResponse.newBuilder().apply {
                                this.certificate = it.certificate
                                status = when {
                                    it.certificate isIn denyCerts -> REVOKED
                                    it.certificate isIn allowCerts -> VALID
                                    else -> UNKNOWN
                                }
                                validFrom = Instant.now().epochSecond
                                validLength = 10
                                statusCertificate = selfCertificate
                                statusSignature = ByteString.copyFrom(
                                    sign(selfPrivateKey.signingPrivateKey.toByteArray())
                                )
                            }
                        }.build().toByteArray().let {
                            try {
                                socket.send(Datagram(ByteReadPacket(it), datagram.address))
                            } catch (_: Throwable) {
                                echo("Socket closed before a response to ${datagram.address} could be sent")
                            }
                        }
                    }
            }
    }

    private fun List<File>.toLoC(): List<NstpV4.Certificate> = flatMap { file ->
        file.readBytes().let {
            try {
                NstpV4.Certificate.parseFrom(it).run {
                    if (isInitialized) listOf(this)
                    else throw IllegalStateException()
                }
            } catch (_: Throwable) {
                NstpV4.CertificateStore.parseFrom(it).run {
                    if (isInitialized) certificatesList
                    else throw IllegalArgumentException("File $file wasn't a Certificate or CertificateStore message")
                }
            }
        }
    }
}

fun main(args: Array<String>) = StatusServer.main(args)