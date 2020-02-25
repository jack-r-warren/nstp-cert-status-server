import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.options.*
import com.github.ajalt.clikt.parameters.types.file
import com.github.ajalt.clikt.parameters.types.int
import io.ktor.network.selector.ActorSelectorManager
import io.ktor.network.sockets.Datagram
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.isClosed
import io.ktor.utils.io.core.ByteReadPacket
import io.ktor.utils.io.core.readBytes
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.IllegalArgumentException
import java.net.InetSocketAddress
import java.net.SocketAddress

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

    private val responseType by option(
        help = "Set how you'd like the server to respond to messages (default valid)",
        helpTags = mapOf(
            "valid" to "Respond normally",
            "invalid" to "Respond with messages that are incorrect in some way",
            "ignore" to "Ignore all messages"
        )
    ).switch(
        "--valid" to ResponseBuilder.Valid,
        "--invalid" to ResponseBuilder.Invalid,
        "--ignore" to ResponseBuilder.Ignore
    ).default(ResponseBuilder.Valid)

    private val verbosity by option(
        help = "Set how much output you'd like (default silent)",
        helpTags = mapOf(
            "silent" to "As quiet as possible, though errors (intentional or unintentional) will be printed",
            "print" to "Print when a response is sent",
            "verbose" to "Print the actual content of every response (null means nothing sent)"
        )
    ).switch(
        "--silent" to { _: NstpV4.CertificateStatusResponse?, _: SocketAddress -> },
        "--print" to { content: NstpV4.CertificateStatusResponse?, from: SocketAddress -> content?.run { echo("Responded to $from with $status") } },
        "--verbose" to { content: NstpV4.CertificateStatusResponse?, from: SocketAddress -> echo("Responded to $from with ${content?.run { status }}\n${content.toString()}") }
    ).default { _: Any?, _: SocketAddress -> }

    val allowCerts by lazy { allow.toListOfCertificate() }
    val denyCerts by lazy { deny.toListOfCertificate() }
    val selfCertificate: NstpV4.Certificate by lazy {
        NstpV4.Certificate.parseFrom(certificateFile.readBytes())
    }
    val selfPrivateKey: NstpV4.PrivateKey by lazy {
        NstpV4.PrivateKey.parseFrom(privateKeyFile.readBytes())
    }

    override fun run() = runBlocking {
        echo("Will mark ${allow.size} certs as valid")
        echo("Will mark ${deny.size} certs as revoked")
        if (allow.isEmpty() && deny.isEmpty()) echo("No certificates passed to --allow or --deny, will mark all as UNKNOWN")
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
                        }.let {
                            with(responseType) { makeResponse(it) }
                        }.also {
                            verbosity.invoke(it, datagram.address)
                        }?.toByteArray()?.let {
                            try {
                                socket.send(Datagram(ByteReadPacket(it), datagram.address))
                            } catch (_: Throwable) {
                                echo("Socket closed before a response to ${datagram.address} could be sent")
                            }
                        }
                    }
            }
    }

    private fun List<File>.toListOfCertificate(): List<NstpV4.Certificate> =
        flatMap { file ->
            file.readBytes().let { bytes ->
                kotlin.runCatching { NstpV4.Certificate.parseFrom(bytes) }.getOrNull()
                    ?.run { if (isInitialized) return@flatMap listOf(this) }
                kotlin.runCatching { NstpV4.CertificateStore.parseFrom(bytes) }.getOrNull()
                    ?.run { if (isInitialized) return@flatMap certificatesList }
                kotlin.runCatching { NstpV4.PinnedCertificateStore.parseFrom(bytes) }.getOrNull()?.run {
                    if (isInitialized) throw IllegalArgumentException("$file was not a Certificate or CertificateStore, it was a PinnedCertificateStore")
                }
                kotlin.runCatching { NstpV4.PrivateKey.parseFrom(bytes) }.getOrNull()?.run {
                    if (isInitialized) throw IllegalArgumentException("$file was not a Certificate or CertificateStore, it was a PrivateKey")
                }
                throw IllegalArgumentException("$file was not a Certificate or CertificateStore")
            }
        }
}

fun main(args: Array<String>) = StatusServer.main(args)