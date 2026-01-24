package de.axelrindle.keycloak.federation

import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedTrustManager

/**
 * An insecure trust manager which does nothing.
 */
class DummyTrustManager : X509ExtendedTrustManager() {
    override fun checkClientTrusted(
        chain: Array<out X509Certificate?>?,
        authType: String?,
        socket: Socket?
    ) {}

    override fun checkServerTrusted(
        chain: Array<out X509Certificate?>?,
        authType: String?,
        socket: Socket?
    ) {}

    override fun checkClientTrusted(
        chain: Array<out X509Certificate?>?,
        authType: String?,
        engine: SSLEngine?
    ) {}

    override fun checkServerTrusted(
        chain: Array<out X509Certificate?>?,
        authType: String?,
        engine: SSLEngine?
    ) {}

    override fun checkClientTrusted(
        chain: Array<out X509Certificate?>?,
        authType: String?
    ) {}

    override fun checkServerTrusted(
        chain: Array<out X509Certificate?>?,
        authType: String?
    ) {}

    override fun getAcceptedIssuers(): Array<out X509Certificate> = emptyArray()
}