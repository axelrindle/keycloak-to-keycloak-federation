package de.axelrindle.keycloak.federation

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import de.axelrindle.keycloak.federation.KeycloakProviderFactory.Companion.LOGGER
import org.apache.http.HttpStatus
import org.keycloak.component.ComponentModel
import org.keycloak.credential.CredentialInput
import org.keycloak.credential.CredentialInputValidator
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.models.credential.PasswordCredentialModel
import org.keycloak.representations.AccessTokenResponse
import org.keycloak.representations.account.UserRepresentation
import org.keycloak.storage.DatastoreProvider
import org.keycloak.storage.UserStorageProvider
import org.keycloak.storage.datastore.DefaultDatastoreProvider
import org.keycloak.storage.user.ImportedUserValidation
import org.keycloak.storage.user.UserLookupProvider
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpRequest.BodyPublishers
import java.net.http.HttpResponse
import java.security.SecureRandom
import java.time.Instant
import javax.net.ssl.SSLContext

class KeycloakProvider(
    private val session: KeycloakSession,
    private val model: ComponentModel,
) : UserStorageProvider,
    UserLookupProvider,
    CredentialInputValidator,
    ImportedUserValidation {

    private val config = Config.of(model)

    private val mapper = ObjectMapper()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
    private val userListType = mapper.typeFactory
        .constructCollectionType(List::class.java, UserRepresentation::class.java)

    private val http: HttpClient by lazy {
        var builder = HttpClient.newBuilder()

        if (config.keycloakSkipCertificateValidation) {
            builder = builder.sslContext(SSLContext.getInstance("TLSv1.2").apply {
                init(null, arrayOf(DummyTrustManager()), SecureRandom.getInstanceStrong())
            })
        }

        builder.build()
    }

    private var token: String? = null
    private var tokenExpiry: Instant = Instant.now()

    override fun close() {
        this.token = null
        this.http.close()
    }

    private fun getClientToken(): String {
        if (token != null && tokenExpiry.isAfter(Instant.now())) {
            return token!!
        }

        LOGGER.debug("retrieving new access token")

        val params = mapOf(
            "grant_type" to "client_credentials",
            "client_id" to config.keycloakClientId,
            "client_secret" to config.keycloakClientSecret
        )
        val req = HttpRequest.newBuilder()
            .uri(URI(String.format("%s/realms/%s/protocol/openid-connect/token", config.keycloakUrl, config.keycloakRealm)))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(BodyPublishers.ofString(urlEncode(params)))
            .build()

        val res = http.send(req, HttpResponse.BodyHandlers.ofInputStream())
        val result = mapper.readValue(res.body(), AccessTokenResponse::class.java)

        this.token = result.token
        this.tokenExpiry = Instant.now().plusSeconds(result.expiresIn - 5)

        if (result.error != null) {
            throw RuntimeException(result.errorDescription)
        }

        return result.token
    }

    private fun storeUser(realm: RealmModel, federated: UserRepresentation): UserModel {
        val provider = (session.getProvider(DatastoreProvider::class.java) as DefaultDatastoreProvider).userLocalStorage()
        val user = provider.getUserByUsername(realm, federated.username) ?: provider.addUser(realm, federated.username)

        user.federationLink = model.id
        user.isEnabled = true
        user.isEmailVerified = true
        user.email = federated.email
        user.firstName = federated.firstName
        user.lastName = federated.lastName

        if (federated.attributes != null) {
            user.attributes.putAll(federated.attributes)
        }

        return user
    }

    override fun getUserById(
        realm: RealmModel,
        id: String
    ): UserModel? {
        val actualUserId = id.substringAfterLast(":")

        LOGGER.debug("retrieving user by id $actualUserId")

        val token = getClientToken()

        val req = HttpRequest.newBuilder()
            .uri(URI(String.format("%s/admin/realms/%s/users/%s", config.keycloakUrl, config.keycloakRealm, actualUserId)))
            .header("Authorization", "Bearer $token")
            .GET()
            .build()

        val res = http.send(req, HttpResponse.BodyHandlers.ofInputStream())
        val result = mapper.readValue(res.body(), UserRepresentation::class.java) ?: return null

        LOGGER.debug("got result ${result.id}")

        return storeUser(realm, result)
    }

    override fun getUserByEmail(
        realm: RealmModel,
        email: String
    ): UserModel? {
        LOGGER.debug("retrieving user by email $email")
        return getByAttribute(realm, "email", email)
    }

    override fun getUserByUsername(
        realm: RealmModel,
        username: String
    ): UserModel? {
        LOGGER.debug("retrieving user by username $username")
        return getByAttribute(realm, "username", username)
    }

    private fun getByAttribute(
        realm: RealmModel,
        attributeName: String,
        attributeValue: String,
    ): UserModel? {
        val token = getClientToken()

        // TODO: Configuration for some parameters
        val params = mapOf(
            "max" to "10",
            "briefRepresentation" to "true",
            "emailVerified" to "true",
            "enabled" to "true",
            "exact" to "true",
            attributeName to attributeValue,
        )
        val req = HttpRequest.newBuilder()
            .uri(URI(String.format("%s/admin/realms/%s/users?%s", config.keycloakUrl, config.keycloakRealm, urlEncode(params))))
            .header("Authorization", "Bearer $token")
            .GET()
            .build()

        val res = http.send(req, HttpResponse.BodyHandlers.ofInputStream())
        val result = mapper.readValue<List<UserRepresentation>>(res.body(), userListType)

        LOGGER.debug("got ${result.size} results")

        if (result.size != 1) {
            return null
        }

        val rep = result.first()

        return storeUser(realm, rep)
    }

    override fun supportsCredentialType(credentialType: String): Boolean {
        return credentialType == PasswordCredentialModel.TYPE
    }

    override fun isConfiguredFor(
        realm: RealmModel,
        user: UserModel,
        credentialType: String
    ): Boolean {
        return this.supportsCredentialType(credentialType)
    }

    override fun isValid(
        realm: RealmModel,
        user: UserModel,
        credentialInput: CredentialInput
    ): Boolean {
        LOGGER.debug("retrieving new user token")

        val params = mapOf(
            "grant_type" to "password",
            "client_id" to config.keycloakClientId,
            "client_secret" to config.keycloakClientSecret,
            "username" to user.username,
            "password" to credentialInput.challengeResponse,
        )
        val req = HttpRequest.newBuilder()
            .uri(URI(String.format("%s/realms/%s/protocol/openid-connect/token", config.keycloakUrl, config.keycloakRealm)))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(BodyPublishers.ofString(urlEncode(params)))
            .build()

        val res = http.send(req, HttpResponse.BodyHandlers.ofInputStream())
        if (res.statusCode() != HttpStatus.SC_OK) {
            return false
        }

        // TODO: revoke session immediately?
        //val result = mapper.readValue(res.body(), AccessTokenResponse::class.java)
        return true
    }

    override fun validate(
        realm: RealmModel,
        user: UserModel
    ): UserModel? {
        LOGGER.debug("validate ${user.username}")
        return getUserByUsername(realm, user.username)
    }


}