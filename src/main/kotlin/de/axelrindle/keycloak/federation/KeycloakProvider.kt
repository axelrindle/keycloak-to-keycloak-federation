package de.axelrindle.keycloak.federation

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.http.HttpStatus
import org.jboss.logging.Logger
import org.keycloak.component.ComponentModel
import org.keycloak.credential.CredentialInput
import org.keycloak.credential.CredentialInputValidator
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.models.credential.OTPCredentialModel
import org.keycloak.models.credential.PasswordCredentialModel
import org.keycloak.representations.AccessTokenResponse
import org.keycloak.representations.account.UserRepresentation
import org.keycloak.representations.idm.CredentialRepresentation
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

    companion object {
        val SUPPORTED_CREDENTIAL_TYPES = listOf(
            PasswordCredentialModel.TYPE,
            OTPCredentialModel.TYPE,
            OTPCredentialModel.TOTP,
            OTPCredentialModel.HOTP,
        )

        const val USER_ATTRIBUTE_EXTERNAL_ID = "external_id"

        private val LOGGER: Logger = Logger.getLogger(KeycloakProviderFactory::class.java)

        private val objectMapper = ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
        private val userListType = objectMapper.typeFactory
            .constructCollectionType(List::class.java, UserRepresentation::class.java)
        private val credentialListType = objectMapper.typeFactory
            .constructCollectionType(List::class.java, CredentialRepresentation::class.java)
    }

    private val config = Config.of(model)

    private val http: HttpClient by lazy {
        var builder = HttpClient.newBuilder()

        if (config.keycloakSkipCertificateValidation) {
            builder = builder.sslContext(SSLContext.getDefault().apply {
                init(null, arrayOf(DummyTrustManager()), SecureRandom.getInstanceStrong())
            })
        }

        builder.build()
    }

    /**
     * The currently cached client access token used for provider operation.
     */
    private var token: String? = null

    /**
     * An indication of when the current client access token expires.
     * Usually set to an instant slightly before the actual expiration.
     */
    private var tokenExpiry: Instant = Instant.now()

    override fun close() {
        this.token = null
        this.http.close()
    }

    /**
     * Request an access token from the remote Keycloak required for provider operation.
     * Upon success the issued token is cached until it's expiration to reduce requests
     * to the remote Keycloak instance.
     *
     * @see token
     * @see tokenExpiry
     */
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
        val result = objectMapper.readValue(res.body(), AccessTokenResponse::class.java)

        this.token = result.token
        this.tokenExpiry = Instant.now().plusSeconds(result.expiresIn - 5)

        if (result.error != null) {
            throw RuntimeException(result.errorDescription)
        }

        return result.token
    }

    /**
     * Create or update a federated user in the local Keycloak storage.
     * The remote user's username serves as the primary key.
     */
    private fun storeUser(realm: RealmModel, federated: UserRepresentation): UserModel {
        val provider = (session.getProvider(DatastoreProvider::class.java) as DefaultDatastoreProvider).userLocalStorage()
        val user = provider.getUserByUsername(realm, federated.username) ?: provider.addUser(realm, federated.username)

        user.setSingleAttribute(USER_ATTRIBUTE_EXTERNAL_ID, federated.id)
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
        val result = objectMapper.readValue(res.body(), UserRepresentation::class.java) ?: return null

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
        return getByAttribute(realm, "username", username) ?: getUserByEmail(realm, username)
    }

    /**
     * Query a user from the remote Keycloak instance based on a single attribute.
     *
     * @param realm The current realm we're operating in.
     * @param attributeName The attribute name to query.
     * @param attributeValue The attribute value to query.
     */
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
        val result = objectMapper.readValue<List<UserRepresentation>>(res.body(), userListType)

        LOGGER.debug("got ${result.size} results")

        if (result.size != 1) {
            return null
        }

        val rep = result.first()

        return storeUser(realm, rep)
    }

    override fun supportsCredentialType(credentialType: String): Boolean {
        return SUPPORTED_CREDENTIAL_TYPES.contains(credentialType)
    }

    override fun isConfiguredFor(
        realm: RealmModel,
        user: UserModel,
        credentialType: String
    ): Boolean {
        val token = getClientToken()

        val userId = user.getFirstAttribute(USER_ATTRIBUTE_EXTERNAL_ID)
        if (userId == null) {
            LOGGER.warn("user ${user.id} is not a federated user")
            return false
        }

        val req = HttpRequest.newBuilder()
            .uri(URI(String.format("%s/admin/realms/%s/users/%s/credentials", config.keycloakUrl, config.keycloakRealm, userId)))
            .header("Authorization", "Bearer $token")
            .GET()
            .build()

        val res = http.send(req, HttpResponse.BodyHandlers.ofInputStream())
        if (res.statusCode() != HttpStatus.SC_OK) {
            val body = res.body().bufferedReader().readText()
            LOGGER.error("isConfiguredFor failed for user ${user.id}")
            LOGGER.error(body)
            return false
        }

        val result = objectMapper.readValue<List<CredentialRepresentation>>(res.body(), credentialListType)

        return result.any { it.type == credentialType }
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
            credentialInput.type to credentialInput.challengeResponse,
        )
        val req = HttpRequest.newBuilder()
            .uri(URI(String.format("%s/realms/%s/protocol/openid-connect/token", config.keycloakUrl, config.keycloakRealm)))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(BodyPublishers.ofString(urlEncode(params)))
            .build()

        val res = http.send(req, HttpResponse.BodyHandlers.ofString())
        if (res.statusCode() != HttpStatus.SC_OK) {
            LOGGER.error("Remote Keycloak denied authentication request: ${res.body()}")
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
