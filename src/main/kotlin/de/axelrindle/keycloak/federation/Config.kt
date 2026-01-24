package de.axelrindle.keycloak.federation

import org.keycloak.common.util.MultivaluedHashMap
import org.keycloak.component.ComponentModel
import org.keycloak.component.ComponentValidationException
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.provider.ProviderConfigurationBuilder
import java.net.URI
import java.net.URISyntaxException

/**
 * Represents a federation instance configuration.
 */
class Config(map: MultivaluedHashMap<String, String>) {

    companion object {
        const val CONFIG_KEYCLOAK_URL = "keycloak.url"
        const val CONFIG_KEYCLOAK_REALM = "keycloak.realm"
        const val CONFIG_KEYCLOAK_CLIENT_ID = "keycloak.client_id"
        const val CONFIG_KEYCLOAK_CLIENT_SECRET = "keycloak.client_secret"
        const val CONFIG_KEYCLOAK_SKIP_CERTIFICATE_VALIDATION = "keycloak.skip_certificate_validation"

        fun of(model: ComponentModel): Config {
            return Config(model.config)
        }

        val PROVIDER_CONFIG_PROPERTIES: List<ProviderConfigProperty> = ProviderConfigurationBuilder.create()
            .property().name(CONFIG_KEYCLOAK_URL).label("Keycloak URL")
            .type(ProviderConfigProperty.STRING_TYPE)
            .helpText("The base URL of your other Keycloak instance")
            .required(true)
            .add()
            .property().name(CONFIG_KEYCLOAK_SKIP_CERTIFICATE_VALIDATION).label("Skip Certificate Validation")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .helpText("Disables validation of remote HTTPS certificates")
            .required(false).defaultValue(false)
            .add()
            .property().name(CONFIG_KEYCLOAK_REALM).label("Realm")
            .type(ProviderConfigProperty.STRING_TYPE)
            .helpText("The connected realm of your other Keycloak instance")
            .required(true)
            .add()
            .property().name(CONFIG_KEYCLOAK_CLIENT_ID).label("Client ID")
            .type(ProviderConfigProperty.STRING_TYPE)
            .helpText("The client ID of a service account in your other Keycloak instance")
            .required(true)
            .add()
            .property().name(CONFIG_KEYCLOAK_CLIENT_SECRET).label("Client Secret")
            .type(ProviderConfigProperty.PASSWORD)
            .helpText("The client secret of a service account in your other Keycloak instance")
            .required(true)
            .add()
            .build()
    }

    val keycloakUrl: String =
        map.getFirst(CONFIG_KEYCLOAK_URL).removeSuffix("/")
    val keycloakRealm: String =
        map.getFirst(CONFIG_KEYCLOAK_REALM)
    val keycloakClientId: String =
        map.getFirst(CONFIG_KEYCLOAK_CLIENT_ID)
    val keycloakClientSecret: String =
        map.getFirst(CONFIG_KEYCLOAK_CLIENT_SECRET)
    val keycloakSkipCertificateValidation: Boolean =
        map.getFirst(CONFIG_KEYCLOAK_SKIP_CERTIFICATE_VALIDATION).toBoolean()

    @Throws(ComponentValidationException::class)
    fun validate() {
        try {
            URI(keycloakUrl).toURL()
        } catch (e: URISyntaxException) {
            throw ComponentValidationException("invalid url", e.cause)
        }
    }

}
