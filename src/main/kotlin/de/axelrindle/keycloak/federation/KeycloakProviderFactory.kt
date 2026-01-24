package de.axelrindle.keycloak.federation

import org.jboss.logging.Logger
import org.keycloak.component.ComponentModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.storage.UserStorageProviderFactory

class KeycloakProviderFactory : UserStorageProviderFactory<KeycloakProvider> {

    companion object {
        val LOGGER: Logger = Logger.getLogger(KeycloakProviderFactory::class.java)
    }

    override fun getId() = "Keycloak"

    override fun create(session: KeycloakSession, model: ComponentModel): KeycloakProvider {
        return KeycloakProvider(session, model)
    }

    override fun getConfigProperties() = Config.PROVIDER_CONFIG_PROPERTIES

    override fun validateConfiguration(session: KeycloakSession, realm: RealmModel, config: ComponentModel) {
        Config.of(config).validate()
    }
}
