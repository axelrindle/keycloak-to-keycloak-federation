package de.axelrindle.keycloak.federation

import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/**
 * Transforms a map of string<>string entries to a url-encoded query string.
 *
 * The result does not start with a question mark.
 */
fun urlEncode(map: Map<String, String>): String {
    return map.entries.joinToString("&") {
        it.key + "=" + URLEncoder.encode(it.value, StandardCharsets.UTF_8)
    }
}