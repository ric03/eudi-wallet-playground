package de.arbeitsagentur.keycloak.wallet.common.credential;

import java.util.List;
import java.util.Map;

/**
 * Normalized result for building a credential in any format.
 */
public record CredentialBuildResult(String encoded,
                                    List<String> disclosures,
                                    Map<String, Object> decoded,
                                    String vct,
                                    String format) {
}
