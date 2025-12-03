package de.arbeitsagentur.keycloak.wallet.common.mdoc;

import de.arbeitsagentur.keycloak.wallet.common.credential.CredentialBuildResult;
import de.arbeitsagentur.keycloak.wallet.mockissuer.MockIssuerKeyService;
import de.arbeitsagentur.keycloak.wallet.mockissuer.config.MockIssuerProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class MdocSelectiveDiscloserTest {

    @TempDir
    Path tempDir;

    private final MdocSelectiveDiscloser discloser = new MdocSelectiveDiscloser();
    private final MdocParser parser = new MdocParser();

    @Test
    void filtersRequestedClaimsAndKeepsDocType() {
        MockIssuerProperties props = new MockIssuerProperties(
                true,
                tempDir.resolve("keys.json"),
                Duration.ofMinutes(5),
                "https://issuer.example/mock",
                tempDir.resolve("cfg.json"),
                List.of()
        );
        MdocCredentialBuilder builder = new MdocCredentialBuilder(new MockIssuerKeyService(props), props);
        CredentialBuildResult built = builder.build(
                "cfg-id",
                "urn:example:pid",
                "https://issuer.example/mock",
                Map.of("given_name", "Alice", "family_name", "Holder", "document_number", "12345"),
                null
        );

        String filtered = discloser.filter(built.encoded(), Set.of("given_name", "document_number"));
        Map<String, Object> claims = parser.extractClaims(filtered);

        assertThat(filtered).isNotBlank();
        assertThat(parser.extractDocType(filtered)).isEqualTo("urn:example:pid");
        assertThat(claims)
                .containsEntry("given_name", "Alice")
                .containsEntry("document_number", "12345")
                .doesNotContainKey("family_name");
    }

    @Test
    void returnsOriginalWhenNoRequests() {
        MockIssuerProperties props = new MockIssuerProperties(
                true,
                tempDir.resolve("keys.json"),
                Duration.ofMinutes(5),
                "https://issuer.example/mock",
                tempDir.resolve("cfg.json"),
                List.of()
        );
        MdocCredentialBuilder builder = new MdocCredentialBuilder(new MockIssuerKeyService(props), props);
        CredentialBuildResult built = builder.build(
                "cfg-id",
                "urn:example:pid",
                "https://issuer.example/mock",
                Map.of("given_name", "Alice"),
                null
        );

        String filtered = discloser.filter(built.encoded(), Set.of());
        assertThat(filtered).isEqualTo(built.encoded());
    }
}
