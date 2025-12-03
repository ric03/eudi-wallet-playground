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

import static org.assertj.core.api.Assertions.assertThat;

class MdocParserTest {

    @TempDir
    Path tempDir;

    private final MdocParser parser = new MdocParser();

    @Test
    void parsesClaimsAndDocType() {
        MockIssuerProperties props = new MockIssuerProperties(
                true,
                tempDir.resolve("keys.json"),
                Duration.ofMinutes(5),
                "https://issuer.example/mock",
                tempDir.resolve("cfg.json"),
                List.of()
        );
        MdocCredentialBuilder builder = new MdocCredentialBuilder(new MockIssuerKeyService(props), props);
        CredentialBuildResult built = builder.build("cfg-id", "urn:example:pid", "https://issuer.example/mock",
                Map.of("given_name", "Alice"), null);
        String hex = built.encoded();

        assertThat(parser.isHex(hex)).isTrue();
        Map<String, Object> claims = parser.extractClaims(hex);
        assertThat(claims).containsEntry("given_name", "Alice");
        assertThat(parser.extractDocType(hex)).isEqualTo("urn:example:pid");
    }
}
