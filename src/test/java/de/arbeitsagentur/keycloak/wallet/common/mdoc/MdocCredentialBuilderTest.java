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

class MdocCredentialBuilderTest {

    @TempDir
    Path tempDir;

    @Test
    void buildsMdocWithHexEncodingAndIssuerSigned() {
        MockIssuerProperties props = new MockIssuerProperties(
                true,
                tempDir.resolve("keys.json"),
                Duration.ofMinutes(5),
                "https://issuer.example/mock",
                tempDir.resolve("cfg.json"),
                List.of()
        );
        MockIssuerKeyService keyService = new MockIssuerKeyService(props);
        MdocCredentialBuilder builder = new MdocCredentialBuilder(keyService, props);

        CredentialBuildResult result = builder.build("cfg-id", "urn:example:pid", "https://issuer.example/mock",
                Map.of("given_name", "Alice"), null);

        assertThat(result.format()).isEqualTo("mso_mdoc");
        assertThat(result.encoded()).matches("^[0-9a-fA-F]+$");
        assertThat(result.decoded().get("issuerSigned")).isInstanceOf(Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> claims = (Map<String, Object>) result.decoded().get("claims");
        assertThat(claims).containsEntry("given_name", "Alice");
    }
}
