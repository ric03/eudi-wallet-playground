package de.arbeitsagentur.keycloak.wallet.common.sdjwt;

import com.fasterxml.jackson.databind.ObjectMapper;
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

class SdJwtCredentialBuilderTest {

    @TempDir
    Path tempDir;

    @Test
    void buildsSdJwtWithDisclosuresAndClaims() {
        MockIssuerProperties props = new MockIssuerProperties(
                true,
                tempDir.resolve("keys.json"),
                Duration.ofMinutes(5),
                "https://issuer.example/mock",
                tempDir.resolve("cfg.json"),
                List.of()
        );
        MockIssuerKeyService keyService = new MockIssuerKeyService(props);
        SdJwtCredentialBuilder builder = new SdJwtCredentialBuilder(new ObjectMapper(), keyService, props);

        CredentialBuildResult result = builder.build("cfg-id", "urn:example:vct", "https://issuer.example/mock",
                Map.of("given_name", "Alice", "family_name", "Holder"), null);

        assertThat(result.format()).isEqualTo("dc+sd-jwt");
        assertThat(result.encoded()).contains("~");
        assertThat(result.disclosures()).isNotEmpty();
        assertThat(result.decoded().get("claims")).isInstanceOf(Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> claims = (Map<String, Object>) result.decoded().get("claims");
        assertThat(claims).containsEntry("given_name", "Alice");
    }
}
