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
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class SdJwtSelectiveDiscloserTest {

    @TempDir
    Path tempDir;

    private SdJwtCredentialBuilder builder(MockIssuerProperties props) {
        return new SdJwtCredentialBuilder(new ObjectMapper(), new MockIssuerKeyService(props), props);
    }

    @Test
    void filtersOnlyRequestedClaims() throws Exception {
        MockIssuerProperties props = new MockIssuerProperties(
                true,
                tempDir.resolve("keys.json"),
                Duration.ofMinutes(5),
                "https://issuer.example/mock",
                tempDir.resolve("cfg.json"),
                List.of()
        );
        CredentialBuildResult built = builder(props).build(
                "cfg-id",
                "urn:example:vct",
                "https://issuer.example/mock",
                Map.of("given_name", "Alice", "family_name", "Holder", "document_number", "DOC-123"),
                null
        );

        SdJwtParser parser = new SdJwtParser(new ObjectMapper());
        SdJwtSelectiveDiscloser discloser = new SdJwtSelectiveDiscloser(parser);

        String filtered = discloser.filter(
                built.encoded(),
                List.of(
                        new SdJwtSelectiveDiscloser.ClaimRequest("given_name", null),
                        new SdJwtSelectiveDiscloser.ClaimRequest("document_number", null)
                ),
                Set.of("given_name", "document_number"));

        Map<String, Object> claims = parser.extractDisclosedClaims(filtered);
        assertThat(claims)
                .containsEntry("given_name", "Alice")
                .containsEntry("document_number", "DOC-123")
                .doesNotContainKey("family_name");

        List<String> filteredDisclosures = discloser.filterDisclosures(
                SdJwtUtils.split(built.encoded()).disclosures(),
                List.of(new SdJwtSelectiveDiscloser.ClaimRequest("given_name", null)),
                Set.of("given_name"));
        assertThat(filteredDisclosures).hasSize(1);
    }
}
