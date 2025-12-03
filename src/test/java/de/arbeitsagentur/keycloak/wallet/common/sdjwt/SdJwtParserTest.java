package de.arbeitsagentur.keycloak.wallet.common.sdjwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.arbeitsagentur.keycloak.wallet.common.credential.CredentialBuildResult;
import de.arbeitsagentur.keycloak.wallet.mockissuer.MockIssuerKeyService;
import de.arbeitsagentur.keycloak.wallet.mockissuer.config.MockIssuerProperties;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class SdJwtParserTest {

    @TempDir
    Path tempDir;

    private final SdJwtParser parser = new SdJwtParser(new ObjectMapper());
    private SdJwtCredentialBuilder builder(MockIssuerProperties props) {
        return new SdJwtCredentialBuilder(new ObjectMapper(), new MockIssuerKeyService(props), props);
    }

    @Test
    void detectsAndParsesSdJwt() {
        MockIssuerProperties props = new MockIssuerProperties(
                true,
                tempDir.resolve("keys.json"),
                Duration.ofMinutes(5),
                "https://issuer.example/mock",
                tempDir.resolve("cfg.json"),
                List.of()
        );
        CredentialBuildResult built = builder(props).build("cfg-id", "urn:example:vct", "https://issuer.example/mock",
                Map.of("given_name", "Alice"), null);
        String sdJwt = built.encoded();

        assertThat(parser.isSdJwt(sdJwt)).isTrue();
        assertThat(parser.signedJwt(sdJwt)).isNotBlank();
        assertThat(parser.disclosures(sdJwt)).isNotEmpty();
    }

    @Test
    void extractsClaimsAndRebuilds() {
        MockIssuerProperties props = new MockIssuerProperties(
                true,
                tempDir.resolve("keys.json"),
                Duration.ofMinutes(5),
                "https://issuer.example/mock",
                tempDir.resolve("cfg.json"),
                List.of()
        );
        CredentialBuildResult built = builder(props).build("cfg-id", "urn:example:vct", "https://issuer.example/mock",
                Map.of("address.country", "DE", "given_name", "Alice"), null);

        Map<String, Object> claims = parser.extractDisclosedClaims(built.encoded());
        assertThat(claims).containsEntry("address.country", "DE");
        assertThat(parser.extractVct(built.encoded())).isEqualTo("urn:example:vct");

        String rebuilt = parser.rebuildForRequestedClaims(built.encoded(), List.of(), Set.of("address.country"));
        Map<String, Object> rebuiltClaims = parser.extractDisclosedClaims(rebuilt);
        assertThat(rebuiltClaims).containsEntry("address.country", "DE");
        assertThat(rebuiltClaims).doesNotContainKey("given_name");
    }

    @Test
    void appendsGivenDisclosures() {
        String base = "h.p.s";
        String disclosureA = "WyJmb28iLCJiYXIiXQ";
        String rebuilt = parser.withDisclosures(base, List.of(disclosureA));
        assertThat(rebuilt).isEqualTo(base + "~" + disclosureA);
    }
}
