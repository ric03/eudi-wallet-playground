package de.arbeitsagentur.keycloak.wallet.common.sdjwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
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

class SdJwtUtilsTest {

    @TempDir
    Path tempDir;

    private SdJwtCredentialBuilder builder(MockIssuerProperties props) {
        return new SdJwtCredentialBuilder(new ObjectMapper(), new MockIssuerKeyService(props), props);
    }

    @Test
    void splitsAndValidatesDisclosures() throws Exception {
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
                Map.of("given_name", "Alice", "family_name", "Holder"),
                null
        );

        SdJwtUtils.SdJwtParts parts = SdJwtUtils.split(built.encoded());
        assertThat(parts.signedJwt()).isNotBlank();
        assertThat(parts.disclosures()).hasSize(2);

        SignedJWT jwt = SignedJWT.parse(parts.signedJwt());
        ObjectMapper mapper = new ObjectMapper();
        assertThat(SdJwtUtils.verifyDisclosures(jwt, parts, mapper)).isTrue();

        Map<String, Object> claims = SdJwtUtils.extractDisclosedClaims(parts, mapper);
        assertThat(claims)
                .containsEntry("given_name", "Alice")
                .containsEntry("family_name", "Holder");
    }
}
