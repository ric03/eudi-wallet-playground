package de.arbeitsagentur.keycloak.wallet.mockissuer.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

@ConfigurationProperties(prefix = "mock-issuer")
public record MockIssuerProperties(
        Boolean enabled,
        Path keyFile,
        Duration credentialTtl,
        String issuerId,
        Path configurationFile,
        List<CredentialConfiguration> configurations
) {
    public MockIssuerProperties {
        if (enabled == null) {
            enabled = Boolean.TRUE;
        }
        if (keyFile == null) {
            keyFile = Path.of("config/mock-issuer-keys.json");
        }
        if (credentialTtl == null) {
            credentialTtl = Duration.ofMinutes(10);
        }
        if (configurationFile == null) {
            configurationFile = Path.of("config/mock-issuer-configurations.json");
        }
        if (configurations == null) {
            configurations = List.of();
        }
    }

    public record CredentialConfiguration(String id, String format, String scope, String name, String vct,
                                          List<ClaimTemplate> claims) {
        public CredentialConfiguration {
            if (claims == null) {
                claims = List.of();
            }
        }
    }

    public record ClaimTemplate(String name, String label, String defaultValue, Boolean required) {
        public ClaimTemplate {
            label = (label == null || label.isBlank()) ? name : label;
            required = Objects.requireNonNullElse(required, Boolean.FALSE);
        }
    }
}
