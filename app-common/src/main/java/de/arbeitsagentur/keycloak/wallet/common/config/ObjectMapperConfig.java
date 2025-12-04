package de.arbeitsagentur.keycloak.wallet.common.config;

import tools.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ObjectMapperConfig {

    @Bean
    ObjectMapper objectMapper() {
        return new ObjectMapper();
    }
}
