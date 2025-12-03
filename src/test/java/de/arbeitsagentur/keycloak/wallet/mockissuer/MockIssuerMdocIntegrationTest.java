package de.arbeitsagentur.keycloak.wallet.mockissuer;

import COSE.AlgorithmID;
import COSE.OneKey;
import COSE.Sign1Message;
import com.upokecenter.cbor.CBORObject;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.crypto.WalletKeyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.net.URI;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class MockIssuerMdocIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private WalletKeyService walletKeyService;

    @Autowired
    private MockIssuerKeyService mockIssuerKeyService;

    @Autowired
    private ObjectMapper objectMapper;

    private final CBORMapper cborMapper = new CBORMapper();

    @Test
    void issuesMdocCredentialEndToEnd() throws Exception {
        Map<String, Object> offerRequest = Map.of(
                "configurationId", "mock-pid-mdoc",
                "format", "mso_mdoc",
                "vct", "urn:example:pid:mock",
                "claims", List.of(Map.of("name", "given_name", "value", "Alice"))
        );

        ResponseEntity<Map> offer = restTemplate.postForEntity(baseUrl("/mock-issuer/offers"), offerRequest, Map.class);
        assertThat(offer.getStatusCode().is2xxSuccessful()).isTrue();
        String preAuth = String.valueOf(offer.getBody().get("preAuthorizedCode"));
        assertThat(preAuth).isNotBlank();

        MultiValueMap<String, String> tokenForm = new LinkedMultiValueMap<>();
        tokenForm.add("pre-authorized_code", preAuth);
        ResponseEntity<Map> tokenResponse = restTemplate.postForEntity(baseUrl("/mock-issuer/token"), tokenForm, Map.class);
        assertThat(tokenResponse.getStatusCode().is2xxSuccessful()).isTrue();
        Map<String, Object> tokenBody = tokenResponse.getBody();
        assertThat(tokenBody).isNotNull();
        String cNonce = String.valueOf(tokenBody.get("c_nonce"));
        String accessToken = String.valueOf(tokenBody.get("access_token"));

        String proof = buildProof(baseUrl("/mock-issuer"), cNonce);

        Map<String, Object> credentialRequest = Map.of(
                "credential_configuration_id", "mock-pid-mdoc",
                "format", "mso_mdoc",
                "proof", Map.of("proof_type", "jwt", "jwt", proof)
        );
        RequestEntity<Map<String, Object>> credentialEntity = RequestEntity
                .post(URI.create(baseUrl("/mock-issuer/credential")))
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .contentType(MediaType.APPLICATION_JSON)
                .body(credentialRequest);
        ResponseEntity<Map> credentialResponse = restTemplate.exchange(credentialEntity, Map.class);
        assertThat(credentialResponse.getStatusCode().is2xxSuccessful()).isTrue();
        Map<String, Object> credentialBody = credentialResponse.getBody();
        assertThat(credentialBody).isNotNull();
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> credentials = (List<Map<String, Object>>) credentialBody.get("credentials");
        assertThat(credentials).isNotEmpty();
        Map<String, Object> first = credentials.get(0);
        assertThat(first.get("format")).isEqualTo("mso_mdoc");
        String hex = first.get("credential").toString();
        assertThat(hex).matches("^[0-9a-fA-F]+$");

        byte[] decoded = hexToBytes(hex);
        Map<String, Object> mdoc = cborMapper.readValue(decoded, Map.class);
        assertThat(mdoc.get("version")).isEqualTo("1.0");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> documents = (List<Map<String, Object>>) mdoc.get("documents");
        assertThat(documents).isNotEmpty();
        Map<String, Object> doc = documents.get(0);
        assertThat(doc.get("docType")).isEqualTo("urn:example:pid:mock");
        @SuppressWarnings("unchecked")
        Map<String, Object> issuerSigned = (Map<String, Object>) doc.get("issuerSigned");
        @SuppressWarnings("unchecked")
        Map<String, Object> nameSpaces = (Map<String, Object>) issuerSigned.get("nameSpaces");
        assertThat(nameSpaces).isNotEmpty();
        assertThat(nameSpaces.values().stream().flatMap(v -> ((List<?>) v).stream())
                .anyMatch(elem -> String.valueOf(((Map<?, ?>) elem).get("elementIdentifier")).equals("given_name"))).isTrue();

        byte[] issuerAuth = toByteArray(issuerSigned.get("issuerAuth"));
        Sign1Message sign1 = (Sign1Message) Sign1Message.DecodeFromBytes(issuerAuth);
        OneKey publicKey = toCosePublicKey(mockIssuerKeyService.signingKey());
        assertThat(sign1.validate(publicKey)).isTrue();

        Map<String, Object> mso = cborMapper.readValue(sign1.GetContent(), Map.class);
        assertThat(mso.get("docType")).isEqualTo("urn:example:pid:mock");
        assertThat(((Map<?, ?>) mso.get("valueDigests")).values()).isNotEmpty();
    }

    private String buildProof(String audience, String nonce) throws Exception {
        ECKey key = walletKeyService.loadOrCreateKey();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(key.toPublicJWK())
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("did:example:wallet")
                .audience(audience)
                .issueTime(new java.util.Date())
                .expirationTime(java.util.Date.from(Instant.now().plusSeconds(300)))
                .claim("nonce", nonce)
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    private OneKey toCosePublicKey(ECKey key) {
        CBORObject cborKey = CBORObject.NewMap();
        cborKey.Add(CBORObject.FromObject(1), CBORObject.FromObject(2)); // kty: EC2
        cborKey.Add(CBORObject.FromObject(-1), CBORObject.FromObject(1)); // crv: P-256
        cborKey.Add(CBORObject.FromObject(-2), CBORObject.FromObject(key.getX().decode()));
        cborKey.Add(CBORObject.FromObject(-3), CBORObject.FromObject(key.getY().decode()));
        if (key.getKeyID() != null) {
            cborKey.Add(CBORObject.FromObject(2), CBORObject.FromObject(key.getKeyID()));
        }
        try {
            return new OneKey(cborKey);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to convert to COSE key", e);
        }
    }

    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    private byte[] toByteArray(Object value) {
        if (value instanceof byte[] bytes) {
            return bytes;
        }
        if (value instanceof List<?> list) {
            byte[] bytes = new byte[list.size()];
            for (int i = 0; i < list.size(); i++) {
                bytes[i] = ((Number) list.get(i)).byteValue();
            }
            return bytes;
        }
        if (value instanceof String str && Base64.getDecoder() != null) {
            return Base64.getDecoder().decode(str);
        }
        return new byte[0];
    }

    private String baseUrl(String path) {
        return "http://localhost:" + port + path;
    }
}
