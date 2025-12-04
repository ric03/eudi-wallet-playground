package de.arbeitsagentur.keycloak.wallet.mockissuer;

import COSE.AlgorithmID;
import COSE.OneKey;
import COSE.Sign1Message;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.dataformat.cbor.CBORMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.common.crypto.WalletKeyService;
import de.arbeitsagentur.keycloak.wallet.common.mdoc.MdocParser;
import de.arbeitsagentur.keycloak.wallet.common.util.HexUtils;
import org.junit.jupiter.api.Test;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.net.URI;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class MockIssuerMdocIntegrationTest {

    private static final ParameterizedTypeReference<Map<String, Object>> MAP_TYPE =
            new ParameterizedTypeReference<>() {};

    @LocalServerPort
    private int port;

    private RestClient restClient;

    @Autowired
    private WalletKeyService walletKeyService;

    @Autowired
    private MockIssuerKeyService mockIssuerKeyService;

    @Autowired
    private ObjectMapper objectMapper;

    private final CBORMapper cborMapper = new CBORMapper();

    @BeforeEach
    void setUpRestClient() {
        restClient = RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .build();
    }

    @Test
    void issuesMdocCredentialEndToEnd() throws Exception {
        Map<String, Object> offerRequest = Map.of(
                "configurationId", "mock-pid-mdoc",
                "format", "mso_mdoc",
                "vct", "urn:example:pid:mock",
                "claims", List.of(Map.of("name", "given_name", "value", "Alice"))
        );

        ResponseEntity<Map<String, Object>> offer = restClient.post()
                .uri("/mock-issuer/offers")
                .body(offerRequest)
                .retrieve()
                .toEntity(MAP_TYPE);
        assertThat(offer.getStatusCode().is2xxSuccessful()).isTrue();
        String preAuth = String.valueOf(offer.getBody().get("preAuthorizedCode"));
        assertThat(preAuth).isNotBlank();

        MultiValueMap<String, String> tokenForm = new LinkedMultiValueMap<>();
        tokenForm.add("pre-authorized_code", preAuth);
        ResponseEntity<Map<String, Object>> tokenResponse = restClient.post()
                .uri("/mock-issuer/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(tokenForm)
                .retrieve()
                .toEntity(MAP_TYPE);
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
        ResponseEntity<Map<String, Object>> credentialResponse = restClient.method(credentialEntity.getMethod())
                .uri(credentialEntity.getUrl())
                .headers(headers -> headers.putAll(credentialEntity.getHeaders()))
                .body(credentialEntity.getBody())
                .retrieve()
                .toEntity(MAP_TYPE);
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

        MdocParser parser = new MdocParser();
        Map<String, Object> claims = parser.extractClaims(hex);
        assertThat(claims).containsEntry("given_name", "Alice");

        byte[] decoded = HexUtils.decode(hex);
        CBORObject mdoc = CBORObject.DecodeFromBytes(decoded);
        assertThat(mdoc.get("version").AsString()).isEqualTo("1.0");
        CBORObject documents = mdoc.get("documents");
        assertThat(documents).isNotNull();
        CBORObject doc = documents.get(0);
        assertThat(doc.get("docType").AsString()).isEqualTo("urn:example:pid:mock");
        CBORObject issuerSigned = doc.get("issuerSigned");
        byte[] issuerAuth = HexUtils.toBytes(issuerSigned.get("issuerAuth"));
        Sign1Message sign1 = (Sign1Message) Sign1Message.DecodeFromBytes(issuerAuth);
        OneKey publicKey = toCosePublicKey(mockIssuerKeyService.signingKey());
        assertThat(sign1.validate(publicKey)).isTrue();

        CBORObject payload = CBORObject.DecodeFromBytes(sign1.GetContent());
        if (payload.HasMostOuterTag(24) && payload.getType() == CBORType.ByteString) {
            payload = CBORObject.DecodeFromBytes(payload.GetByteString());
        } else if (payload.getType() == CBORType.ByteString) {
            payload = CBORObject.DecodeFromBytes(payload.GetByteString());
        }
        CBORObject mso = payload;
        assertThat(mso.get("docType").AsString()).isEqualTo("urn:example:pid:mock");
        assertThat(mso.get("valueDigests")).isNotNull();
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
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
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

    private String baseUrl(String path) {
        return "http://localhost:" + port + path;
    }
}
