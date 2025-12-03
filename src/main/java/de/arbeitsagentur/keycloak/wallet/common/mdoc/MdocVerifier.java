package de.arbeitsagentur.keycloak.wallet.common.mdoc;

import COSE.OneKey;
import COSE.Sign1Message;
import com.upokecenter.cbor.CBORObject;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.keycloak.wallet.verification.service.TrustListService;
import de.arbeitsagentur.keycloak.wallet.verification.service.VerificationSteps;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Verifies mDoc credentials (CBOR/COSE) including issuer signature, digest integrity and optional holder binding.
 */
public class MdocVerifier {
    private final CBORMapper cborMapper = new CBORMapper();
    private final MdocParser parser = new MdocParser();
    private final TrustListService trustListService;

    public MdocVerifier(TrustListService trustListService) {
        this.trustListService = trustListService;
    }

    public boolean isMdoc(String token) {
        return parser.isHex(token);
    }

    public Map<String, Object> verify(String hex,
                                      String trustListId,
                                      String keyBindingJwt,
                                      String expectedAudience,
                                      String expectedNonce,
                                      VerificationSteps steps) {
        try {
            Map<String, Object> root = parser.decode(hex);
            Map<String, Object> claims = new LinkedHashMap<>(parser.extractClaims(hex));
            String docType = parser.extractDocType(hex);

            byte[] issuerAuth = issuerAuthBytes(root);
            Sign1Message sign1 = (Sign1Message) Sign1Message.DecodeFromBytes(issuerAuth);
            verifySignature(sign1, trustListId);
            if (steps != null) {
                steps.add("Signature verified against trust-list.json",
                        "Checked mDoc issuerAuth signature against trusted issuers in the trust list.",
                        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6-2.2.2.1");
            }

            verifyDigests(sign1.GetContent(), root);
            if (steps != null) {
                steps.add("Digest values validated",
                        "Validated mDoc valueDigests against issuerSigned nameSpaces.",
                        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6");
            }
            validateValidity(root);
            if (steps != null) {
                steps.add("Credential timing rules validated",
                        "Checked validityInfo timestamps to ensure credential is currently valid.",
                        "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-14.1.2");
            }

            if (keyBindingJwt != null && !keyBindingJwt.isBlank()) {
                PublicKey deviceKey = extractDeviceKey(sign1.GetContent());
                verifyHolderBinding(keyBindingJwt, deviceKey, expectedAudience, expectedNonce);
                if (steps != null) {
                    steps.add("Validated holder binding",
                            "Validated KB-JWT holder binding against mDoc deviceKeyInfo.",
                            "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.6-2.2.2.4");
                }
                claims.put("key_binding_jwt", keyBindingJwt);
            }
            if (docType != null && !claims.containsKey("docType")) {
                claims.put("docType", docType);
            }
            return claims;
        } catch (Exception e) {
            throw new IllegalStateException("Credential signature not trusted", e);
        }
    }

    private void verifySignature(Sign1Message sign1, String trustListId) throws Exception {
        List<PublicKey> keys = trustListService.publicKeys(trustListId);
        if (keys == null) {
            keys = List.of();
        }
        for (PublicKey key : keys) {
            OneKey coseKey = OneKeyFromPublicKey.build(key);
            if (coseKey != null && sign1.validate(coseKey)) {
                return;
            }
        }
        throw new IllegalStateException("Credential signature not trusted");
    }

    private void verifyDigests(byte[] msoBytes, Map<String, Object> root) throws Exception {
        Map<String, Object> mso = cborMapper.readValue(msoBytes, Map.class);
        Map<String, Object> valueDigests = asMap(mso.get("valueDigests"));
        if (valueDigests == null) {
            return;
        }
        Map<String, Object> document = firstDocument(root);
        Map<String, Object> issuerSigned = asMap(document.get("issuerSigned"));
        Map<String, Object> nameSpaces = asMap(issuerSigned.get("nameSpaces"));
        if (nameSpaces == null) {
            throw new IllegalStateException("Invalid mDoc payload");
        }
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        for (Map.Entry<String, Object> nsEntry : nameSpaces.entrySet()) {
            String nameSpace = nsEntry.getKey();
            List<Map<String, Object>> elements = asListOfMaps(nsEntry.getValue());
            Map<Integer, byte[]> digests = collectDigestMap(asListOfMaps(valueDigests.get(nameSpace)));
            for (Map<String, Object> element : elements) {
                Integer digestId = toInt(element.get("digestID"));
                byte[] expectedDigest = digests.get(digestId);
                if (expectedDigest == null) {
                    throw new IllegalStateException("Missing digest for element " + digestId);
                }
                byte[] encoded = cborMapper.writer().writeValueAsBytes(element);
                byte[] digest = sha.digest(encoded);
                if (!java.util.Arrays.equals(expectedDigest, digest)) {
                    throw new IllegalStateException("Digest mismatch for element " + digestId);
                }
            }
        }
    }

    private void validateValidity(Map<String, Object> root) {
        Map<String, Object> document = firstDocument(root);
        Map<String, Object> validityInfo = asMap(document.get("validityInfo"));
        if (validityInfo == null) {
            return;
        }
        Instant now = Instant.now();
        Long notBefore = toLong(validityInfo.get("validFrom"));
        if (notBefore != null && Instant.ofEpochSecond(notBefore).isAfter(now)) {
            throw new IllegalStateException("Credential presentation not yet valid");
        }
        Long notAfter = toLong(validityInfo.get("validUntil"));
        if (notAfter != null && Instant.ofEpochSecond(notAfter).isBefore(now)) {
            throw new IllegalStateException("Credential presentation expired");
        }
    }

    private void verifyHolderBinding(String keyBindingJwt,
                                     PublicKey credentialKey,
                                     String expectedAudience,
                                     String expectedNonce) throws Exception {
        if (credentialKey == null) {
            throw new IllegalStateException("Holder binding key does not match credential cnf");
        }
        SignedJWT holderBinding = SignedJWT.parse(keyBindingJwt);
        if (!TrustListService.verifyWithKey(holderBinding, credentialKey)) {
            throw new IllegalStateException("Holder binding signature invalid");
        }
        if (holderBinding.getJWTClaimsSet().getExpirationTime() != null
                && holderBinding.getJWTClaimsSet().getExpirationTime().toInstant().isBefore(Instant.now())) {
            throw new IllegalStateException("Presentation has expired");
        }
        if (holderBinding.getJWTClaimsSet().getNotBeforeTime() != null
                && holderBinding.getJWTClaimsSet().getNotBeforeTime().toInstant().isAfter(Instant.now())) {
            throw new IllegalStateException("Presentation not yet valid");
        }
        if (expectedAudience != null && holderBinding.getJWTClaimsSet().getAudience() != null
                && !holderBinding.getJWTClaimsSet().getAudience().isEmpty()) {
            String aud = holderBinding.getJWTClaimsSet().getAudience().get(0);
            if (!expectedAudience.equals(aud)) {
                throw new IllegalStateException("Audience mismatch in credential");
            }
        }
        if (expectedNonce != null) {
            String nonce = holderBinding.getJWTClaimsSet().getStringClaim("nonce");
            if (nonce != null && !expectedNonce.equals(nonce)) {
                throw new IllegalStateException("Nonce mismatch in presentation");
            }
        }
    }

    private PublicKey extractDeviceKey(byte[] msoBytes) throws Exception {
        Map<String, Object> mso = cborMapper.readValue(msoBytes, Map.class);
        Map<String, Object> deviceKeyInfo = asMap(mso.get("deviceKeyInfo"));
        if (deviceKeyInfo == null) {
            return null;
        }
        Object jwkObj = deviceKeyInfo.containsKey("jwk") ? deviceKeyInfo.get("jwk") : deviceKeyInfo;
        if (!(jwkObj instanceof Map<?, ?> map)) {
            return null;
        }
        Map<String, Object> normalized = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (entry.getKey() != null) {
                normalized.put(entry.getKey().toString(), entry.getValue());
            }
        }
        com.nimbusds.jose.jwk.JWK parsed = com.nimbusds.jose.jwk.JWK.parse(normalized);
        if (parsed instanceof com.nimbusds.jose.jwk.ECKey ecKey) {
            return ecKey.toECPublicKey();
        }
        if (parsed instanceof com.nimbusds.jose.jwk.RSAKey rsaKey) {
            return rsaKey.toRSAPublicKey();
        }
        return null;
    }

    private Map<Integer, byte[]> collectDigestMap(List<Map<String, Object>> digests) {
        Map<Integer, byte[]> map = new LinkedHashMap<>();
        if (digests == null) {
            return map;
        }
        for (Map<String, Object> digest : digests) {
            Integer id = toInt(digest.get("digestID"));
            byte[] value = toByteArray(digest.get("digest"));
            if (id != null && value.length > 0) {
                map.put(id, value);
            }
        }
        return map;
    }

    private Map<String, Object> firstDocument(Map<String, Object> root) {
        Object docs = root.get("documents");
        if (docs instanceof List<?> list && !list.isEmpty() && list.get(0) instanceof Map<?, ?> map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> doc = (Map<String, Object>) map;
            return doc;
        }
        throw new IllegalStateException("Invalid mDoc payload");
    }

    private Map<String, Object> asMap(Object value) {
        if (value instanceof Map<?, ?> map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> cast = (Map<String, Object>) map;
            return cast;
        }
        return null;
    }

    private List<Map<String, Object>> asListOfMaps(Object value) {
        if (value instanceof List<?> list) {
            List<Map<String, Object>> result = new ArrayList<>();
            for (Object elem : list) {
                if (elem instanceof Map<?, ?> map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> cast = (Map<String, Object>) map;
                    result.add(cast);
                }
            }
            return result;
        }
        return List.of();
    }

    private byte[] issuerAuthBytes(Map<String, Object> root) {
        Map<String, Object> document = firstDocument(root);
        Map<String, Object> issuerSigned = asMap(document.get("issuerSigned"));
        Object issuerAuth = issuerSigned != null ? issuerSigned.get("issuerAuth") : null;
        return toByteArray(issuerAuth);
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
        if (value instanceof String str) {
            try {
                return Base64.getDecoder().decode(str);
            } catch (IllegalArgumentException ignored) {
                return hexToBytes(str);
            }
        }
        return new byte[0];
    }

    private byte[] hexToBytes(String hex) {
        if (hex == null) {
            return new byte[0];
        }
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    private Integer toInt(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String str) {
            try {
                return Integer.parseInt(str);
            } catch (NumberFormatException ignored) {
            }
        }
        return null;
    }

    private Long toLong(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof String str) {
            try {
                return Long.parseLong(str);
            } catch (NumberFormatException ignored) {
            }
        }
        return null;
    }

    private static final class OneKeyFromPublicKey {
        private OneKeyFromPublicKey() {
        }

        static OneKey build(PublicKey key) {
            try {
                if (key instanceof ECPublicKey ecKey) {
                    com.nimbusds.jose.jwk.ECKey jwk = new com.nimbusds.jose.jwk.ECKey.Builder(
                            com.nimbusds.jose.jwk.Curve.P_256, ecKey).build();
                    CBORObject cborKey = CBORObject.NewMap();
                    cborKey.Add(CBORObject.FromObject(1), CBORObject.FromObject(2)); // kty: EC2
                    cborKey.Add(CBORObject.FromObject(-1), CBORObject.FromObject(1)); // crv: P-256
                    cborKey.Add(CBORObject.FromObject(-2), CBORObject.FromObject(jwk.getX().decode()));
                    cborKey.Add(CBORObject.FromObject(-3), CBORObject.FromObject(jwk.getY().decode()));
                    return new OneKey(cborKey);
                }
                return null;
            } catch (Exception e) {
                return null;
            }
        }
    }
}
