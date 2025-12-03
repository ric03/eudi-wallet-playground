package de.arbeitsagentur.keycloak.wallet.common.mdoc;

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.OneKey;
import COSE.Sign1Message;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import com.nimbusds.jose.jwk.ECKey;
import com.upokecenter.cbor.CBORObject;
import de.arbeitsagentur.keycloak.wallet.common.credential.CredentialBuildResult;
import de.arbeitsagentur.keycloak.wallet.mockissuer.MockIssuerKeyService;
import de.arbeitsagentur.keycloak.wallet.mockissuer.config.MockIssuerProperties;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds ISO 18013-5 compliant mDoc credentials for the mock issuer.
 */
public class MdocCredentialBuilder {
    private final MockIssuerKeyService keyService;
    private final MockIssuerProperties properties;
    private final CBORMapper cborMapper = new CBORMapper();

    public MdocCredentialBuilder(MockIssuerKeyService keyService, MockIssuerProperties properties) {
        this.keyService = keyService;
        this.properties = properties;
    }

    public CredentialBuildResult build(String configurationId, String vct, String issuer,
                                       Map<String, Object> claims, JsonNode cnf) {
        try {
            Map<String, Object> nameSpaces = new LinkedHashMap<>();
            List<Map<String, Object>> elements = new ArrayList<>();
            List<Map<String, Object>> digestEntries = new ArrayList<>();
            int digestId = 0;
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                Map<String, Object> element = new LinkedHashMap<>();
                element.put("digestID", digestId);
                element.put("elementIdentifier", entry.getKey());
                element.put("elementValue", entry.getValue());
                elements.add(element);

                byte[] encodedElement = cborMapper.writer().writeValueAsBytes(element);
                byte[] digest = sha.digest(encodedElement);
                Map<String, Object> digestElement = new LinkedHashMap<>();
                digestElement.put("digestID", digestId);
                digestElement.put("elementIdentifier", entry.getKey());
                digestElement.put("digest", digest);
                digestEntries.add(digestElement);
                digestId++;
            }
            nameSpaces.put(vct, elements);

            Map<String, Object> validityInfo = Map.of(
                    "signed", Instant.now().getEpochSecond(),
                    "validFrom", Instant.now().getEpochSecond(),
                    "validUntil", Instant.now().plus(properties.credentialTtl()).getEpochSecond()
            );

            Map<String, Object> valueDigests = Map.of(vct, digestEntries);
            Map<String, Object> mso = new LinkedHashMap<>();
            mso.put("version", "1.0");
            mso.put("digestAlgorithm", "SHA-256");
            mso.put("valueDigests", valueDigests);
            mso.put("docType", vct);
            mso.put("validityInfo", validityInfo);
            if (cnf != null) {
                mso.put("deviceKeyInfo", cborMapper.convertValue(cnf, Map.class));
            }
            byte[] msoBytes = cborMapper.writer().writeValueAsBytes(mso);

            byte[] issuerAuth = signMso(msoBytes);

            Map<String, Object> issuerSigned = new LinkedHashMap<>();
            issuerSigned.put("nameSpaces", nameSpaces);
            issuerSigned.put("issuerAuth", issuerAuth);

            Map<String, Object> document = new LinkedHashMap<>();
            document.put("docType", vct);
            document.put("issuerSigned", issuerSigned);
            document.put("validityInfo", validityInfo);

            Map<String, Object> mdoc = new LinkedHashMap<>();
            mdoc.put("version", "1.0");
            mdoc.put("documents", List.of(document));
            mdoc.put("status", 0);
            mdoc.put("issuer", issuer);

            byte[] cbor = cborMapper.writer().writeValueAsBytes(mdoc);
            String encoded = toHex(cbor);

            Map<String, Object> decoded = new LinkedHashMap<>();
            decoded.put("iss", issuer);
            decoded.put("credential_configuration_id", configurationId);
            decoded.put("vct", vct);
            decoded.put("docType", vct);
            decoded.put("validityInfo", validityInfo);
            if (cnf != null) {
                decoded.put("cnf", cborMapper.convertValue(cnf, Map.class));
            }
            decoded.put("claims", claims);
            decoded.put("issuerSigned", issuerSigned);

            return new CredentialBuildResult(encoded, List.of(), decoded, vct, "mso_mdoc");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build mDoc", e);
        }
    }

    private byte[] signMso(byte[] msoBytes) throws Exception {
        ECKey key = keyService.signingKey();
        OneKey coseKey = toCoseKey(key);
        Sign1Message sign1 = new Sign1Message();
        sign1.addAttribute(CBORObject.FromObject(1), AlgorithmID.ECDSA_256.AsCBOR(), Attribute.PROTECTED);
        if (key.getKeyID() != null) {
            sign1.addAttribute(CBORObject.FromObject(4), CBORObject.FromObject(key.getKeyID()), Attribute.PROTECTED);
        }
        sign1.SetContent(msoBytes);
        try {
            sign1.sign(coseKey);
            return sign1.EncodeToBytes();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign mDoc MSO", e);
        }
    }

    private OneKey toCoseKey(ECKey key) {
        CBORObject cborKey = CBORObject.NewMap();
        cborKey.Add(CBORObject.FromObject(1), CBORObject.FromObject(2)); // kty: EC2
        cborKey.Add(CBORObject.FromObject(-1), CBORObject.FromObject(1)); // crv: P-256
        cborKey.Add(CBORObject.FromObject(-2), CBORObject.FromObject(key.getX().decode()));
        cborKey.Add(CBORObject.FromObject(-3), CBORObject.FromObject(key.getY().decode()));
        cborKey.Add(CBORObject.FromObject(-4), CBORObject.FromObject(key.getD().decode()));
        if (key.getKeyID() != null) {
            cborKey.Add(CBORObject.FromObject(2), CBORObject.FromObject(key.getKeyID()));
        }
        try {
            return new OneKey(cborKey);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to convert signing key to COSE format", e);
        }
    }

    private String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
