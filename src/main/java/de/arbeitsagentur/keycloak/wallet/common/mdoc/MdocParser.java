package de.arbeitsagentur.keycloak.wallet.common.mdoc;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Utilities to parse mDoc (CBOR) credentials.
 */
public class MdocParser {
    private final CBORMapper cborMapper = new CBORMapper();

    public boolean isHex(String value) {
        return value != null && value.matches("^[0-9a-fA-F]+$");
    }

    public Map<String, Object> extractClaims(String hex) {
        try {
            Map<String, Object> root = decode(hex);
            Object docs = root.get("documents");
            if (!(docs instanceof List<?> list) || list.isEmpty() || !(list.get(0) instanceof Map<?, ?> firstDoc)) {
                return Collections.emptyMap();
            }
            Object issuerSigned = firstDoc.get("issuerSigned");
            if (!(issuerSigned instanceof Map<?, ?> signed)) {
                return Collections.emptyMap();
            }
            Object nameSpaces = signed.get("nameSpaces");
            if (!(nameSpaces instanceof Map<?, ?> nsMap)) {
                return Collections.emptyMap();
            }
            Map<String, Object> claims = new LinkedHashMap<>();
            for (Object entryObj : nsMap.entrySet()) {
                Map.Entry<String, Object> entry = (Map.Entry<String, Object>) entryObj;
                Object elements = entry.getValue();
                if (elements instanceof List<?> elList) {
                    for (Object elem : elList) {
                        if (elem instanceof Map<?, ?> map) {
                            Object id = map.get("elementIdentifier");
                            Object value = map.get("elementValue");
                            if (id != null && value != null) {
                                claims.put(id.toString(), value);
                            }
                        }
                    }
                }
            }
            return claims;
        } catch (Exception e) {
            return Collections.emptyMap();
        }
    }

    public String extractDocType(String hex) {
        try {
            Map<String, Object> root = decode(hex);
            Object docs = root.get("documents");
            if (docs instanceof List<?> list && !list.isEmpty()) {
                Object first = list.get(0);
                if (first instanceof Map<?, ?> doc) {
                    Object docType = doc.get("docType");
                    if (docType != null) {
                        return docType.toString();
                    }
                }
            }
            Object docType = root.get("docType");
            return docType != null ? docType.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    public String prettyPrint(String hex) {
        try {
            Object decoded = decode(hex);
            return cborMapper.writerWithDefaultPrettyPrinter().writeValueAsString(decoded);
        } catch (Exception e) {
            return null;
        }
    }

    public Map<String, Object> decode(String hex) throws Exception {
        return cborMapper.readValue(hexToBytes(hex), Map.class);
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
}
