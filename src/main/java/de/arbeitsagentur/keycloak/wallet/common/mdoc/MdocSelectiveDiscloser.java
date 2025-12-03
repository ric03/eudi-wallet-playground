package de.arbeitsagentur.keycloak.wallet.common.mdoc;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Filters mDoc issuerSigned nameSpaces to retain only requested claims and re-encodes the mDoc.
 */
public class MdocSelectiveDiscloser {
    private final CBORMapper cborMapper = new CBORMapper();
    private final MdocParser parser = new MdocParser();

    public String filter(String hex, Set<String> requestedClaims) {
        if (requestedClaims == null || requestedClaims.isEmpty()) {
            return hex;
        }
        try {
            Map<String, Object> root = parser.decode(hex);
            Object docs = root.get("documents");
            if (!(docs instanceof List<?> list) || list.isEmpty()) {
                return hex;
            }
            boolean changed = false;
            for (Object docObj : list) {
                if (!(docObj instanceof Map<?, ?> mapObj)) {
                    continue;
                }
                @SuppressWarnings("unchecked")
                Map<String, Object> doc = (Map<String, Object>) mapObj;
                Object issuerSignedObj = doc.get("issuerSigned");
                if (!(issuerSignedObj instanceof Map<?, ?> issuerSigned)) {
                    continue;
                }
                Object nameSpacesObj = issuerSigned.get("nameSpaces");
                if (!(nameSpacesObj instanceof Map<?, ?> nameSpaces)) {
                    continue;
                }
                Map<String, Object> filteredNamespaces = new LinkedHashMap<>();
                for (Map.Entry<?, ?> nsEntry : nameSpaces.entrySet()) {
                    Object elementsObj = nsEntry.getValue();
                    if (elementsObj instanceof List<?> elems) {
                        List<Map<String, Object>> filteredElems = new ArrayList<>();
                        for (Object elemObj : elems) {
                            if (elemObj instanceof Map<?, ?> elemMap) {
                                Object id = elemMap.get("elementIdentifier");
                                String idStr = id != null ? id.toString() : null;
                                if (idStr != null && requested(idStr, requestedClaims)) {
                                    @SuppressWarnings("unchecked")
                                    Map<String, Object> cast = new LinkedHashMap<>((Map<String, Object>) elemMap);
                                    filteredElems.add(cast);
                                }
                            }
                        }
                        if (!filteredElems.isEmpty()) {
                            filteredNamespaces.put(nsEntry.getKey().toString(), filteredElems);
                            if (filteredElems.size() != elems.size()) {
                                changed = true;
                            }
                        } else {
                            changed = true;
                        }
                    }
                }
                if (!filteredNamespaces.isEmpty()) {
                    Map<String, Object> newIssuerSigned = new LinkedHashMap<>();
                    if (issuerSignedObj instanceof Map<?, ?> existing) {
                        for (Map.Entry<?, ?> entry : existing.entrySet()) {
                            if (entry.getKey() != null) {
                                newIssuerSigned.put(entry.getKey().toString(), entry.getValue());
                            }
                        }
                    }
                    newIssuerSigned.put("nameSpaces", filteredNamespaces);
                    doc.put("issuerSigned", newIssuerSigned);
                }
            }
            if (!changed) {
                return hex;
            }
            byte[] encoded = cborMapper.writer().writeValueAsBytes(root);
            return toHex(encoded);
        } catch (Exception e) {
            return hex;
        }
    }

    private boolean requested(String claimName, Set<String> requestedClaims) {
        if (claimName == null || requestedClaims == null || requestedClaims.isEmpty()) {
            return false;
        }
        for (String req : requestedClaims) {
            if (req == null || req.isBlank()) {
                continue;
            }
            if (req.equals(claimName) || req.endsWith("." + claimName) || claimName.endsWith("." + req)) {
                return true;
            }
        }
        return false;
    }

    private String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
