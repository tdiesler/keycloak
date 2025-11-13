package org.keycloak.protocol.oid4vc.issuance.credentialoffer;

import org.apache.commons.collections4.map.HashedMap;
import org.keycloak.protocol.oid4vc.model.PreAuthorizedGrant;

import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

class InMemoryCredentialOfferStorage implements CredentialOfferStorage {

    private final Set<OfferEntry> offerStorage = new HashSet<>();

    @Override
    public synchronized void putOfferEntry(OfferEntry entry) {
        offerStorage.add(entry);
    }

    @Override
    public synchronized OfferEntry findOfferEntryByNonce(String nonce, boolean remove) {
        var entry = offerStorage.stream()
                .filter(it -> it.nonce().equals(nonce))
                .findFirst()
                .orElse(null);
        if (entry != null && remove) {
            removeOfferEntry(entry);
        }
        return entry;
    }

    @Override
    public synchronized OfferEntry findOfferEntryByCode(String code, boolean remove) {
        var entry = offerStorage.stream()
                .filter(it -> {
                    var maybeCode = it.getPreAuthorizedCode();
                    return code.equals(maybeCode.orElse(null));
                })
                .findFirst()
                .orElse(null);
        if (entry != null && remove) {
            removeOfferEntry(entry);
        }
        return entry;
    }

    @Override
    public synchronized void removeOfferEntry(OfferEntry entry) {
        offerStorage.remove(entry);
    }
}
