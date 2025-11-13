package org.keycloak.protocol.oid4vc.issuance.credentialoffer;

import org.keycloak.protocol.oid4vc.model.CredentialsOffer;
import org.keycloak.protocol.oid4vc.model.PreAuthorizedCode;
import org.keycloak.protocol.oid4vc.model.PreAuthorizedGrant;
import org.keycloak.protocol.oidc.utils.OAuth2Code;
import org.keycloak.provider.Provider;

import java.util.Optional;

public interface CredentialOfferStorage extends Provider {

    record OfferEntry(String nonce, OAuth2Code code, CredentialsOffer offer) {
        public Optional<String> getPreAuthorizedCode() {
            return Optional.ofNullable(offer.getGrants())
                    .map(PreAuthorizedGrant::getPreAuthorizedCode)
                    .map(PreAuthorizedCode::getPreAuthorizedCode);
        }
        public String getClientId() {
            var clientUserIdPair = code.getUserSessionId();
            return clientUserIdPair.split("\\.")[0];
        }
        public String getSubjectId() {
            var clientUserIdPair = code.getUserSessionId();
            return clientUserIdPair.split("\\.")[1];
        }
    }

    void putOfferEntry(OfferEntry entry);

    OfferEntry findOfferEntryByNonce(String nonce, boolean remove);

    OfferEntry findOfferEntryByCode(String code, boolean remove);

    void removeOfferEntry(OfferEntry entry);

    @Override
    default void close() { }
}
