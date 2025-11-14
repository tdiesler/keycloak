/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.testsuite.oid4vc.issuance;

import jakarta.ws.rs.core.HttpHeaders;
import org.apache.commons.io.IOUtils;
import org.apache.directory.api.util.Strings;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicNameValuePair;
import org.junit.Ignore;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.TokenVerifier;
import org.keycloak.protocol.oid4vc.model.CredentialIssuer;
import org.keycloak.protocol.oid4vc.model.CredentialOfferURI;
import org.keycloak.protocol.oid4vc.model.CredentialRequest;
import org.keycloak.protocol.oid4vc.model.CredentialResponse;
import org.keycloak.protocol.oid4vc.model.CredentialsOffer;
import org.keycloak.protocol.oid4vc.model.PreAuthorizedCode;
import org.keycloak.protocol.oid4vc.model.SupportedCredentialConfiguration;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.protocol.oidc.grants.PreAuthorizedCodeGrantTypeFactory;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.testsuite.oid4vc.issuance.signing.OID4VCIssuerEndpointTest;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.util.JsonSerialization;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * Credential Offer Validity Matrix
 * <p>
 * +----------+-----------+---------+---------+------------------------------------------------------+
 * | pre-auth | clientId  | userId  | Valid   | Notes                                                |
 * +----------+-----------+---------+---------+------------------------------------------------------+
 * | no       | no        | no      | yes     | Generic offer; any logged-in user may redeem.        |
 * | no       | no        | yes     | yes     | Offer restricted to a specific user.                 |
 * | no       | yes       | no      | yes     | Bound to client; user determined at login.           |
 * | no       | yes       | yes     | yes     | Bound to both client and user.                       |
 * +----------+-----------+---------+---------+------------------------------------------------------+
 * | yes      | no        | no      | no      | Pre-auth requires a user subject; missing userId.    |
 * | yes      | no        | yes     | yes     | Pre-auth for a specific user; client issuer defined. |
 * | yes      | yes       | no      | no      | Same as above; userId required.                      |
 * | yes      | yes       | yes     | yes     | Fully constrained: user + client.                    |
 * +----------+-----------+---------+---------+------------------------------------------------------+
 */
public class OID4VCICredentialOfferMatrixTest extends OID4VCIssuerEndpointTest {

    record UseCase(
            boolean preAuth,
            boolean clientId,
            boolean userId,
            boolean valid) {
    }

    static class OfferTestContext {
        boolean preAuthorized;
        String targetUser;
        String targetClient;
        ClientScopeRepresentation scope;
        CredentialIssuer issuerMetadata;
        OIDCConfigurationRepresentation authorizationMetadata;
        SupportedCredentialConfiguration supportedCredentialConfiguration;
    }

    OfferTestContext newOfferTestContext(UseCase uc) {
        var ctx = new OfferTestContext();
        ctx.preAuthorized = uc.preAuth;
        ctx.targetUser = uc.userId ? "john" : null;
        ctx.targetClient = uc.clientId ? "test-app" : null;
        ctx.scope = jwtTypeCredentialClientScope;
        ctx.issuerMetadata = getCredentialIssuerMetadata();
        ctx.authorizationMetadata = getAuthorizationMetadata(ctx.issuerMetadata.getAuthorizationServers().get(0));
        ctx.supportedCredentialConfiguration = getSupportedCredentialConfigurationByScope(ctx.issuerMetadata, ctx.scope.getName());
        return ctx;
    }


    @Test
    @Ignore
    public void testCredentialOffer_noPreAuth_noClientId_noUserId() throws Exception {
        testCredentialOfferParams(new UseCase(false, false, false, true));
    }

    @Test
    @Ignore
    public void testCredentialOffer_noPreAuth_noClientId_UserId() throws Exception {
        testCredentialOfferParams(new UseCase(false, false, true, true));
    }

    @Test
    @Ignore
    public void testCredentialOffer_noPreAuth_ClientId_noUserId() throws Exception {
        testCredentialOfferParams(new UseCase(false, true, false, true));
    }

    @Test
    @Ignore
    public void testCredentialOffer_noPreAuth_ClientId_UserId() throws Exception {
        testCredentialOfferParams(new UseCase(false, true, true, true));
    }

    @Test
    @Ignore
    public void testCredentialOffer_PreAuth_noClientId_noUserId() throws Exception {
        testCredentialOfferParams(new UseCase(true, false, false, false));
    }

    @Test
    public void testCredentialOffer_PreAuth_noClientId_UserId() throws Exception {
        testCredentialOfferParams(new UseCase(true, false, true, true));
    }

    @Test
    @Ignore
    public void testCredentialOffer_PreAuth_ClientId_noUserId() throws Exception {
        testCredentialOfferParams(new UseCase(true, true, false, false));
    }

    @Test
    public void testCredentialOffer_PreAuth_ClientId_UserId() throws Exception {
        testCredentialOfferParams(new UseCase(true, true, true, true));
    }

    void testCredentialOfferParams(UseCase uc) throws Exception {
        log.infof("%s", uc);

        // 1. Retrieving issuer, credential, authorization metadata
        //
        var ctx = newOfferTestContext(uc);
        var scope = ctx.scope.getName();
        assertNotNull(ctx.supportedCredentialConfiguration, "No credential configuration for: " + scope);
        var credConfigId = ctx.supportedCredentialConfiguration.getId();

        // 2. Retrieving the credential-offer-uri
        //
        String token = getBearerToken(oauth, client, ctx.targetUser, scope);
        String credOfferUriUrl = getCredentialOfferUriUrl(credConfigId, ctx.preAuthorized, ctx.targetUser, ctx.targetClient);
        HttpGet getCredentialOfferURI = new HttpGet(credOfferUriUrl);
        getCredentialOfferURI.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        CloseableHttpResponse credentialOfferURIResponse = httpClient.execute(getCredentialOfferURI);

        assertEquals(HttpStatus.SC_OK, credentialOfferURIResponse.getStatusLine().getStatusCode(), "A valid offer uri should be returned");
        String s = IOUtils.toString(credentialOfferURIResponse.getEntity().getContent(), StandardCharsets.UTF_8);
        CredentialOfferURI credentialOfferURI = JsonSerialization.readValue(s, CredentialOfferURI.class);
        assertTrue(credentialOfferURI.getIssuer().startsWith(ctx.issuerMetadata.getCredentialIssuer()));
        assertTrue(Strings.isNotEmpty(credentialOfferURI.getNonce()));

        // 3. Using the uri to get the actual credential offer
        //
        HttpGet getCredentialOffer = new HttpGet(credentialOfferURI.getIssuer() + "/" + credentialOfferURI.getNonce());
        CloseableHttpResponse credentialOfferResponse = httpClient.execute(getCredentialOffer);

        assertEquals(HttpStatus.SC_OK, credentialOfferResponse.getStatusLine().getStatusCode(), "A valid offer should be returned");
        s = IOUtils.toString(credentialOfferResponse.getEntity().getContent(), StandardCharsets.UTF_8);

        CredentialsOffer credOffer = JsonSerialization.readValue(s, CredentialsOffer.class);
        assertEquals(List.of(credConfigId), credOffer.getCredentialConfigurationIds());

        PreAuthorizedCode preAuthorizedCode = credOffer.getGrants().getPreAuthorizedCode();
        assertNotNull(preAuthorizedCode, "No pre-auth code");

        // 4. Get an access token for the pre-authorized code
        //
        HttpPost postPreAuthorizedCode = new HttpPost(ctx.authorizationMetadata.getTokenEndpoint());
        List<NameValuePair> parameters = new LinkedList<>();
        parameters.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, PreAuthorizedCodeGrantTypeFactory.GRANT_TYPE));
        parameters.add(new BasicNameValuePair(PreAuthorizedCodeGrantTypeFactory.CODE_REQUEST_PARAM, preAuthorizedCode.getPreAuthorizedCode()));
        UrlEncodedFormEntity formEntity = new UrlEncodedFormEntity(parameters, StandardCharsets.UTF_8);
        postPreAuthorizedCode.setEntity(formEntity);
        AccessTokenResponse accessTokenResponse = new AccessTokenResponse(httpClient.execute(postPreAuthorizedCode));
        assertEquals(HttpStatus.SC_OK, accessTokenResponse.getStatusCode());
        String accessToken = accessTokenResponse.getAccessToken();

        // 5. Get the credential
        //
        CredentialRequest request = new CredentialRequest();
        request.setCredentialConfigurationId(ctx.supportedCredentialConfiguration.getId());
        StringEntity stringEntity = new StringEntity(JsonSerialization.valueAsString(request), ContentType.APPLICATION_JSON);

        HttpPost postCredential = new HttpPost(ctx.issuerMetadata.getCredentialEndpoint());
        postCredential.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        postCredential.setEntity(stringEntity);

        CredentialResponse credentialResponse;
        try (CloseableHttpResponse credentialRequestResponse = httpClient.execute(postCredential)) {
            assertEquals(HttpStatus.SC_OK, credentialRequestResponse.getStatusLine().getStatusCode());
            s = IOUtils.toString(credentialRequestResponse.getEntity().getContent(), StandardCharsets.UTF_8);
            credentialResponse = JsonSerialization.valueFromString(s, CredentialResponse.class);
        }
        assertNotNull(credentialResponse.getCredentials(), "The credentials array should be present in the response.");
        assertFalse(credentialResponse.getCredentials().isEmpty(), "The credentials array should not be empty.");

        // 6. Verify the credential
        //
        CredentialResponse.Credential credentialObj = credentialResponse.getCredentials().get(0);
        assertNotNull(credentialObj, "The first credential in the array should not be null.");

        JsonWebToken jsonWebToken = TokenVerifier.create((String) credentialObj.getCredential(), JsonWebToken.class).getToken();
        assertEquals("did:web:test.org", jsonWebToken.getIssuer());
        Object vc = jsonWebToken.getOtherClaims().get("vc");
        VerifiableCredential credential = JsonSerialization.mapper.convertValue(vc, VerifiableCredential.class);
        assertEquals(List.of(scope), credential.getType());
        assertEquals(URI.create("did:web:test.org"), credential.getIssuer());
        assertEquals("john@email.cz", credential.getCredentialSubject().getClaims().get("email"));
        assertTrue(credential.getCredentialSubject().getClaims().containsKey("scope-name"), "The static claim should be set.");
        assertEquals(scope, credential.getCredentialSubject().getClaims().get("scope-name"), "The static claim should be set.");
        assertFalse(credential.getCredentialSubject().getClaims().containsKey("AnotherCredentialType"), "Only mappers supported for the requested type should have been evaluated.");
    }
}
