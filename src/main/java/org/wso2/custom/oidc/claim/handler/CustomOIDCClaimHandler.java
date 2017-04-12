package org.wso2.custom.oidc.claim.handler;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.openidconnect.SAMLAssertionClaimsCallback;

import java.util.HashMap;
import java.util.Map;


/**
 * Custom OIDC Claim handler that allows claims to be retrieved from an external claim store.
 */
public class CustomOIDCClaimHandler extends SAMLAssertionClaimsCallback {

    private static final String INBOUND_AUTH_TYPE_OAUTH2 = "oauth2";
    private static final Log log = LogFactory.getLog(CustomOIDCClaimHandler.class);


    @Override
    public void handleCustomClaims(JWTClaimsSet jwtClaimsSet, OAuthTokenReqMessageContext requestMsgCtx) {

        // let the super class set claims like 'sub'
        super.handleCustomClaims(jwtClaimsSet, requestMsgCtx);

        // scopes requested in this oidc token request
        String[] oidcScopes = requestMsgCtx.getScope();
        AuthenticatedUser authorizedUser = requestMsgCtx.getAuthorizedUser();

        String spName;
        try {
            spName = getSpNameFromClientID(requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId());
        } catch (IdentityException e) {
            log.error("Error retrieving SP information. Cannot continue handling custom claims.", e);
            return;
        }

        Map<String, String> claimMap = getClaimsFromExternalAttributeStore(authorizedUser, spName, oidcScopes);
        // Set the claims to the JWT (id_token)
        for (Map.Entry<String, String> claimEntry : claimMap.entrySet()) {
            jwtClaimsSet.setClaim(claimEntry.getKey(), claimEntry.getValue());
        }

    }

    @Override
    public void handleCustomClaims(JWTClaimsSet jwtClaimsSet, OAuthAuthzReqMessageContext requestMsgCtx) {

        // let the super class set claims like 'sub'
        super.handleCustomClaims(jwtClaimsSet, requestMsgCtx);

        AuthenticatedUser authorizedUser = requestMsgCtx.getAuthorizationReqDTO().getUser();
        // scopes approved in this oidc authorization request
        String[] oidcScopes = requestMsgCtx.getApprovedScope();
        String spName;
        try {
            spName = getSpNameFromClientID(requestMsgCtx.getAuthorizationReqDTO().getConsumerKey());
        } catch (IdentityException e) {
            log.error("Error retrieving SP information. Cannot continue handling custom claims.", e);
            return;
        }

        Map<String, String> claimMap = getClaimsFromExternalAttributeStore(authorizedUser, spName, oidcScopes);
        // Set the claims to the JWT (id_token)
        for (Map.Entry<String, String> claimEntry : claimMap.entrySet()) {
            jwtClaimsSet.setClaim(claimEntry.getKey(), claimEntry.getValue());
        }
    }

    /**
     * Get claims from an external attribute store
     *
     * @param user                Authenticated User
     * @param serviceProviderName Application name
     * @param oidcScopes          scopes requested (Scope strings sent in token/authorization request)
     * @return
     */
    protected Map<String, String> getClaimsFromExternalAttributeStore(AuthenticatedUser user,
                                                                      String serviceProviderName,
                                                                      String[] oidcScopes) {

        log.info("Retrieving claims for user : " + user.getAuthenticatedSubjectIdentifier() + ", SP: " + serviceProviderName);
        // We can call an external API and get the claims
        Map<String, String> claims = new HashMap<>();
        claims.put("bonus", "none");
        claims.put("status", "inactive");
        return claims;
    }

    /**
     * Get the Service Provider name from the OIDC Client ID.
     *
     * @return
     */
    private String getSpNameFromClientID(String clientID) throws IdentityException {

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        ServiceProvider sp;
        try {
            sp = ApplicationManagementService.getInstance().getServiceProviderByClientId(clientID,
                    INBOUND_AUTH_TYPE_OAUTH2, tenantDomain);
            if (sp == null) {
                throw new IdentityException("Unable to find the service provider associated with clientId:" + clientID);
            }
            return sp.getApplicationName();
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityException("Error retrieving SP Name for client_id : " + clientID, e);
        }
    }
}
