package org.wso2.custom.oidc.claim.handler.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;

/**
 * @scr.component name="CustomOIDCClaimHandlerServiceComponent" immediate="true"
 */
public class CustomOIDCClaimHandlerServiceComponent {

    private static final Log log = LogFactory.getLog(CustomOIDCClaimHandlerServiceComponent.class);

    protected void activate(ComponentContext context) {

        /**
         * Any logic which need to run during the bundle activation goes here.
         * Ex: Reading config file
         */

        log.info("CustomOIDCClaimHandlerServiceComponent bundle is activated");
    }

    protected void deactivate(ComponentContext context) {

        log.info("CustomOIDCClaimHandlerServiceComponent bundle is deactivated");
    }

}
