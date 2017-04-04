# Custom OIDC Claim Handler
---
This component allows to retrieve oidc claims from a custom attribute store when building the id_token for an 
authorized user.

## Building From Source

Clone this repository first (`https://github.com/mefarazath/OIDCCustomClaimHandler.git`) 

Use maven install to build
`mvn clean install`.

## Deploying to IS 5.3.0

* Copy **org.wso2.custom.oidc.claim.handler-1.0.0.jar** file to **wso2is-5.3.0/repository/components/dropins**
 folder
* Update the **<IDTokenCustomClaimsCallBackHandler>** tag in **wso2is-5.3.0/repository/conf/identity/identity.xml** as follows,
````xml
<IDTokenCustomClaimsCallBackHandler>org.wso2.custom.oidc.claim.handler.CustomOIDCClaimHandler</IDTokenCustomClaimsCallBackHandler>
````
