# App Gateway v1 lives here. 

## Updating Certificates
As long as the new certificate names match in the keyvault, no updates should be necessary.

## Adding New Certificates
If adding a new certificate (or updating a cert w/ a different identifying name):
1. to retrieve all certificates and secrets from a keyvault, add/update the name of the certificate and matching secret from the keyvault to the AZ_AKV_CERTIFICATE and AZ_AKV_SECRET keyvault variables
2. to add the certificates to the app gateway, add/update the name to the appropriate AZ_APP_GATEWAY_AUTH_CERTIFICATE or AZ_APP_GATEWAY_SSL_CERTIFICATE variables 

Additionally, you may add multiple certificates to single backends by adding one or more certificates to BACKEND_HTTP_SETTINGS_AUTHENTICATION_CERT to loop through nested dynamic content blocks

## BACKEND_HTTP_SETTINGS 
Due to flattening, all attributes and child objects are required.

## Routing Rules
Routing rules must contain a valid string for redirect_configuration_name. This means that routing rules for only backends cannot contain an empty string for redirect_configuration_name. To accomodate this issue, a pair of conditional dynamic blocks are used; one of which contains the appropriate arguments for redirect rules and one of which contains the appropriate arguments for backend routing rules.

### Adding Routing Rules
Because of the above, when adding a routing rule, at a minimum, the following are required: 
* include ROUTING_RULE_NAME as an attribute even though it is also the key
* include BACKEND_ADDRESS_POOL_NAME and BACKEND_HTTP_SETTINGS_NAME even if they are empty strings
* include REDIRECT_CONFIG_NAME even if it is an empty string