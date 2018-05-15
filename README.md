# Open Banking Client Authentication Tool

Command line tool that can be used to request access tokens to an ASPSP using OAuth client_credentials grant and private_key_jwt authentication. The tool:
- generates a private key JWT
- submits to the ASPSP the authentication request over a mutually authenticated channel

# Usage

To run the tool:

- Ensure that a client has been registered at the ASPSP
- download and unzip the source code from GitHub or clone the source
- change the following parameters in the src/main/resources/configuration.properties file:
  - ob.signingKeyId the signing key ID obtained from the Open Banking Directory frontend.
  - aspsp.audience the audience expected from the ASPSP. In our case this is the URL of token endpoint used to submit the token request.
  - aspsp.tppClientID the client id issued by the ASPSP during client registration.
  - aspsp.networkCertPassword the password used to protect the p12 network certificate.
  - aspsp.tokenEndpoint the token endpoint of the ASPSP.
- replace the signing key and the network certificates with yours:
  - signing key: replace the file src/main/resources/dynamic_client_reg_signing.key with your signing private key
  - network certificate: replace the file src/main/resources/dynamic_client_reg_network.p12 with your TPP certificate
- run the following command from the root of the project:

```sh
mvn compile exec:java -Dexec.mainClass="com.pingidentity.openbanking.ClientAuthenticationTool"
```