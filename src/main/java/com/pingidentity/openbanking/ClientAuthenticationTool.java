package com.pingidentity.openbanking;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.net.ssl.SSLContext;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationUtils;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.io.FileUtils;
import org.apache.http.HttpHeaders;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;

/**
 * Command line tool that can be used to request access tokens to an ASPSP using OAuth client_credentials grant and private_key_jwt authentication. The tool:
 * 
 * - generates a private key JWT
 * - submits to the ASPSP the authentication request over a mutually authenticated channel
 * 
 */
public class ClientAuthenticationTool {

	private static final String OB_SIGNING_KEY_ID = "ob.signingKeyId";
	
	private static final String ASPSP_AUDIENCE = "aspsp.audience";
	private static final String ASPSP_TPP_CLIENT_ID = "aspsp.tppClientID";
	private static final String ASPSP_NETWORK_CERT_PASSWORD = "aspsp.networkCertPassword";
	private static final String ASPSP_TOKEN_ENDPOINT = "aspsp.tokenEndpoint";
	private static final String ASPSP_SCOPE = "aspsp.scope";
	
	Configuration config;
	
	
	public ClientAuthenticationTool() throws Exception {
		config = new PropertiesConfiguration("config.properties");

	}

	public void authenticate() throws Exception {
		// Load the private key to sign the request JWT
		PrivateKey signingKey = loadSigningKey();

		// generate the privateKeyJWT to authenticate at the token endpoint
		String privateKeyJWT = generatePrivateKeyJWT(signingKey);

		// get the ASPSP access token using client credentials
		getASPSPAccessToken(privateKeyJWT);

	}

	protected String getASPSPAccessToken(String privateKeyJWT) throws Exception {
		Unirest.setHttpClient(getMTLSHttpClient());
		
		// send the client_credentials request
		HttpResponse<JsonNode> jsonResponse = Unirest.post(config.getString(ASPSP_TOKEN_ENDPOINT))
				.header(HttpHeaders.ACCEPT, ContentType.APPLICATION_JSON.getMimeType())
				.header(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_FORM_URLENCODED.getMimeType()).field("grant_type", "client_credentials")
				.field("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer").field("client_assertion", privateKeyJWT)
				.field("scope", config.getString(ASPSP_SCOPE)).asJson();

		log("ASPSP Token endpoint response code " + jsonResponse.getStatus() + ", body " + jsonResponse.getBody().toString());

		// stop if response code is not HTTP 200
		if (jsonResponse.getStatus() != 200) {
			throw new Exception("Authentication failed");
		}

		// extract access token if successful
		String accessToken = jsonResponse.getBody().getObject().getString("access_token");
		log("Access token " + accessToken);
		return accessToken;
	}

	protected String generatePrivateKeyJWT(PrivateKey rsaPrivate) throws Exception {
		// generate the claims for the JWT body
		JwtClaims claims = new JwtClaims();
		claims.setIssuer(config.getString(ASPSP_TPP_CLIENT_ID));
		claims.setSubject(config.getString(ASPSP_TPP_CLIENT_ID));
		claims.setAudience(config.getString(ASPSP_AUDIENCE));
		claims.setExpirationTimeMinutesInTheFuture(5);
		claims.setIssuedAtToNow();
		claims.setGeneratedJwtId();

		// get the signed JWT
		String privateKeyJWT = getJwt(config.getString(OB_SIGNING_KEY_ID), rsaPrivate, claims);
		log("Private key JWT " + privateKeyJWT);
		return privateKeyJWT;
	}

	protected String getJwt(String keyId, PrivateKey rsaPrivate, JwtClaims claims) throws JoseException {
		JsonWebSignature jws = new JsonWebSignature();
		// set the payload
		jws.setPayload(claims.toJson());

		// set the signing key
		jws.setKey(rsaPrivate);

		// set header
		jws.setKeyIdHeaderValue(keyId);
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

		// generate and return JWT
		return jws.getCompactSerialization();
	}

	protected CloseableHttpClient getMTLSHttpClient() throws Exception {
		String networkCertPassword = config.getString(ASPSP_NETWORK_CERT_PASSWORD);
		File file = ConfigurationUtils.fileFromURL(getClass().getClassLoader().getResource("dynamic_client_reg_network.p12"));
		KeyStore keystore = KeyStore.getInstance("PKCS12");
		keystore.load(new FileInputStream(file), networkCertPassword.toCharArray());
		SSLContext sslcontext = SSLContexts.custom().loadKeyMaterial(keystore, networkCertPassword.toCharArray()).build();
		SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext, new String[] { "TLSv1.2" }, null,
				SSLConnectionSocketFactory.getDefaultHostnameVerifier());
		CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
		return httpclient;
	}

	protected PrivateKey loadSigningKey() throws Exception {
		File file = ConfigurationUtils.fileFromURL(getClass().getClassLoader().getResource("dynamic_client_reg_signing.key"));
		String privateKey = FileUtils.readFileToString(file).replace(System.getProperty("line.separator"), "");
		byte[] decoded = Base64.getDecoder().decode(privateKey);
		return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
	}

	protected static void log(String logMessage) {
		System.out.println(logMessage);
	}

	public static void main(String[] args) throws Exception {
		ClientAuthenticationTool regTool = new ClientAuthenticationTool();
		regTool.authenticate();
	}

}
