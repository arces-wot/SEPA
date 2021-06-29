package it.unibo.arces.wot.sepa.engine.dependability.authorization;

import org.apache.http.impl.client.CloseableHttpClient;
import com.google.gson.JsonObject;
import com.nimbusds.jwt.SignedJWT;

import it.unibo.arces.wot.sepa.engine.scheduling.JenaSparqlParsing;

public class WebAccessControlManager {
	//TODO: implement WAC
	/** The http client. */
	protected CloseableHttpClient httpClient;
	
	// Parse token
	SignedJWT signedJWT = null;
	// see validateToken method in class KeyCloakSecurityManager
	
	//JSON
	private JsonObject results;
	
	// SPARQL
	// https://jena.apache.org/
	JenaSparqlParsing sparqlParser;
	
	void validateToken() {
		
	}
	
	void accessControl() {
		
	}
}
