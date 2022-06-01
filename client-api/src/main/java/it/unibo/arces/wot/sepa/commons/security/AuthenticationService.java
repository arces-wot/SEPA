package it.unibo.arces.wot.sepa.commons.security;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;

import javax.net.ssl.SSLContext;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import it.unibo.arces.wot.sepa.commons.exceptions.SEPASecurityException;
import it.unibo.arces.wot.sepa.commons.response.Response;

public abstract class AuthenticationService implements Closeable {
	protected static final Logger logger = LogManager.getLogger();

	protected CloseableHttpClient httpClient;
	protected SSLContext ctx;
	protected OAuthProperties oauthProperties;
	
	public AuthenticationService(OAuthProperties oauthProperties) throws SEPASecurityException {		
		if (oauthProperties.useJks()) {
			File f = new File(oauthProperties.getJks());
			if (!f.exists() || f.isDirectory())
				throw new SEPASecurityException(oauthProperties.getJks() + " not found");
			httpClient = new SSLManager().getSSLHttpClient(oauthProperties.getJks(), oauthProperties.getJksSecret());
			ctx = new SSLManager().getSSLContextFromJKS(oauthProperties.getJks(), oauthProperties.getJksSecret());
		}
		else {
			httpClient = new SSLManager().getSSLHttpClientTrustAllCa(oauthProperties.getSSLProtocol());
			ctx = new SSLManager().getSSLContextTrustAllCa(oauthProperties.getSSLProtocol());
		}
		
		this.oauthProperties = oauthProperties;
	}
	
	public final CloseableHttpClient getSSLHttpClient() {return httpClient;}
	
	public SSLContext getSSLContext()  {
		return ctx;
	}
	
	abstract Response registerClient(String client_id,String username,String initialAccessToken,int timeout) throws SEPASecurityException;
	abstract Response requestToken(String authorization,int timeout);
	
	@Override
	public void close() throws IOException {
		httpClient.close();
	}
}
