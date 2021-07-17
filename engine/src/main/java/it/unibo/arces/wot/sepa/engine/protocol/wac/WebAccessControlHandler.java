package it.unibo.arces.wot.sepa.engine.protocol.wac;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.apache.http.ExceptionLogger;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.BasicHttpEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.nio.bootstrap.HttpServer;
import org.apache.http.impl.nio.bootstrap.ServerBootstrap;
import org.apache.http.nio.protocol.BasicAsyncRequestConsumer;
import org.apache.http.nio.protocol.BasicAsyncResponseProducer;
import org.apache.http.nio.protocol.HttpAsyncExchange;
import org.apache.http.nio.protocol.HttpAsyncRequestConsumer;
import org.apache.http.nio.protocol.HttpAsyncRequestHandler;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.gson.Gson;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.sun.tools.javac.util.Pair;

import it.unibo.arces.wot.sepa.commons.exceptions.SEPAProtocolException;
import it.unibo.arces.wot.sepa.commons.exceptions.SEPASecurityException;
import it.unibo.arces.wot.sepa.commons.response.ErrorResponse;
import it.unibo.arces.wot.sepa.commons.response.Response;
import it.unibo.arces.wot.sepa.commons.security.ClientAuthorization;
import it.unibo.arces.wot.sepa.commons.security.Credentials;
import it.unibo.arces.wot.sepa.engine.bean.EngineBeans;
import it.unibo.arces.wot.sepa.engine.bean.HTTPHandlerBeans;
import it.unibo.arces.wot.sepa.engine.bean.SEPABeans;
import it.unibo.arces.wot.sepa.engine.core.EngineProperties;
import it.unibo.arces.wot.sepa.engine.dependability.Dependability;
import it.unibo.arces.wot.sepa.engine.dependability.authorization.SEPASecurityContext;
import it.unibo.arces.wot.sepa.engine.dependability.authorization.wac.PermissionsBean;
import it.unibo.arces.wot.sepa.engine.dependability.authorization.wac.WebAccessControlManager;
import it.unibo.arces.wot.sepa.engine.gates.http.EchoHandler;
import it.unibo.arces.wot.sepa.engine.gates.http.HttpUtilities;
import it.unibo.arces.wot.sepa.engine.protocol.sparql11.SPARQL11ProtocolException;
import it.unibo.arces.wot.sepa.engine.protocol.sparql11.SPARQL11ResponseHandler;
import it.unibo.arces.wot.sepa.engine.scheduling.InternalUQRequest;
import it.unibo.arces.wot.sepa.engine.scheduling.ScheduledRequest;
import it.unibo.arces.wot.sepa.engine.scheduling.Scheduler;
import it.unibo.arces.wot.sepa.engine.timing.Timings;

public class WebAccessControlHandler implements HttpAsyncRequestHandler<HttpRequest>, WebAccessControlHandlerMBean {
	protected static final Logger logger = LogManager.getLogger();

	protected HTTPHandlerBeans jmx = new HTTPHandlerBeans();

	protected final String wacPath;

	public WebAccessControlHandler(String wacPath) throws IllegalArgumentException {
		this.wacPath = wacPath;

		// JMX
		if(this.getClass().getSimpleName().equals("WebAccessControlHandler"))
			SEPABeans.registerMBean("SEPA:type=" + this.getClass().getSimpleName(), this);
	}
	
	protected boolean corsHandling(HttpAsyncExchange exchange) {
		if (!Dependability.processCORSRequest(exchange)) {
			logger.error("CORS origin not allowed");
			jmx.corsFailed();
			HttpUtilities.sendFailureResponse(exchange,
					new ErrorResponse(HttpStatus.SC_UNAUTHORIZED, "cors_error", "CORS origin not allowed"));
			return false;
		}

		if (Dependability.isPreFlightRequest(exchange)) {
			logger.debug("Preflight request");
			HttpUtilities.sendResponse(exchange, HttpStatus.SC_NO_CONTENT, "");
			return false;
		}

		return true;
	}
	
	protected String validateAccessToken(String accessToken) throws WacProtocolException {
		logger.log(Level.getLevel("oauth"),"VALIDATE TOKEN");

		// Parse token
		SignedJWT signedJWT = null;
		try {
			signedJWT = SignedJWT.parse(accessToken);
		} catch (ParseException e) {
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "Access token parsing error: " + e.getMessage());
		}

		// Verify token
		// TODO: dobbiamo ottenere la chiave pubblica (jwk) dell'IdentityProvider
		// in maniera dinamica secondo il protocollo OIDC.
		/*
		 * Lines below were copied from SecurityManager.setupValidation():
		 */
		// Get the  public key to verify
		RSAPublicKey publicKey = jwk.toRSAPublicKey();

		// Create RSA-verifier with the public key
		RSASSAVerifier verifier = new RSASSAVerifier(publicKey);

		//#####################################################################
		
		try {
			if (!signedJWT.verify(verifier)) {
				logger.error("Signed JWT not verified");
				return new ClientAuthorization("invalid_grant", "Signed JWT not verified");
			}

		} catch (JOSEException e) {
			logger.error(e.getMessage());
			return new ClientAuthorization("invalid_grant", "JOSEException: " + e.getMessage());
		}
		

		String webid;
		// Process token (validate)
		JWTClaimsSet claimsSet = null;
		try {
			claimsSet = signedJWT.getJWTClaimsSet();
			logger.log(Level.getLevel("oauth"),claimsSet);
			// Get client credentials for accessing the SPARQL endpoint
			webid = claimsSet.getStringClaim("webid");
			if (webid == null) {
				logger.log(Level.getLevel("oauth"),"<webid> claim is null. WebID-OIDC protocol violated");
				return new ClientAuthorization("invalid_grant", "Username claim not found");
			}
			
			logger.log(Level.getLevel("oauth"),"Subject: "+claimsSet.getSubject());
			logger.log(Level.getLevel("oauth"),"Issuer: "+claimsSet.getIssuer());
			logger.log(Level.getLevel("oauth"),"WebId: "+webid);
		} catch (ParseException e) {
			logger.error(e.getMessage());
			return new ClientAuthorization("invalid_grant", "ParseException. " + e.getMessage());
		}


		// Check token expiration (an "invalid_grant" error is raised if the token is
		// expired)
		Date now = new Date();
		long nowUnixSeconds = (now.getTime() / 1000) * 1000;
		Date expiring = claimsSet.getExpirationTime();
		Date notBefore = claimsSet.getNotBeforeTime();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS");
		if (expiring.getTime() - nowUnixSeconds < 0) {
			logger.warn("Token is expired: " + sdf.format(claimsSet.getExpirationTime()) + " < "
					+ sdf.format(new Date(nowUnixSeconds)));

			return new ClientAuthorization("invalid_grant", "Token issued at " + sdf.format(claimsSet.getIssueTime())
					+ " is expired: " + sdf.format(claimsSet.getExpirationTime()) + " < " + sdf.format(now));
		}

		if (notBefore != null && nowUnixSeconds < notBefore.getTime()) {
			logger.warn("Token can not be used before: " + claimsSet.getNotBeforeTime());
			return new ClientAuthorization("invalid_grant",
					"Token can not be used before: " + claimsSet.getNotBeforeTime());
		}
		
		return webid;
	}
	
	
	protected WacRequest parse(HttpAsyncExchange httpExchange) {
		// Values to be returned
		String webid = "";
		String resIdentifier = "";
		
		HttpRequest request = httpExchange.getRequest();
		String requestUri = request.getRequestLine().getUri();
		
		// Request URI syntactical validation
		URI uri;
		try {
			uri = new URI(requestUri);
		} catch (URISyntaxException e) {
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, e.getMessage());
		}
		
		// URI path validation
		if (!uri.getPath().equals(wacPath))
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "Wrong path: " + uri.getPath() + " expecting: " + wacPath);	
		
		Header[] headers;
		// Parsing and validating request headers
		// Content-Type: text/plain
		// Accept: application/json
		
		// Content-Type header
		headers = request.getHeaders("Content-Type");
		if (headers.length == 0) {
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "Content-Type is missing");
		}
		if (headers.length > 1) {
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "Too many Content-Type headers");
		}
		if (!headers[0].getValue().equals("text/plain")) {
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "Content-Type must be: text/plain");
		}

		// Accept header
		headers = request.getHeaders("Accept");
		if (headers.length == 0) {
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "Accept is missing");
		}
		if (headers.length > 1) {
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "Too many Accept headers");
		}
		if (!headers[0].getValue().equals("application/json")) {
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "Content-Type must be: application/json");
		}

		// Authorization header
		headers = request.getHeaders("Authorization");
		if (headers.length == 0) {
			webid = null;
		} else if (headers.length > 1) {
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "Too many Authorization headers");
		} else {
			// Extract Bearer64 authorization
			String bearer = headers[0].getValue();
	
			if (!bearer.startsWith("Bearer ")) {
				throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "Authorization must be \"Bearer Base64(OIDC identity token)\"");
			}
			
			String base64Token = bearer.split(" ")[1];
			try {
				webid = this.validateAccessToken(base64Token);
			} catch(WacProtocolException e) {
				throw e;
			}
		}
		
		String requestMethod = request.getRequestLine().getMethod();
		if (!requestMethod.toUpperCase().equals("POST")) {
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "The only method allowed is POST");
		}
		
		HttpEntity entity = ((HttpEntityEnclosingRequest) request).getEntity();
		try {
			resIdentifier = EntityUtils.toString(entity, Charset.forName("UTF-8"));
		} catch (org.apache.http.ParseException | IOException e) {
			logger.error(e);
			throw new WacProtocolException(HttpStatus.SC_INTERNAL_SERVER_ERROR, "Error while parsing the request body");
		}
		
		// Resource identifier URI syntactical validation
		try {
			new URI(resIdentifier);
		} catch (URISyntaxException e) {
			logger.error(e);
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "Resource identifier should be a valid URI.");
		}
		
		// Return the final result
		return new WacRequest(webid, resIdentifier);
	}
	
	@Override
	public HttpAsyncRequestConsumer<HttpRequest> processRequest(HttpRequest request, HttpContext context)
			throws HttpException, IOException {
		logger.log(Level.getLevel("http"), "@processRequest " + request + " " + context);
		// Buffer request content in memory for simplicity
		return new BasicAsyncRequestConsumer();
	}

	@Override
	public void handle(HttpRequest request, HttpAsyncExchange httpExchange, HttpContext context)
			throws HttpException, IOException  {
		logger.log(Level.getLevel("http"), "@handle " + request + " " + context);
		// CORS
		if (!corsHandling(httpExchange))
			return;

		WacRequest wacReq;
		try {
			// Parsing SOLID Wac request
			wacReq = parse(httpExchange);
		} catch (WacProtocolException e) {
			logger.error("Parsing failed: " + httpExchange.getRequest());
			HttpUtilities.sendFailureResponse(httpExchange,
					new ErrorResponse(e.getCode(), "WacProtocolException", "Parsing failed: " + e.getMessage()));
			jmx.parsingFailed();
			return;
		}
		
		// Perform the Wac authorization algorithm
		WebAccessControlManager wacManager = new WebAccessControlManager();
		PermissionsBean allowedModes = wacManager.handle(wacReq.getResIdentifier(), wacReq.getWebid());
		
		// Convert the Java Bean into Json and send the response
		Gson gson = new Gson();
		String allowedModesJson = gson.toJson(allowedModes);
		HttpUtilities.sendResponse(httpExchange, HttpStatus.SC_OK, allowedModesJson);
	}

	/*
	 * MBean interface implementation
	 */
	
	@Override
	public long getRequests() {
		return jmx.getRequests();
	}

	@Override
	public void reset() {
		jmx.reset();
	}

	@Override
	public float getHandlingTime_ms() {
		return jmx.getHandlingTime();
	}

	@Override
	public float getHandlingMinTime_ms() {
		return jmx.getHandlingMinTime();
	}

	@Override
	public float getHandlingAvgTime_ms() {
		return jmx.getHandlingAvgTime();
	}

	@Override
	public float getHandlingMaxTime_ms() {
		return jmx.getHandlingMaxTime_ms();
	}

	@Override
	public long getErrors_Timeout() {
		return jmx.getErrors_Timeout();
	}

	@Override
	public long getErrors_CORSFailed() {
		return jmx.getErrors_CORSFailed();
	}

	@Override
	public long getErrors_ParsingFailed() {
		return jmx.getErrors_ParsingFailed();
	}

	private class WacRequest {
		private String webid;
		private String resIdentifier;
		
		public WacRequest() {
			this.webid = "";
			this.resIdentifier = "";
		}
		
		public WacRequest(String webid, String resIdentifier) {
			this.webid = webid;
			this.resIdentifier = resIdentifier;
		}
		
		public String getWebid() {
			return webid;
		}
		
		public void setWebid(String webid) {
			this.webid = webid;
		}
		
		public String getResIdentifier() {
			return resIdentifier;
		}
		
		public void setResIdentifier(String resIdentifier) {
			this.resIdentifier = resIdentifier;
		}
		
	}

}

