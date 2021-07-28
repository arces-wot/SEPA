package it.unibo.arces.wot.sepa.engine.protocol.wac;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpStatus;
import org.apache.http.nio.protocol.BasicAsyncRequestConsumer;
import org.apache.http.nio.protocol.HttpAsyncExchange;
import org.apache.http.nio.protocol.HttpAsyncRequestConsumer;
import org.apache.http.nio.protocol.HttpAsyncRequestHandler;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.gson.Gson;

import it.unibo.arces.wot.sepa.commons.response.ErrorResponse;
import it.unibo.arces.wot.sepa.engine.bean.HTTPHandlerBeans;
import it.unibo.arces.wot.sepa.engine.bean.SEPABeans;
import it.unibo.arces.wot.sepa.engine.dependability.Dependability;
import it.unibo.arces.wot.sepa.engine.dependability.authorization.wac.PermissionsBean;
import it.unibo.arces.wot.sepa.engine.dependability.authorization.wac.WebAccessControlManager;
import it.unibo.arces.wot.sepa.engine.gates.http.HttpUtilities;

public class WebAccessControlHandler implements HttpAsyncRequestHandler<HttpRequest>, WebAccessControlHandlerMBean {
	protected static final Logger logger = LogManager.getLogger();

	protected HTTPHandlerBeans jmx = new HTTPHandlerBeans();

	protected final String wacPath;
	protected final WebAccessControlManager wacManager = new WebAccessControlManager(); // a Singleton instance

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
	
	protected WacRequest parse(HttpAsyncExchange httpExchange) {
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
		if (!uri.getPath().equals(this.wacPath))
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "Wrong path: " + uri.getPath() + " expecting: " + this.wacPath);	
		
		Header[] headers;
		// Parsing and validating request headers
		// Content-Type: application/json
		// Accept: application/json
		
		// Content-Type header
		headers = request.getHeaders("Content-Type");
		if (headers.length == 0) {
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "Content-Type is missing");
		}
		if (headers.length > 1) {
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "Too many Content-Type headers");
		}
		if (!headers[0].getValue().equals("application/json")) {
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "Content-Type must be: application/json");
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
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "Accept must be: application/json");
		}

		
		String requestMethod = request.getRequestLine().getMethod();
		if (!requestMethod.toUpperCase().equals("POST")) {
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "The only method allowed is POST");
		}
		
		String requestBody;
		HttpEntity entity = ((HttpEntityEnclosingRequest) request).getEntity();
		try {
			requestBody = EntityUtils.toString(entity, Charset.forName("UTF-8"));
		} catch (org.apache.http.ParseException | IOException e) {
			logger.error(e);
			throw new WacProtocolException(HttpStatus.SC_INTERNAL_SERVER_ERROR, "Error while parsing the request body");
		}
		
		Gson gson = new Gson();
		WacRequest wacRequest = (WacRequest) gson.fromJson(requestBody, WacRequest.class);
		
		// Root identifier URI syntactical validation
		try {
			new URI(wacRequest.getRootIdentifier());
		} catch (URISyntaxException e) {
			logger.error(e);
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "Root identifier should be a valid URI.");
		}
		
		// Resource identifier URI syntactical validation
		try {
			new URI(wacRequest.getResIdentifier());
		} catch (URISyntaxException e) {
			logger.error(e);
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "Resource identifier should be a valid URI.");
		}
		
		// WebId URI syntactical validation
		try {
			new URI(wacRequest.getWebid());
		} catch (URISyntaxException e) {
			logger.error(e);
			throw new WacProtocolException(HttpStatus.SC_BAD_REQUEST, "WebId should be a valid URI.");
		}
		
		// Return the final result
		return wacRequest;
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
		PermissionsBean allowedModes = this.wacManager.handle(wacReq.getRootIdentifier(),
				wacReq.getResIdentifier(), wacReq.getWebid());
		
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

}

