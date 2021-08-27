/* HTTP handler for SPARQL 1.1 protocol
 * 
 * Author: Luca Roffia (luca.roffia@unibo.it)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package it.unibo.arces.wot.sepa.engine.protocol.sparql11;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.util.Map;
import java.util.Set;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpStatus;
import org.apache.http.ParseException;
import org.apache.http.nio.protocol.BasicAsyncRequestConsumer;
import org.apache.http.nio.protocol.HttpAsyncExchange;
import org.apache.http.nio.protocol.HttpAsyncRequestConsumer;
import org.apache.http.nio.protocol.HttpAsyncRequestHandler;

import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import it.unibo.arces.wot.sepa.commons.exceptions.SEPASecurityException;
import it.unibo.arces.wot.sepa.commons.exceptions.SEPASparqlParsingException;
import it.unibo.arces.wot.sepa.commons.response.ErrorResponse;
import it.unibo.arces.wot.sepa.commons.security.ClientAuthorization;
import it.unibo.arces.wot.sepa.engine.bean.HTTPHandlerBeans;
import it.unibo.arces.wot.sepa.engine.bean.SEPABeans;
import it.unibo.arces.wot.sepa.engine.dependability.Dependability;
import it.unibo.arces.wot.sepa.engine.gates.http.HttpUtilities;
import it.unibo.arces.wot.sepa.engine.scheduling.InternalQueryRequest;
import it.unibo.arces.wot.sepa.engine.scheduling.InternalUQRequest;
import it.unibo.arces.wot.sepa.engine.scheduling.InternalUpdateRequest;
import it.unibo.arces.wot.sepa.engine.scheduling.ScheduledRequest;
import it.unibo.arces.wot.sepa.engine.scheduling.Scheduler;
import it.unibo.arces.wot.sepa.engine.timing.Timings;

public class SPARQL11Handler implements HttpAsyncRequestHandler<HttpRequest>, SPARQL11HandlerMBean {
	protected static final Logger logger = LogManager.getLogger();

	private Scheduler scheduler;

	protected HTTPHandlerBeans jmx = new HTTPHandlerBeans();

	protected final String queryPath;
	protected final String updatePath;

	public SPARQL11Handler(Scheduler scheduler, String queryPath, String updatePath) throws IllegalArgumentException {

		if (scheduler == null)
			throw new IllegalArgumentException("Scheduler is null");

		this.scheduler = scheduler;
		this.queryPath = queryPath;
		this.updatePath = updatePath;

		// JMX
		if(this.getClass().getSimpleName().equals("SPARQL11Handler")) SEPABeans.registerMBean("SEPA:type=" + this.getClass().getSimpleName(), this);
	}

	protected ClientAuthorization authorize(HttpRequest request) throws SEPASecurityException {
		return new ClientAuthorization();
	}

	protected boolean corsHandling(HttpAsyncExchange exchange) {
		if (!Dependability.processCORSRequest(exchange)) {
			logger.log(Level.getLevel("http"),"CORS origin not allowed");
			jmx.corsFailed();
			HttpUtilities.sendFailureResponse(exchange,
					new ErrorResponse(HttpStatus.SC_UNAUTHORIZED, "cors_error", "CORS origin not allowed"));
			return false;
		}

		if (Dependability.isPreFlightRequest(exchange)) {
			logger.log(Level.getLevel("http"),"Preflight request");
			HttpUtilities.sendResponse(exchange, HttpStatus.SC_NO_CONTENT, "");
			return false;
		}

		return true;
	}

	protected InternalUQRequest parse(HttpAsyncExchange exchange, ClientAuthorization auth) {
		URI uri;
		try {
			uri = new URI(exchange.getRequest().getRequestLine().getUri());
		} catch (URISyntaxException e1) {
			throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST, e1.getMessage());
		}

		String requestUri = exchange.getRequest().getRequestLine().getUri();
		
		if (exchange.getRequest().getRequestLine().getMethod().toUpperCase().equals("GET")) {
			/** <a href="https://www.w3.org/TR/sparql11-protocol/"> SPARQL 1.1 Protocol</a>
			 * 
			 * <pre>
			 * 
			 * 					HTTP Method 	Query String Parameters 	Request 	| Content Type 	Request Message Body
			 * ---------------------------------------------------------------------------------------------------------------------------------------- 
			 * query via GET 	| GET 			|	query (exactly 1) 		|  None 	| None 			| default-graph-uri (0 or more)  named-graph-uri (0 or more)
			 * 
			 * 2.1.4 Specifying an RDF Dataset
			 * 
			 * A SPARQL query is executed against an RDF Dataset. The RDF Dataset for a
			 * query may be specified either via the default-graph-uri and named-graph-uri
			 * parameters in the SPARQL Protocol or in the SPARQL query string using the
			 * FROM and FROM NAMED keywords.
			 * 
			 * If different RDF Datasets are specified in both the protocol request and the
			 * SPARQL query string, then the SPARQL service must execute the query using the
			 * RDF Dataset given in the protocol request.
			 * 
			 * Note that a service may reject a query with HTTP response code 400 if the
			 * service does not allow protocol clients to specify the RDF Dataset. If an RDF
			 * Dataset is not specified in either the protocol request or the SPARQL query
			 * string, then implementations may execute the query against an
			 * implementation-defined default RDF dataset. 
			 * 
			 * 
			 * </pre>
			 */
			if (!uri.getPath().equals(queryPath))
				throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,
						"GET method available for query only. Wrong path: " + uri.getPath() + " expecting: "
								+ queryPath);	
			try {
				if (requestUri.indexOf('?') == -1) {
					throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,
							"Wrong request uri: ? not found in " + requestUri);
				}

				String queryParameters = requestUri.substring(requestUri.indexOf('?') + 1);
				Map<String, Set<String>> params = HttpUtilities.splitQuery(queryParameters);

				if (params.get("query") == null) {
					throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,
							"Wrong request uri: 'query=' not found in " + queryParameters);
				}

				String sparql = params.get("query").iterator().next();
				Set<String> graphUri = params.get("default-graph-uri");
				Set<String> namedGraphUri = params.get("named-graph-uri");

				Header[] headers = exchange.getRequest().getHeaders("Accept");
				if (headers.length != 1)
					return new InternalQueryRequest(sparql, graphUri, namedGraphUri);
				else
					return new InternalQueryRequest(sparql, graphUri, namedGraphUri, auth, headers[0].getValue());
			} catch (SEPASparqlParsingException | UnsupportedEncodingException e) {
				throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST, e.getMessage());
			}
		} else if (exchange.getRequest().getRequestLine().getMethod().toUpperCase().equals("POST")) {
			
			/**
			 * <a href="https://www.w3.org/TR/sparql11-protocol/"> SPARQL 1.1 Protocol</a>
			 *
			 * *
			 * 
			 * <pre>
			 *                               HTTP Method   Query String Parameters           Request Content Type                Request Message Body
			 *----------------------------------------------------------------------------------------------------------------------------------------
			 * update via URL-encoded POST|   POST         None                              application/x-www-form-urlencoded   URL-encoded, ampersand-separated query parameters.
			 *                            |                                                                                     update (exactly 1)
			 *                            |                                                                                     using-graph-uri (0 or more)
			 *                            |                                                                                     using-named-graph-uri (0 or more)
			 *----------------------------------------------------------------------------------------------------------------------------------------																													
			 * update via POST directly   |   POST        using-graph-uri (0 or more)        application/sparql-update           Unencoded SPARQL update request string
			 *                                            using-named-graph-uri (0 or more)
			 * ----------------------------------------------------------------------------------------------------------------------------------------												
			 * query via URL-encoded POST |   POST         None                              application/x-www-form-urlencoded   URL-encoded, ampersand-separated query parameters.
			 *                            |                                                                                     query (exactly 1)
			 *                            |                                                                                     default-graph-uri (0 or more)
			 *                            |                                                                                     named-graph-uri (0 or more)
			 *----------------------------------------------------------------------------------------------------------------------------------------																													
			 * query via POST directly    |   POST         default-graph-uri (0 or more)
			 *                            |                named-graph-uri (0 or more)       application/sparql-query            Unencoded SPARQL query string
			 * </pre>
			 * 
			 */
			
			Header[] headers = exchange.getRequest().getHeaders("Content-Type");
			if (headers.length != 1) {
				logger.log(Level.getLevel("http"),"Content-Type is missing or multiple");
				throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST, "Content-Type is missing or multiple");
			}
			
			HttpEntity entity = ((HttpEntityEnclosingRequest) exchange.getRequest()).getEntity();
			String body;
			try {
				body = EntityUtils.toString(entity, Charset.forName("UTF-8"));
			} catch (ParseException | IOException e) {
				throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,e.getMessage());
			}
			
			String defGraph = "default-graph-uri";
			String namedGraph = "named-graph-uri";
			String sparql = null;
			Set<String> default_graph_uri = null;
			Set<String> named_graph_uri = null;
			
			if (headers[0].getValue().equals("application/x-www-form-urlencoded")) {
				String decodedBody;
				try {
					decodedBody = URLDecoder.decode(body, "UTF-8");
				} catch (UnsupportedEncodingException e) {
					throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,e.getMessage());
				}
				try {
					Map<String, Set<String>> params = HttpUtilities.splitQuery(decodedBody);
					if (params.containsKey("query")) {
						if (!uri.getPath().equals(queryPath))
							throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,
									"Wrong path: " + uri.getPath() + " was expecting: "+ queryPath);
						
						params = HttpUtilities.splitQuery(decodedBody);
						sparql = params.get("query").iterator().next();
						default_graph_uri = params.get(defGraph);
						named_graph_uri = params.get(namedGraph);
						
						headers = exchange.getRequest().getHeaders("Accept");
						if (headers.length != 1)
							try {
								return new InternalQueryRequest(sparql, default_graph_uri, named_graph_uri);
							} catch (SEPASparqlParsingException e) {
								throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,e.getMessage());
							}
						else
							try {
								return new InternalQueryRequest(sparql, default_graph_uri, named_graph_uri, auth,
										headers[0].getValue());
							} catch (SEPASparqlParsingException e) {
								throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,e.getMessage());
							}
						
					} else if (params.containsKey("update")) { 
						if (!uri.getPath().equals(updatePath))
							throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,
									"Wrong path: " + uri.getPath() + " was expecting: "+ updatePath);
						defGraph = "using-graph-uri";
						namedGraph = "using-named-graph-uri";
						
						params = HttpUtilities.splitQuery(decodedBody);
						sparql = params.get("update").iterator().next();
						default_graph_uri = params.get(defGraph);
						named_graph_uri = params.get(namedGraph);
						
						try {
							return new InternalUpdateRequest(sparql, default_graph_uri, named_graph_uri, auth);
						} catch (SPARQL11ProtocolException | SEPASparqlParsingException e) {
							throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,e.getMessage());
						}
						
					}
					throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,"Query or update query parameter not found");
				} catch (UnsupportedEncodingException e) {
					throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,e.getMessage());
				}
			} else if (headers[0].getValue().equals("application/sparql-query")) {
				if (!uri.getPath().equals(queryPath))
					throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,
							"Wrong path: " + uri.getPath() + " was expecting: "+ queryPath);
				
				if (requestUri.indexOf('?') != -1) {
					String queryParameters = requestUri.substring(requestUri.indexOf('?') + 1);
					Map<String, Set<String>> params;
					try {
						params = HttpUtilities.splitQuery(queryParameters);
						default_graph_uri = params.get(defGraph);
						named_graph_uri = params.get(namedGraph);
					} catch (UnsupportedEncodingException e) {
						throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,e.getMessage());
					}
					
				}
				
				sparql = body;
				
				headers = exchange.getRequest().getHeaders("Accept");
				if (headers.length != 1)
					try {
						return new InternalQueryRequest(sparql, default_graph_uri, named_graph_uri);
					} catch (SEPASparqlParsingException e) {
						throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,e.getMessage());
					}
				else
					try {
						return new InternalQueryRequest(sparql, default_graph_uri, named_graph_uri, auth,
								headers[0].getValue());
					} catch (SEPASparqlParsingException e) {
						throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,e.getMessage());
					}
				
			} else if (headers[0].getValue().equals("application/sparql-update")) {
				if (!uri.getPath().equals(updatePath))
					throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,
							"Wrong path: " + uri.getPath() + " was expecting: "+ updatePath);
				defGraph = "using-graph-uri";
				namedGraph = "using-named-graph-uri";
				
				if (requestUri.indexOf('?') != -1) {
					String queryParameters = requestUri.substring(requestUri.indexOf('?') + 1);
					Map<String, Set<String>> params;
					try {
						params = HttpUtilities.splitQuery(queryParameters);
						default_graph_uri = params.get(defGraph);
						named_graph_uri = params.get(namedGraph);
					} catch (UnsupportedEncodingException e) {
						throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,e.getMessage());
					}
					
				}
				
				sparql = body;
				
				try {
					return new InternalUpdateRequest(sparql, default_graph_uri, named_graph_uri, auth);
				} catch (SPARQL11ProtocolException | SEPASparqlParsingException e) {
					throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,e.getMessage());
				}
			}
		}

		throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,
				"Unsupported HTTP method: " + exchange.getRequest().getRequestLine().getMethod().toUpperCase());
	}

//	protected InternalUQRequest parseQuery(HttpAsyncExchange exchange, ClientAuthorization auth)
//			throws SPARQL11ProtocolException {
//		switch (exchange.getRequest().getRequestLine().getMethod().toUpperCase()) {
//		case "GET":
//			logger.debug("query via GET");
//			try {
//				String requestUri = exchange.getRequest().getRequestLine().getUri();
//
//				if (requestUri.indexOf('?') == -1) {
//					throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,
//							"Wrong request uri: ? not found in " + requestUri);
//				}
//
//				String queryParameters = requestUri.substring(requestUri.indexOf('?') + 1);
//				Map<String, Set<String>> params = HttpUtilities.splitQuery(queryParameters);
//
//				if (params.get("query") == null) {
//					throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,
//							"Wrong request uri: 'query=' not found in " + queryParameters);
//				}
//
//				String sparql = params.get("query").iterator().next();
//				Set<String> graphUri = params.get("default-graph-uri");
//				Set<String> namedGraphUri = params.get("named-graph-uri");
//
//				Header[] headers = exchange.getRequest().getHeaders("Accept");
//				if (headers.length != 1)
//					return new InternalQueryRequest(sparql, graphUri, namedGraphUri, auth);
//				else
//					return new InternalQueryRequest(sparql, graphUri, namedGraphUri, auth, headers[0].getValue());
//			} catch (SEPASparqlParsingException | UnsupportedEncodingException e) {
//				throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST, e.getMessage());
//			}
//		case "POST":
//			return parsePost(exchange, "query", auth);
//		}
//
//		logger.error("UNSUPPORTED METHOD: " + exchange.getRequest().getRequestLine().getMethod().toUpperCase());
//		throw new SPARQL11ProtocolException(HttpStatus.SC_NOT_FOUND,
//				"Unsupported method: " + exchange.getRequest().getRequestLine().getMethod().toUpperCase());
//	}

//	protected InternalUQRequest parseUpdate(HttpAsyncExchange exchange, ClientAuthorization auth) {
//		if (!exchange.getRequest().getRequestLine().getMethod().toUpperCase().equals("POST")) {
//			logger.error("Request MUST conform to SPARQL 1.1 Protocol (https://www.w3.org/TR/sparql11-protocol/)");
//			throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,
//					"Request MUST conform to SPARQL 1.1 Protocol (https://www.w3.org/TR/sparql11-protocol/)");
//		}
//
//		return parsePost(exchange, "update", auth);
//	}

	/**
	 * <a href="https://www.w3.org/TR/sparql11-protocol/"> SPARQL 1.1 Protocol</a>
	 *
	 * *
	 * 
	 * <pre>
	 *                               HTTP Method   Query String Parameters           Request Content Type                Request Message Body
	 *----------------------------------------------------------------------------------------------------------------------------------------
	 * update via URL-encoded POST|   POST         None                              application/x-www-form-urlencoded   URL-encoded, ampersand-separated query parameters.
	 *                            |                                                                                     update (exactly 1)
	 *                            |                                                                                     using-graph-uri (0 or more)
	 *                            |                                                                                     using-named-graph-uri (0 or more)
	 *----------------------------------------------------------------------------------------------------------------------------------------																													
	 * update via POST directly   |   POST        using-graph-uri (0 or more)        application/sparql-update           Unencoded SPARQL update request string
	 *                                            using-named-graph-uri (0 or more)
	 * ----------------------------------------------------------------------------------------------------------------------------------------												
	 * query via URL-encoded POST |   POST         None                              application/x-www-form-urlencoded   URL-encoded, ampersand-separated query parameters.
	 *                            |                                                                                     query (exactly 1)
	 *                            |                                                                                     default-graph-uri (0 or more)
	 *                            |                                                                                     named-graph-uri (0 or more)
	 *----------------------------------------------------------------------------------------------------------------------------------------																													
	 * query via POST directly    |   POST         default-graph-uri (0 or more)
	 *                            |                named-graph-uri (0 or more)       application/sparql-query            Unencoded SPARQL query string
	 * </pre>
	 * 
	 */
//	protected InternalUQRequest parsePost(HttpAsyncExchange exchange, String type, ClientAuthorization auth) {
//		String contentTypePost = "application/sparql-query";
//		String defGraph = "default-graph-uri";
//		String namedGraph = "named-graph-uri";
//		if (type.equals("update")) {
//			contentTypePost = "application/sparql-update";
//			defGraph = "using-graph-uri";
//			namedGraph = "using-named-graph-uri";
//		}
//
//		String sparql = null;
//		Set<String> default_graph_uri = null;
//		Set<String> named_graph_uri = null;
//
//		try {
//			HttpEntity entity = ((HttpEntityEnclosingRequest) exchange.getRequest()).getEntity();
//			String body = EntityUtils.toString(entity, Charset.forName("UTF-8"));
//
//			Header[] headers = exchange.getRequest().getHeaders("Content-Type");
//			if (headers.length != 1) {
//				logger.error("Content-Type is missing");
//				throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST, "Content-Type is missing");
//			}
//
//			if (headers[0].getValue().equals(contentTypePost)) {
//				logger.trace(type + " via POST directly");
//
//				String requestUri = exchange.getRequest().getRequestLine().getUri();
//
//				if (requestUri.indexOf('?') != -1) {
//					String queryParameters = requestUri.substring(requestUri.indexOf('?') + 1);
//					Map<String, Set<String>> params = HttpUtilities.splitQuery(queryParameters);
//					default_graph_uri = params.get(defGraph);
//					named_graph_uri = params.get(namedGraph);
//				}
//
//				sparql = body;
//
//			} else if (headers[0].getValue().equals("application/x-www-form-urlencoded")) {
//				logger.trace(type + " via URL ENCODED POST");
//
//				String decodedBody = URLDecoder.decode(body, "UTF-8");
//				Map<String, Set<String>> params = HttpUtilities.splitQuery(decodedBody);
//
//				sparql = params.get(type).iterator().next();
//				default_graph_uri = params.get(defGraph);
//				named_graph_uri = params.get(namedGraph);
//			} else {
//				logger.error("Request MUST conform to SPARQL 1.1 Protocol (https://www.w3.org/TR/sparql11-protocol/)");
//				throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,
//						"Request MUST conform to SPARQL 1.1 Protocol (https://www.w3.org/TR/sparql11-protocol/)");
//			}
//
//		} catch (ParseException | IOException e) {
//			logger.error(e.getMessage());
//			throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST, e.getMessage());
//		}
//
//		try {
//			if (type.equals("query")) {
//				Header[] headers = exchange.getRequest().getHeaders("Accept");
//				logger.debug("query Accept headers: " + headers.length);
//				if (headers.length != 1)
//					return new InternalQueryRequest(sparql, default_graph_uri, named_graph_uri, auth);
//				else
//					return new InternalQueryRequest(sparql, default_graph_uri, named_graph_uri, auth,
//							headers[0].getValue());
//			} else
//				return new InternalUpdateRequest(sparql, default_graph_uri, named_graph_uri, auth);
//		} catch (SEPASparqlParsingException e) {
//			logger.error(e.getMessage());
//			throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST, e.getMessage());
//		}
//	}

	@Override
	public HttpAsyncRequestConsumer<HttpRequest> processRequest(HttpRequest request, HttpContext context)
			throws HttpException, IOException {
		logger.log(Level.getLevel("http"), "@processRequest " + request + " " + context);
		// Buffer request content in memory for simplicity
		return new BasicAsyncRequestConsumer();
	}

	@Override
	public void handle(HttpRequest request, HttpAsyncExchange httpExchange, HttpContext context)
			throws HttpException, IOException {
		logger.log(Level.getLevel("http"), "@handle " + request + " " + context);
		// CORS
		if (!corsHandling(httpExchange))
			return;

		// Authorize
		ClientAuthorization oauth = null;
		try {
			oauth = authorize(httpExchange.getRequest());
		} catch (SEPASecurityException e1) {
			HttpUtilities.sendFailureResponse(httpExchange,
					new ErrorResponse(HttpStatus.SC_UNAUTHORIZED, "oauth_exception", e1.getMessage()));
			jmx.authorizingFailed();
			return;
		}

		InternalUQRequest sepaRequest = null;

		try {
			// Parsing SPARQL 1.1 request and attach a token
			sepaRequest = parse(httpExchange, oauth);
		} catch (SPARQL11ProtocolException e) {
			logger.log(Level.getLevel("http"),"Parsing failed: " + httpExchange.getRequest());
			HttpUtilities.sendFailureResponse(httpExchange,
					new ErrorResponse(e.getCode(), "SPARQL11ProtocolException", "Parsing failed: " + e.getMessage()));
			jmx.parsingFailed();
			return;
		}

		// Schedule request
		Timings.log(sepaRequest);
		ScheduledRequest req = scheduler.schedule(sepaRequest, new SPARQL11ResponseHandler(httpExchange, jmx));
		if (req == null) {
			logger.error("Out of tokens");
			HttpUtilities.sendFailureResponse(httpExchange,
					new ErrorResponse(429, "too_many_requests", "Too many pending requests"));
			jmx.outOfTokens();
		}
	}

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
