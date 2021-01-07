/* This class implements a generic client of the SEPA Application Design Pattern (including the query primitive)
 * 
 * Author: Luca Roffia (luca.roffia@unibo.it)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package it.unibo.arces.wot.sepa.pattern;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Hashtable;

import it.unibo.arces.wot.sepa.api.ISubscriptionHandler;
import it.unibo.arces.wot.sepa.api.SPARQL11SEProperties;
import it.unibo.arces.wot.sepa.api.SubscriptionProtocol;
import it.unibo.arces.wot.sepa.api.protocols.websocket.WebsocketSubscriptionProtocol;
import it.unibo.arces.wot.sepa.api.SPARQL11SEProtocol;
import it.unibo.arces.wot.sepa.commons.sparql.Bindings;
import it.unibo.arces.wot.sepa.commons.exceptions.SEPABindingsException;
import it.unibo.arces.wot.sepa.commons.exceptions.SEPAPropertiesException;
import it.unibo.arces.wot.sepa.commons.exceptions.SEPAProtocolException;
import it.unibo.arces.wot.sepa.commons.exceptions.SEPASecurityException;

import it.unibo.arces.wot.sepa.commons.protocol.SPARQL11Protocol;

import it.unibo.arces.wot.sepa.commons.request.QueryRequest;
import it.unibo.arces.wot.sepa.commons.request.Request;
import it.unibo.arces.wot.sepa.commons.request.SubscribeRequest;
import it.unibo.arces.wot.sepa.commons.request.UnsubscribeRequest;
import it.unibo.arces.wot.sepa.commons.request.UpdateRequest;
import it.unibo.arces.wot.sepa.commons.response.ErrorResponse;
import it.unibo.arces.wot.sepa.commons.response.Notification;
import it.unibo.arces.wot.sepa.commons.response.Response;

/**
 * The Class GenericClient.
 */
public final class GenericClient extends Client implements ISubscriptionHandler {
	private ISubscriptionHandler handler;

	// Subscription request handling
	private Request req = null;
	private Object subLock = new Object();
	private String url = null;
	private SPARQL11SEProtocol subscription = null;
	private SubscriptionProtocol protocol = null;
	private final SPARQL11Protocol client;

	/** The active urls. */
	// URL ==> client
	private Hashtable<String, SPARQL11SEProtocol> activeClients = new Hashtable<String, SPARQL11SEProtocol>();

	/** The subscriptions. */
	// SPUID ==> client
	private Hashtable<String, SPARQL11SEProtocol> subscriptions = new Hashtable<String, SPARQL11SEProtocol>();

	private Hashtable<String, SubscriptionProtocol> protocols = new Hashtable<String, SubscriptionProtocol>();

	@Override
	public void onSemanticEvent(Notification notify) {
		if (handler != null)
			handler.onSemanticEvent(notify);
	}

	@Override
	public void onBrokenConnection(ErrorResponse errorResponse) {
		if (handler != null)
			handler.onBrokenConnection(errorResponse);
	}

	@Override
	public void onError(ErrorResponse errorResponse) {
//		if (errorResponse.isTokenExpiredError()) {
//			String message = "Failed to refresh token";
//			try {
//				sm.refreshToken();
//				
//				message = "Failed to get authorization header after token refresh";
//				req.setAuthorizationHeader(appProfile.getAuthenticationProperties().getBearerAuthorizationHeader());
//				
//				if (req.isSubscribeRequest()) {
//					message = "Failed to subscribe after token refresh";
//					subscription.subscribe((SubscribeRequest) req);
//				}
//				else {
//					message = "Failed to unsubscribe after token refresh";
//					subscription.unsubscribe((UnsubscribeRequest) req);
//				}			
//			} catch (SEPAPropertiesException | SEPASecurityException | SEPAProtocolException e) {
//				logger.error(e.getMessage());
//				if (logger.isTraceEnabled())
//					e.printStackTrace();
//				if (handler != null)
//					handler.onError(
//							new ErrorResponse(401, "invalid_grant", message +" "+ e.getMessage()));
//				return;
//			}
//		}

		if (handler != null)
			handler.onError(errorResponse);

	}

	@Override
	public void onSubscribe(String spuid, String alias) {
		synchronized (subLock) {
			activeClients.put(url, subscription);
			subscriptions.put(spuid, subscription);
			protocols.put(url, protocol);
			req = null;
			subLock.notify();
		}

		if (handler != null)
			handler.onSubscribe(spuid, alias);
	}

	@Override
	public void onUnsubscribe(String spuid) {
		synchronized (subLock) {
			subscriptions.remove(spuid);
			req = null;
			subLock.notify();
		}

		if (handler != null)
			handler.onUnsubscribe(spuid);
	}

//	/**
//	 * Instantiates a new generic client.
//	 *
//	 * @param appProfile the JSAP profile
//	 * @param sm         the security manager (needed for secure connections)
//	 * @throws SEPAProtocolException the SEPA protocol exception
//	 */
//	public GenericClient(JSAP appProfile, ClientSecurityManager sm) throws SEPAProtocolException {
//		this(appProfile, sm, null);
//	}

	public GenericClient(JSAP appProfile, ISubscriptionHandler handler)
			throws SEPAProtocolException, SEPASecurityException, SEPAPropertiesException {
		super(appProfile);
		client = new SPARQL11Protocol(sm);
		this.handler = handler;
	}

	public void setHandler(ISubscriptionHandler handler) {
		this.handler = handler;
	}

	/**
	 * Update.
	 *
	 * @param ID      the identifier of the update within the JSAP
	 * @param sparql  if specified it replaces the default SPARQL in the JSAP
	 * @param forced  the forced bindings
	 * @param timeout the timeout
	 * @return the response
	 * @throws SEPAProtocolException   the SEPA protocol exception
	 * @throws SEPASecurityException   the SEPA security exception
	 * @throws IOException             Signals that an I/O exception has occurred.
	 * @throws SEPAPropertiesException the SEPA properties exception
	 * @throws SEPABindingsException   the SEPA bindings exception
	 */
	public Response update(String ID, String sparql, Bindings forced, long timeout, long nRetry)
			throws SEPAProtocolException, SEPASecurityException, IOException, SEPAPropertiesException,
			SEPABindingsException {
		return _update(ID, sparql, forced, timeout, nRetry);
	}

	public Response update(String ID, String sparql, Bindings forced) throws SEPAProtocolException,
			SEPASecurityException, IOException, SEPAPropertiesException, SEPABindingsException {
		return _update(ID, sparql, forced, TIMEOUT, NRETRY);
	}

	/**
	 * Update.
	 *
	 * @param ID      the identifier of the update within the JSAP
	 * @param forced  the forced bindings
	 * @param timeout the timeout
	 * @return the response
	 * @throws SEPAProtocolException   the SEPA protocol exception
	 * @throws SEPASecurityException   the SEPA security exception
	 * @throws IOException             Signals that an I/O exception has occurred.
	 * @throws SEPAPropertiesException the SEPA properties exception
	 * @throws SEPABindingsException   the SEPA bindings exception
	 */
	public Response update(String ID, Bindings forced, long timeout, long nRetry) throws SEPAProtocolException,
			SEPASecurityException, IOException, SEPAPropertiesException, SEPABindingsException {
		return _update(ID, null, forced, timeout, nRetry);
	}

	public Response update(String ID, Bindings forced) throws SEPAProtocolException, SEPASecurityException, IOException,
			SEPAPropertiesException, SEPABindingsException {
		return _update(ID, null, forced, TIMEOUT, NRETRY);
	}

	/**
	 * Query.
	 *
	 * @param ID      the identifier of the query within the JSAP
	 * @param sparql  if specified it replaces the default SPARQL in the JSAP
	 * @param forced  the forced bindings
	 * @param timeout the timeout
	 * @return the response
	 * @throws SEPAProtocolException   the SEPA protocol exception
	 * @throws SEPASecurityException   the SEPA security exception
	 * @throws IOException             Signals that an I/O exception has occurred.
	 * @throws SEPAPropertiesException the SEPA properties exception
	 * @throws SEPABindingsException   the SEPA bindings exception
	 */
	public Response query(String ID, String sparql, Bindings forced, long timeout, long nRetry)
			throws SEPAProtocolException, SEPASecurityException, IOException, SEPAPropertiesException,
			SEPABindingsException {
		return _query(ID, sparql, forced, timeout, nRetry);
	}

	public Response query(String ID, String sparql, Bindings forced) throws SEPAProtocolException,
			SEPASecurityException, IOException, SEPAPropertiesException, SEPABindingsException {
		return _query(ID, sparql, forced, TIMEOUT, NRETRY);
	}

	/**
	 * Query.
	 *
	 * @param ID      the identifier of the query within the JSAP
	 * @param forced  the forced
	 * @param timeout the timeout
	 * @return the response
	 * @throws SEPAProtocolException   the SEPA protocol exception
	 * @throws SEPASecurityException   the SEPA security exception
	 * @throws SEPAPropertiesException the SEPA properties exception
	 * @throws SEPABindingsException   the SEPA bindings exception
	 */
	public Response query(String ID, Bindings forced, long timeout, long nRetry)
			throws SEPAProtocolException, SEPASecurityException, SEPAPropertiesException, SEPABindingsException {
		return _query(ID, null, forced, timeout, nRetry);
	}

	public Response query(String ID, Bindings forced)
			throws SEPAProtocolException, SEPASecurityException, SEPAPropertiesException, SEPABindingsException {
		return _query(ID, null, forced, TIMEOUT, NRETRY);
	}

	/**
	 * Subscribe.
	 *
	 * @param ID      the identifier of the subscribe within the JSAP
	 * @param sparql  if specified it replaces the default SPARQL in the JSAP
	 * @param forced  the forced
	 * @param handler the handler
	 * @param timeout the timeout
	 * @throws SEPAProtocolException   the SEPA protocol exception
	 * @throws SEPASecurityException   the SEPA security exception
	 * @throws SEPAPropertiesException the SEPA properties exception
	 * @throws SEPABindingsException   the SEPA bindings exception
	 * @throws InterruptedException
	 */
	public void subscribe(String ID, String sparql, Bindings forced, String alias, long timeout, long nRetry)
			throws SEPAProtocolException, SEPASecurityException, SEPAPropertiesException, SEPABindingsException,
			InterruptedException {
		_subscribe(ID, sparql, forced, alias, timeout, nRetry);
	}

	public void subscribe(String ID, String sparql, Bindings forced, String alias) throws SEPAProtocolException,
			SEPASecurityException, SEPAPropertiesException, SEPABindingsException, InterruptedException {
		_subscribe(ID, sparql, forced, alias, TIMEOUT, NRETRY);
	}

	public void subscribe(String ID, String sparql, Bindings forced, long timeout, long nRetry)
			throws SEPAProtocolException, SEPASecurityException, SEPAPropertiesException, SEPABindingsException,
			InterruptedException {
		_subscribe(ID, sparql, forced, null, timeout, nRetry);
	}

	public void subscribe(String ID, String sparql, Bindings forced) throws SEPAProtocolException,
			SEPASecurityException, SEPAPropertiesException, SEPABindingsException, InterruptedException {
		_subscribe(ID, sparql, forced, null, TIMEOUT, NRETRY);
	}

	/**
	 * Subscribe.
	 *
	 * @param ID      the identifier of the subscribe within the JSAP
	 * @param forced  the forced
	 * @param handler the handler
	 * @param timeout the timeout
	 * @throws SEPAProtocolException   the SEPA protocol exception
	 * @throws SEPASecurityException   the SEPA security exception
	 * @throws SEPAPropertiesException the SEPA properties exception
	 * @throws SEPABindingsException   the SEPA bindings exception
	 * @throws InterruptedException
	 */
	public void subscribe(String ID, Bindings forced, String alias, long timeout, long nRetry)
			throws SEPAProtocolException, SEPASecurityException, SEPAPropertiesException, SEPABindingsException,
			InterruptedException {
		_subscribe(ID, null, forced, alias, timeout, nRetry);
	}

	public void subscribe(String ID, Bindings forced, String alias) throws SEPAProtocolException, SEPASecurityException,
			SEPAPropertiesException, SEPABindingsException, InterruptedException {
		_subscribe(ID, null, forced, alias, TIMEOUT, NRETRY);
	}

	public void subscribe(String ID, Bindings forced, long timeout, long nRetry) throws SEPAProtocolException,
			SEPASecurityException, SEPAPropertiesException, SEPABindingsException, InterruptedException {
		_subscribe(ID, null, forced, null, timeout, nRetry);
	}

	public void subscribe(String ID, Bindings forced) throws SEPAProtocolException, SEPASecurityException,
			SEPAPropertiesException, SEPABindingsException, InterruptedException {
		_subscribe(ID, null, forced, null, TIMEOUT, NRETRY);
	}

	/**
	 * Unsubscribe.
	 *
	 * @param ID      the SPUID of the active subscription
	 * @param timeout the timeout
	 * @throws SEPASecurityException   the SEPA security exception
	 * @throws SEPAPropertiesException the SEPA properties exception
	 * @throws SEPAProtocolException   the SEPA protocol exception
	 * @throws InterruptedException
	 */
	public void unsubscribe(String subID)
			throws SEPASecurityException, SEPAPropertiesException, SEPAProtocolException, InterruptedException {
		unsubscribe(subID, TIMEOUT, NRETRY);
	}

	public void unsubscribe(String subID, long timeout, long nRetry)
			throws SEPASecurityException, SEPAPropertiesException, SEPAProtocolException, InterruptedException {
		if (!subscriptions.containsKey(subID))
			return;

		synchronized (subLock) {
			if (req != null)
				subLock.wait();

			req = new UnsubscribeRequest(subID, (appProfile.isSecure() ? appProfile.getAuthenticationProperties().getBearerAuthorizationHeader() : null), timeout, nRetry);

			subscriptions.get(subID).unsubscribe((UnsubscribeRequest) req);
		}
	}

	/**
	 * Update.
	 *
	 * @param ID      the identifier of the update within the JSAP
	 * @param sparql  if specified it replaces the default SPARQL in the JSAP
	 * @param forced  the forced
	 * @param timeout the timeout
	 * @return the response
	 * @throws SEPAProtocolException   the SEPA protocol exception
	 * @throws SEPASecurityException   the SEPA security exception
	 * @throws IOException             Signals that an I/O exception has occurred.
	 * @throws SEPAPropertiesException the SEPA properties exception
	 * @throws SEPABindingsException   the SEPA bindings exception
	 */
	private Response _update(String ID, String sparql, Bindings forced, long timeout, long nRetry)
			throws SEPAProtocolException, SEPASecurityException, SEPAPropertiesException, SEPABindingsException {
		if (sparql == null)
			sparql = appProfile.getSPARQLUpdate(ID);

		if (sparql == null)
			throw new SEPAProtocolException("SPARQL update not found " + ID);

		Response ret = client
				.update(new UpdateRequest(appProfile.getUpdateMethod(ID), appProfile.getUpdateProtocolScheme(ID),
						appProfile.getUpdateHost(ID), appProfile.getUpdatePort(ID), appProfile.getUpdatePath(ID),
						appProfile.addPrefixesAndReplaceBindings(sparql, addDefaultDatatype(forced, ID, false)),
						appProfile.getUsingGraphURI(ID), appProfile.getUsingNamedGraphURI(ID), (appProfile.isSecure() ? appProfile.getAuthenticationProperties().getBearerAuthorizationHeader() : null), timeout, nRetry));

//		if (appProfile.isSecure() && ret.isError()) {
//			ErrorResponse errorResponse = (ErrorResponse) ret;
//
//			if (errorResponse.isTokenExpiredError()) {
//				sm.refreshToken();
//
//				ret = client.update(new UpdateRequest(appProfile.getUpdateMethod(ID),
//						appProfile.getUpdateProtocolScheme(ID), appProfile.getUpdateHost(ID),
//						appProfile.getUpdatePort(ID), appProfile.getUpdatePath(ID),
//						appProfile.addPrefixesAndReplaceBindings(sparql, addDefaultDatatype(forced, ID, false)),
//						appProfile.getUsingGraphURI(ID), appProfile.getUsingNamedGraphURI(ID), (appProfile.isSecure() ? appProfile.getAuthenticationProperties().getBearerAuthorizationHeader() : null), timeout, nRetry));
//			}
//		}

		return ret;
	}

	/**
	 * Query.
	 *
	 * @param ID      the identifier of the query within the JSAP
	 * @param sparql  if specified it replaces the default SPARQL in the JSAP
	 * @param forced  the forced
	 * @param timeout the timeout
	 * @return the response
	 * @throws SEPAProtocolException   the SEPA protocol exception
	 * @throws SEPASecurityException   the SEPA security exception
	 * @throws IOException             Signals that an I/O exception has occurred.
	 * @throws SEPAPropertiesException the SEPA properties exception
	 * @throws SEPABindingsException   the SEPA bindings exception
	 */
	private Response _query(String ID, String sparql, Bindings forced, long timeout, long nRetry)
			throws SEPAProtocolException, SEPASecurityException, SEPAPropertiesException, SEPABindingsException {
		if (sparql == null)
			sparql = appProfile.getSPARQLQuery(ID);

		if (sparql == null)
			throw new SEPAProtocolException("SPARQL query not found " + ID);

		Response ret = client
				.query(new QueryRequest(appProfile.getQueryMethod(ID), appProfile.getQueryProtocolScheme(ID),
						appProfile.getQueryHost(ID), appProfile.getQueryPort(ID), appProfile.getQueryPath(ID),
						appProfile.addPrefixesAndReplaceBindings(sparql, addDefaultDatatype(forced, ID, true)),
						appProfile.getDefaultGraphURI(ID), appProfile.getNamedGraphURI(ID), (appProfile.isSecure() ? appProfile.getAuthenticationProperties().getBearerAuthorizationHeader() : null), timeout, nRetry));

//		if (appProfile.isSecure() && ret.isError()) {
//			ErrorResponse errorResponse = (ErrorResponse) ret;
//
//			if (errorResponse.isTokenExpiredError()) {
//				sm.refreshToken();
//
//				ret = client
//						.query(new QueryRequest(appProfile.getQueryMethod(ID), appProfile.getQueryProtocolScheme(ID),
//								appProfile.getQueryHost(ID), appProfile.getQueryPort(ID), appProfile.getQueryPath(ID),
//								appProfile.addPrefixesAndReplaceBindings(sparql, addDefaultDatatype(forced, ID, true)),
//								appProfile.getDefaultGraphURI(ID), appProfile.getNamedGraphURI(ID), (appProfile.isSecure() ? appProfile.getAuthenticationProperties().getBearerAuthorizationHeader() : null), timeout, nRetry));
//			}
//		}

		return ret;
	}

	/**
	 * Subscribe.
	 *
	 * @param ID      the identifier of the subscribe within the JSAP
	 * @param sparql  if specified it replaces the default SPARQL in the JSAP
	 * @param forced  the forced
	 * @param handler the handler
	 * @param timeout the timeout
	 * @throws SEPAProtocolException   the SEPA protocol exception
	 * @throws SEPASecurityException   the SEPA security exception
	 * @throws IOException             Signals that an I/O exception has occurred.
	 * @throws SEPAPropertiesException the SEPA properties exception
	 * @throws URISyntaxException      the URI syntax exception
	 * @throws SEPABindingsException   the SEPA bindings exception
	 * @throws InterruptedException
	 */
	private void _subscribe(String ID, String sparql, Bindings forced, String alias, long timeout, long nRretry)
			throws SEPAProtocolException, SEPASecurityException, SEPAPropertiesException, SEPABindingsException,
			InterruptedException {

		if (sparql == null)
			sparql = appProfile.getSPARQLQuery(ID);

		if (sparql == null)
			throw new SEPAProtocolException("SPARQL query not found " + ID);

		synchronized (subLock) {
			if (req != null)
				subLock.wait();

			if (appProfile.getSubscribeProtocol(ID).equals(SPARQL11SEProperties.SubscriptionProtocol.WS)) {
				url = "ws_" + appProfile.getSubscribeHost(ID) + "_" + appProfile.getSubscribePort(ID) + "_"
						+ appProfile.getSubscribePath(ID);
			} else {
				url = "wss_" + appProfile.getSubscribeHost(ID) + "_" + appProfile.getSubscribePort(ID) + "_"
						+ appProfile.getSubscribePath(ID);
			}

			if (activeClients.containsKey(url)) {
				subscription = activeClients.get(url);
			} else {
				protocol = new WebsocketSubscriptionProtocol(appProfile.getSubscribeHost(ID),
						appProfile.getSubscribePort(ID), appProfile.getSubscribePath(ID), this, sm);
				subscription = new SPARQL11SEProtocol(protocol);
			}

			req = new SubscribeRequest(
					appProfile.addPrefixesAndReplaceBindings(sparql, addDefaultDatatype(forced, ID, true)), alias,
					appProfile.getDefaultGraphURI(ID), appProfile.getNamedGraphURI(ID), (appProfile.isSecure() ? appProfile.getAuthenticationProperties().getBearerAuthorizationHeader() : null), timeout, nRretry);

			subscription.subscribe((SubscribeRequest) req);
		}
	}

	@Override
	public void close() throws IOException {
		for (SPARQL11SEProtocol client : activeClients.values())
			client.close();
		for (SubscriptionProtocol protocol : protocols.values())
			protocol.close();

		client.close();
	}
}
