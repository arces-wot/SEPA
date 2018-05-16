/* This class implements a naive implementation of a SPU
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

package it.unibo.arces.wot.sepa.engine.processing.subscriptions;

import org.apache.logging.log4j.Logger;

import it.unibo.arces.wot.sepa.commons.exceptions.SEPAProtocolException;
import it.unibo.arces.wot.sepa.commons.protocol.SPARQL11Properties;
import it.unibo.arces.wot.sepa.commons.request.SubscribeRequest;
import it.unibo.arces.wot.sepa.commons.response.ErrorResponse;
import it.unibo.arces.wot.sepa.commons.response.Notification;
import it.unibo.arces.wot.sepa.commons.response.QueryResponse;
import it.unibo.arces.wot.sepa.commons.response.Response;
import it.unibo.arces.wot.sepa.commons.response.SubscribeResponse;
import it.unibo.arces.wot.sepa.commons.response.UpdateResponse;
import it.unibo.arces.wot.sepa.commons.sparql.ARBindingsResults;
import it.unibo.arces.wot.sepa.commons.sparql.Bindings;
import it.unibo.arces.wot.sepa.commons.sparql.BindingsResults;
import it.unibo.arces.wot.sepa.engine.bean.ProcessorBeans;
import it.unibo.arces.wot.sepa.engine.core.EventHandler;

import java.util.concurrent.Semaphore;

import org.apache.logging.log4j.LogManager;

public class SPUNaive extends SPU {
	private final Logger logger;

	private BindingsResults lastBindings = null;
	private Integer sequence = 1;

	public SPUNaive(SubscribeRequest subscribe, EventHandler handler, SPARQL11Properties endpointProperties,
			Semaphore endpointSemaphore, SPUSync sync) throws SEPAProtocolException {
		super(subscribe, endpointProperties, handler, endpointSemaphore, sync);

		logger = LogManager.getLogger("SPUNaive" + getUUID());
		logger.debug("SPU: " + this.getUUID() + " request: " + subscribe);
	}

	@Override
	public Response init() {
		logger.debug("Process SPARQL query " + request);

		// Process the SPARQL query
		Response ret = queryProcessor.process(request, ProcessorBeans.getQueryTimeout());

		if (ret.getClass().equals(ErrorResponse.class)) {
			logger.error("Not initialized");
			return ret;
		}

		lastBindings = ((QueryResponse) ret).getBindingsResults();
		firstResults = new BindingsResults(lastBindings);

		logger.debug("First results: " + firstResults.toString());

		return new SubscribeResponse(request.getToken(), getUUID(), request.getAlias(), getFirstResults());
	}

	@Override
	public Response processInternal(UpdateResponse update, int timeout) {
		logger.debug("* PROCESSING *" + request);
		Response ret;
		
		try {
			// Query the SPARQL processing service
			ret = queryProcessor.process(request, timeout);

			if (ret.getClass().equals(ErrorResponse.class)) {
				logger.error(ret);
				return ret;
			}

			// Current and previous bindings
			BindingsResults results = ((QueryResponse) ret).getBindingsResults();
			BindingsResults currentBindings = new BindingsResults(results);

			// Initialize the results with the current bindings
			BindingsResults added = new BindingsResults(results.getVariables(), null);
			BindingsResults removed = new BindingsResults(results.getVariables(), null);

			// Create empty bindings if null
			if (lastBindings == null)
				lastBindings = new BindingsResults(null, null);

			logger.debug("Current bindings: " + currentBindings);
			logger.debug("Last bindings: " + lastBindings);

			// Find removed bindings
			long start = System.nanoTime();
			for (Bindings solution : lastBindings.getBindings()) {
				if (!results.contains(solution) && !solution.isEmpty())
					removed.add(solution);
				else
					results.remove(solution);
			}
			long stop = System.nanoTime();
			logger.debug("Removed bindings: " + removed + " found in " + (stop - start) + " ns");

			// Find added bindings
			start = System.nanoTime();
			for (Bindings solution : results.getBindings()) {
				if (!lastBindings.contains(solution) && !solution.isEmpty())
					added.add(solution);
			}
			stop = System.nanoTime();
			logger.debug("Added bindings: " + added + " found in " + (stop - start) + " ns");

			// Update the last bindings with the current ones
			lastBindings = currentBindings;

			// Send notification (or end processing indication)
			if (!added.isEmpty() || !removed.isEmpty()) ret = new Notification(getUUID(), new ARBindingsResults(added, removed), sequence++);
		} catch (Exception e) {
			ret = new ErrorResponse(500, e.getMessage());
		}
		
		return ret;
	}
}
