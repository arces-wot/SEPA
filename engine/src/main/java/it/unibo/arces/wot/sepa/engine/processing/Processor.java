/*
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
 * */

package it.unibo.arces.wot.sepa.engine.processing;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import it.unibo.arces.wot.sepa.commons.exceptions.SEPAProcessingException;
import it.unibo.arces.wot.sepa.commons.exceptions.SEPAProtocolException;
import it.unibo.arces.wot.sepa.commons.exceptions.SEPASecurityException;
import it.unibo.arces.wot.sepa.commons.exceptions.SEPASparqlParsingException;
import it.unibo.arces.wot.sepa.commons.protocol.SPARQL11Properties;
import it.unibo.arces.wot.sepa.commons.response.ErrorResponse;
import it.unibo.arces.wot.sepa.commons.response.Response;
import it.unibo.arces.wot.sepa.engine.bean.ProcessorBeans;
import it.unibo.arces.wot.sepa.engine.bean.QueryProcessorBeans;
import it.unibo.arces.wot.sepa.engine.bean.SEPABeans;
import it.unibo.arces.wot.sepa.engine.bean.UpdateProcessorBeans;
import it.unibo.arces.wot.sepa.engine.core.EngineProperties;
import it.unibo.arces.wot.sepa.engine.processing.subscriptions.SPUManager;
import it.unibo.arces.wot.sepa.engine.protocol.sparql11.SPARQL11ProtocolException;
import it.unibo.arces.wot.sepa.engine.scheduling.InternalQueryRequest;
import it.unibo.arces.wot.sepa.engine.scheduling.InternalSubscribeRequest;
import it.unibo.arces.wot.sepa.engine.scheduling.InternalUpdateRequest;
import it.unibo.arces.wot.sepa.engine.scheduling.ScheduledRequest;
import it.unibo.arces.wot.sepa.engine.scheduling.Scheduler;

/**
 * This class implements the processing of the requests coming form the
 * scheduler
 * 
 * 
 * @author Luca Roffia (luca.roffia@unibo.it)
 * @version 0.9.12
 */
public class Processor implements ProcessorMBean {
	private final Logger logger = LogManager.getLogger();

	// Processor threads
	private final UpdateProcessingThread updateProcessingThread;
	private final SubscribeProcessingThread subscribeProcessingThread;
	private final UnsubscribeProcessingThread unsubscribeProcessingThread;
	private final QueryProcessingThread queryProcessingThread;

	// SPARQL Processors
	private final QueryProcessor queryProcessor;
	private final UpdateProcessor updateProcessor;

	// SPU manager
	private final SPUManager spuManager;

	// Scheduler queue
	private final Scheduler scheduler;

	// Running flag
	private final AtomicBoolean running = new AtomicBoolean(true);

	public Processor(SPARQL11Properties endpointProperties, EngineProperties properties, Scheduler scheduler)
			throws IllegalArgumentException, SEPAProtocolException, SEPASecurityException {

		this.scheduler = scheduler;

		// Processors
		queryProcessor = new QueryProcessor(endpointProperties);
		updateProcessor = new UpdateProcessor(endpointProperties);

		// SPU Manager
		spuManager = new SPUManager(this);

		// Subscribe/Unsubscribe processing
		subscribeProcessingThread = new SubscribeProcessingThread(this);
		unsubscribeProcessingThread = new UnsubscribeProcessingThread(this);

		// Update processor
		updateProcessingThread = new UpdateProcessingThread(this);

		// Query processing
		queryProcessingThread = new QueryProcessingThread(this);

		// JMX
		SEPABeans.registerMBean("SEPA:type=" + this.getClass().getSimpleName(), this);
		ProcessorBeans.setEndpoint(endpointProperties);
		QueryProcessorBeans.setTimeout(properties.getQueryTimeout());
		UpdateProcessorBeans.setTimeout(properties.getUpdateTimeout());
		UpdateProcessorBeans.setReilable(properties.isUpdateReliable());
	}

	public boolean isRunning() {
		return running.get();
	}

	public void start() {
		running.set(true);
		queryProcessingThread.start();
		subscribeProcessingThread.start();
		unsubscribeProcessingThread.start();
		updateProcessingThread.start();
	}

	public void interrupt() {
		running.set(false);
		queryProcessingThread.interrupt();
		unsubscribeProcessingThread.interrupt();
		subscribeProcessingThread.interrupt();
		updateProcessingThread.interrupt();
	}

	// Processing primitives
	public synchronized Response processSubscribe(InternalSubscribeRequest request) {
		return spuManager.subscribe(request);
	}

	public synchronized Response processUnsubscribe(String sid, String gid) {
		return spuManager.unsubscribe(sid, gid);
	}

	public synchronized Response processUpdate(InternalUpdateRequest update) {
		InternalUpdateRequest preRequest = update;
		if (spuManager.doUpdateARQuadsExtraction(update)) {
			try {
				preRequest = ARQuadsAlgorithm.extractARQuads(update, queryProcessor);
			} catch (SEPAProcessingException | SPARQL11ProtocolException | SEPASparqlParsingException e) {
				return new ErrorResponse(HttpStatus.SC_INTERNAL_SERVER_ERROR, "update_processing", e.getMessage());
			}
		}

		// PRE-UPDATE processing
		spuManager.subscriptionsProcessingPreUpdate(preRequest);

		// Endpoint UPDATE
		Response ret;
		try {
			ret = updateEndpoint(preRequest);
		} catch (SEPASecurityException | IOException e) {
			return new ErrorResponse(HttpStatus.SC_INTERNAL_SERVER_ERROR, "sparql11endpoint", e.getMessage());
		}

		// STOP processing?
		if (ret.isError()) {
			logger.error("*** UPDATE ENDPOINT PROCESSING FAILED *** " + ret);
			spuManager.abortSubscriptionsProcessing();
			return ret;
		}

		// POST-UPDATE processing
		spuManager.subscriptionsProcessingPostUpdate(ret);

		return ret;
	}

//	public void killSubscription(String sid, String gid) throws InterruptedException {
//		spuManager.killSubscription(sid, gid);
//	}

	private Response updateEndpoint(InternalUpdateRequest preRequest) throws SEPASecurityException, IOException {
		return updateProcessor.process(preRequest);
	}

	public Response processQuery(InternalQueryRequest query) throws SEPASecurityException, IOException {
		return queryProcessor.process(query);
	}

	boolean isUpdateReliable() {
		return UpdateProcessorBeans.getReilable();
	}

	ScheduledRequest waitQueryRequest() throws InterruptedException {
		return scheduler.waitQueryRequest();
	}

	ScheduledRequest waitSubscribeRequest() throws InterruptedException {
		return scheduler.waitSubscribeRequest();
	}

	ScheduledRequest waitUpdateRequest() throws InterruptedException {
		return scheduler.waitUpdateRequest();
	}

	ScheduledRequest waitUnsubscribeRequest() throws InterruptedException {
		return scheduler.waitUnsubscribeRequest();
	}

	public void addResponse(int token, Response ret) {
		scheduler.addResponse(token, ret);
	}

	@Override
	public String getEndpointHost() {
		return ProcessorBeans.getEndpointHost();
	}

	@Override
	public int getEndpointPort() {
		return ProcessorBeans.getEndpointPort();
	}

	@Override
	public String getEndpointQueryPath() {
		return ProcessorBeans.getEndpointQueryPath();
	}

	@Override
	public String getEndpointUpdatePath() {
		return ProcessorBeans.getEndpointUpdatePath();
	}

	@Override
	public String getEndpointUpdateMethod() {
		return ProcessorBeans.getEndpointUpdateMethod().name();
	}

	@Override
	public String getEndpointQueryMethod() {
		return ProcessorBeans.getEndpointQueryMethod().name();
	}
}
