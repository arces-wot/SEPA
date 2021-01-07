package it.unibo.arces.wot.sepa;

import java.io.IOException;

import it.unibo.arces.wot.sepa.commons.exceptions.SEPABindingsException;
import it.unibo.arces.wot.sepa.commons.exceptions.SEPAPropertiesException;
import it.unibo.arces.wot.sepa.commons.exceptions.SEPAProtocolException;
import it.unibo.arces.wot.sepa.commons.exceptions.SEPASecurityException;
import it.unibo.arces.wot.sepa.commons.sparql.ARBindingsResults;
import it.unibo.arces.wot.sepa.commons.sparql.BindingsResults;
import it.unibo.arces.wot.sepa.pattern.Consumer;

public class ConsumerTestUnit extends Consumer {
	protected static boolean notificationReceived = false;
	protected static boolean firstResultsReceived = false;
	
	public ConsumerTestUnit(ConfigurationProvider provider, String subscribeID)
			throws SEPAProtocolException, SEPASecurityException, SEPAPropertiesException {
		super(provider.getJsap(), subscribeID);
	}

	public void syncSubscribe(long timeout,long nretry) throws SEPASecurityException, IOException, SEPAPropertiesException, SEPAProtocolException, InterruptedException, SEPABindingsException {
		logger.debug("subscribe");
		
		notificationReceived = false;
		firstResultsReceived = false;
		
		super.subscribe(timeout,nretry);
		
		synchronized(this) {
			while (!isSubscribed()) wait();
			logger.debug("subscribed");
		}
	}
	
	public void syncUnsubscribe(long timeout,long nretry) throws SEPASecurityException, SEPAPropertiesException, SEPAProtocolException, InterruptedException {
		logger.debug("unsubscribe");
		
		super.unsubscribe(timeout,nretry);
		
		synchronized(this) {
			while (isSubscribed()) wait();
			logger.debug("ussubscribed");
		}
	}
	
	public void waitNotification() throws InterruptedException {
		synchronized(this) {
			logger.debug("waitNotification");
			while (!notificationReceived) wait();
			notificationReceived = false;
			logger.debug("notification received");
		}
	}
	
	public void waitFirstNotification() throws InterruptedException {
		synchronized(this) {
			logger.debug("waitFirstNotification");
			while (!firstResultsReceived) wait();
			firstResultsReceived = false;
			logger.debug("notification received");
		}
	}
	
	@Override
	public void onResults(ARBindingsResults results) {
		synchronized(this) {
			logger.debug("onResults");
			notificationReceived = true;
			notify();
		}
	}

	@Override
	public void onFirstResults(BindingsResults results) {
		synchronized(this) {
			logger.debug("onFirstResults");
			firstResultsReceived = true;
			notify();
		}	
	}

}
