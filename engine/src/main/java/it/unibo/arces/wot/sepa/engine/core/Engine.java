/* This class is the main entry point of the Semantic Event Processing Architecture (SEPA) Engine
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
package it.unibo.arces.wot.sepa.engine.core;

import java.io.IOException;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.regex.PatternSyntaxException;

import org.apache.logging.log4j.LogManager;

import com.nimbusds.jose.JOSEException;

import it.unibo.arces.wot.sepa.commons.exceptions.SEPAPropertiesException;
import it.unibo.arces.wot.sepa.commons.exceptions.SEPAProtocolException;
import it.unibo.arces.wot.sepa.commons.exceptions.SEPASecurityException;
import it.unibo.arces.wot.sepa.commons.protocol.SPARQL11Properties;

import it.unibo.arces.wot.sepa.engine.bean.EngineBeans;
import it.unibo.arces.wot.sepa.engine.bean.ProcessorBeans;
import it.unibo.arces.wot.sepa.engine.bean.SEPABeans;
import it.unibo.arces.wot.sepa.engine.dependability.AuthorizationManager;
import it.unibo.arces.wot.sepa.engine.dependability.DependabilityManager;
import it.unibo.arces.wot.sepa.engine.processing.Processor;

import it.unibo.arces.wot.sepa.engine.protocol.websocket.WebsocketServer;
import it.unibo.arces.wot.sepa.engine.protocol.http.HttpGate;
import it.unibo.arces.wot.sepa.engine.protocol.http.HttpsGate;
import it.unibo.arces.wot.sepa.engine.protocol.websocket.SecureWebsocketServer;

import it.unibo.arces.wot.sepa.engine.scheduling.Scheduler;

/**
 * This class represents the SPARQL Subscription Broker (Core) of the Semantic
 * Event Processing Architecture (SEPA)
 * 
 * @author Luca Roffia (luca.roffia@unibo.it)
 * @version 0.9.0
 */

public class Engine implements EngineMBean {
	private static Engine engine;
	private static String version = "0.9.1";

	// Scheduler request queue
	private final SchedulerRequestResponseQueue schedulerQueue = new SchedulerRequestResponseQueue();

	// Primitives scheduler/dispatcher
	private Scheduler scheduler = null;

	// Primitives scheduler/dispatcher
	private Processor processor = null;

	// SPARQL 1.1 Protocol handler
	private HttpGate httpGate = null;

	// SPARQL 1.1 SE Protocol handler
	private WebsocketServer wsServer;
	private SecureWebsocketServer wssServer;
	private HttpsGate httpsGate = null;
	private int wsShutdownTimeout = 5000;

	// Outh 2.0 Authorization Server
	private AuthorizationManager oauth;

	// Dependability manager
	private DependabilityManager dependabilityMng;

	// JKS Credentials
	private String storeName = "sepa.jks";
	private String storePassword = "sepa2017";
	private String jwtAlias = "sepakey";
	private String jwtPassword = "sepa2017";
	private String serverCertificate = "sepacert";

	// Logging file name
	private void setLoggingFileName() {
		// Logging
		TimeZone tz = TimeZone.getTimeZone("UTC");
		DateFormat df = new SimpleDateFormat("yyyyMMdd_HH_mm_ss"); // Quoted "Z" to indicate UTC, no timezone offset
		df.setTimeZone(tz);
		String nowAsISO = df.format(new Date());
		System.setProperty("logFilename", nowAsISO);
		org.apache.logging.log4j.core.LoggerContext ctx = (org.apache.logging.log4j.core.LoggerContext) LogManager
				.getContext(false);
		ctx.reconfigure();
	}

	private void printUsage() {
		System.out.println("Usage:");
		System.out.println("java [JMX] [JVM] [LOG4J] -jar SEPAEngine_X.Y.Z.jar [JKS OPTIONS]");
		System.out.println("");
		System.out.println("JMX:");
		System.out.println("-Dcom.sun.management.config.file=jmx.properties : to enable JMX remote managment");
		System.out.println("JVM:");
		System.out.println("-XX:+UseG1GC");
		System.out.println("LOG4J");
		System.out.println("-Dlog4j.configurationFile=./log4j2.xml");
		System.out.println("JKS OPTIONS:");
		System.out.println("-help : to print this help");
		System.out.println("-storename=<name> : file name of the JKS     (default: sepa.jks)");
		System.out.println("-storepwd=<pwd> : password of the JKS        (default: sepa2017)");
		System.out.println("-alias=<jwt> : alias for the JWT key         (default: sepakey)");
		System.out.println("-aliaspwd=<pwd> : password of the JWT key    (default: sepa2017)");
		System.out.println("-certificate=<crt> : name of the certificate (default: sepacert)");
	}

	private void parsingArgument(String[] args) throws PatternSyntaxException {
		String[] tmp;
		for (String arg : args) {
			if (arg.equals("-help")) {
				printUsage();
				return;
			}
			if (arg.startsWith("-")) {
				tmp = arg.split("=");
				switch (tmp[0]) {
				case "-storename":
					storeName = tmp[1];
					break;
				case "-storepwd":
					storePassword = tmp[1];
					break;
				case "-alias":
					jwtAlias = tmp[1];
					break;
				case "-aliaspwd":
					jwtPassword = tmp[1];
					break;
				case "-certificate":
					serverCertificate = tmp[1];
					break;
				default:
					break;
				}
			}
		}
	}

	public Engine(String[] args) throws SEPASecurityException, SEPAProtocolException {
		// Set logging file name with the current timestamp YYYYMMDD_HH_MM_SS
		setLoggingFileName();

		// Command arguments
		parsingArgument(args);

		System.out
				.println("##########################################################################################");
		System.out
				.println("# SEPA Broker                                                                            #");
		System.out
				.println("# Dynamic Linked Data & Web of Things Research - University of Bologna (Italy)           #");
		System.out
				.println("# Copyright (C) 2016-2018                                                                #");
		System.out
				.println("# This program comes with ABSOLUTELY NO WARRANTY                                         #");
		System.out
				.println("# This is free software, and you are welcome to redistribute it under certain conditions #");
		System.out
				.println("# GNU GENERAL PUBLIC LICENSE, Version 3, 29 June 2007                                    #");
		System.out
				.println("#                                                                                        #");
		System.out
				.println("# GITHUB: https://github.com/arces-wot/sepa                                              #");
		System.out
				.println("# WEB: http://site.unibo.it/wot                                                          #");
		System.out
				.println("# WIKI: https: // github.com/arces-wot/SEPA/wiki                                         #");
		System.out
				.println("##########################################################################################");

		// Beans
		SEPABeans.registerMBean("SEPA:type=" + this.getClass().getSimpleName(), this);
		EngineBeans.setVersion(version);

		// Initialize SPARQL 1.1 SE processing service properties
		EngineProperties properties = null;
		try {
			properties = new EngineProperties("engine.jpar");
		} catch (SEPAPropertiesException e) {
			System.err.println("Failed to load engine.jpar: "+e.getMessage());
			properties = null;
		}

		SPARQL11Properties endpointProperties = null;
		try {
			endpointProperties = new SPARQL11Properties("endpoint.jpar");
		} catch (SEPAPropertiesException e2) {
			System.err.println("Failed to load endpoint.jpar: "+e2.getMessage());
			endpointProperties = null;
		}

		// OAUTH 2.0 Authorization Manager
		if (properties.isSecure()) {
			try {
				oauth = new AuthorizationManager(storeName, storePassword, jwtAlias, jwtPassword, serverCertificate);
			} catch (UnrecoverableKeyException | KeyManagementException | KeyStoreException | NoSuchAlgorithmException
					| CertificateException | IOException | JOSEException e1) {
				System.err.println(e1.getLocalizedMessage());
				System.exit(1);
			}
		}

		// SPARQL 1.1 SE request scheduler
		scheduler = new Scheduler(properties, schedulerQueue);
		scheduler.start();

		// Dependability manager
		dependabilityMng = new DependabilityManager(scheduler);

		// SEPA Processor
		try {
			processor = new Processor(endpointProperties, properties, schedulerQueue);
		} catch (SEPAProtocolException e1) {
			System.err.println(e1.getMessage());
			System.exit(1);
		}
		processor.setName("SEPA Processor");
		processor.start();

		// SPARQL protocol service
		int port = endpointProperties.getHttpPort();
		String portS = "";
		if (port != -1)
			portS = String.format(":%d", port);

		String queryMethod = "";
		switch (endpointProperties.getQueryMethod()) {
		case POST:
			queryMethod = " (Method: POST)";
			break;
		case GET:
			queryMethod = " (Method: GET)";
			break;
		case URL_ENCODED_POST:
			queryMethod = " (Method: URL ENCODED POST)";
			break;
		}

		String updateMethod = "";
		switch (endpointProperties.getUpdateMethod()) {
		case POST:
			updateMethod = " (Method: POST)";
			break;
		case GET:
			updateMethod = " (Method: GET)";
			break;
		case URL_ENCODED_POST:
			updateMethod = " (Method: URL ENCODED POST)";
			break;
		}

		System.out.println("SPARQL 1.1 endpoint");
		System.out.println("----------------------");
		System.out.println("SPARQL 1.1 Query     | http://" + endpointProperties.getHost() + portS
				+ endpointProperties.getQueryPath() + queryMethod);
		System.out.println("SPARQL 1.1 Update    | http://" + endpointProperties.getHost() + portS
				+ endpointProperties.getUpdatePath() + updateMethod);
		System.out.println("----------------------");
		System.out.println("");

		// Protocol gates
		System.out.println("SPARQL 1.1 Protocol (https://www.w3.org/TR/sparql11-protocol/)");
		System.out.println("----------------------");
		try {
			if (!properties.isSecure())
				httpGate = new HttpGate(properties, scheduler);
			else
				httpsGate = new HttpsGate(properties, scheduler, oauth);
		} catch (SEPAProtocolException e) {
			System.err.println(e.getMessage());
			System.exit(1);
		}

		// Protocol gates
		System.out.println("----------------------");
		System.out.println("");
		System.out.println("SPARQL 1.1 SE Protocol (https://wot.arces.unibo.it/TR/sparql11-se-protocol/)");
		System.out.println("----------------------");

		if (!properties.isSecure()) {
			wsServer = new WebsocketServer(properties.getWsPort(), properties.getSubscribePath(), scheduler,
					dependabilityMng);
			wsServer.start();
			synchronized (wsServer) {
				try {
					wsServer.wait(5000);
				} catch (InterruptedException e) {
					throw new SEPAProtocolException(e);
				}
			}
		} else {
			wssServer = new SecureWebsocketServer(properties.getWssPort(),
					properties.getSecurePath() + properties.getSubscribePath(), scheduler, oauth, dependabilityMng);

			wssServer.start();
			synchronized (wssServer) {
				try {
					wssServer.wait(5000);
				} catch (InterruptedException e) {
					throw new SEPAProtocolException(e);
				}
			}
		}

		System.out.println("----------------------");

		// Welcome message
		System.out.println("");
		System.out.println("*****************************************************************************************");
		System.out.println(
				"*                      SEPA Broker Ver " + version + " is up and running                          *");
		System.out.println("*                                Let Things Talk!                                       *");
		System.out.println("*****************************************************************************************");
	}

	public static void main(String[] args) throws SEPASecurityException, SEPAProtocolException {
		engine = new Engine(args);

		// Attach CTRL+C hook
		Runtime.getRuntime().addShutdownHook(new EngineShutdownHook(engine));
	}

	public void shutdown() {
		System.out.println("Stopping...");

		System.out.println("Stopping HTTP gate...");
		httpGate.shutdown();

		System.out.println("Stopping HTTPS gate...");
		httpsGate.shutdown();

		try {
			System.out.println("Stopping WS gate...");
			wsServer.stop(wsShutdownTimeout);
		} catch (InterruptedException e) {
			System.err.println(e.getMessage());
		}
		try {
			System.out.println("Stopping WSS gate...");
			wssServer.stop(wsShutdownTimeout);
		} catch (InterruptedException e) {
			System.err.println(e.getMessage());
		}

		System.out.println("Stopping Processor...");
		processor.interrupt();

		System.out.println("Stopped...bye bye :-)");
	}

	@Override
	public String getUpTime() {
		return EngineBeans.getUpTime();
	}

	@Override
	public String getURL_Query() {
		return EngineBeans.getQueryURL();
	}

	@Override
	public String getURL_Update() {
		return EngineBeans.getUpdateURL();
	}

	@Override
	public String getURL_SecureQuery() {
		return EngineBeans.getSecureQueryURL();
	}

	@Override
	public String getURL_SecureUpdate() {
		return EngineBeans.getSecureUpdateURL();
	}

	@Override
	public String getURL_Registration() {
		return EngineBeans.getRegistrationURL();
	}

	@Override
	public String getURL_TokenRequest() {
		return EngineBeans.getTokenRequestURL();
	}

	@Override
	public void resetAll() {
		EngineBeans.resetAll();
	}

	@Override
	public String getEndpoint_Host() {
		return ProcessorBeans.getEndpointHost();
	}

	@Override
	public String getEndpoint_Port() {
		return String.format("%d", ProcessorBeans.getEndpointPort());
	}

	@Override
	public String getEndpoint_QueryPath() {
		return ProcessorBeans.getEndpointQueryPath();
	}

	@Override
	public String getEndpoint_UpdatePath() {
		return ProcessorBeans.getEndpointUpdatePath();
	}

	@Override
	public String getEndpoint_UpdateMethod() {
		return ProcessorBeans.getEndpointUpdateMethod();
	}

	@Override
	public String getEndpoint_QueryMethod() {
		return ProcessorBeans.getEndpointQueryMethod();
	}

	@Override
	public String getVersion() {
		return EngineBeans.getVersion();
	}
}
