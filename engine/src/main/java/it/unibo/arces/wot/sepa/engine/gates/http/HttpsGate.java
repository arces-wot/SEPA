/* The main HTTP gate supporting the SPARQL 1.1 protocol over SSL
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

package it.unibo.arces.wot.sepa.engine.gates.http;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import org.apache.http.ExceptionLogger;
import org.apache.http.impl.nio.bootstrap.HttpServer;
import org.apache.http.impl.nio.bootstrap.ServerBootstrap;
import org.apache.http.impl.nio.reactor.IOReactorConfig;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import it.unibo.arces.wot.sepa.commons.exceptions.SEPAProtocolException;
import it.unibo.arces.wot.sepa.commons.exceptions.SEPASecurityException;
import it.unibo.arces.wot.sepa.engine.bean.EngineBeans;
import it.unibo.arces.wot.sepa.engine.core.EngineProperties;
import it.unibo.arces.wot.sepa.engine.dependability.Dependability;
import it.unibo.arces.wot.sepa.engine.protocol.wac.WebAccessControlHandler;
import it.unibo.arces.wot.sepa.engine.protocol.oauth.JWTRequestHandler;
import it.unibo.arces.wot.sepa.engine.protocol.oauth.RegisterHandler;
import it.unibo.arces.wot.sepa.engine.protocol.sparql11.SecureSPARQL11Handler;
import it.unibo.arces.wot.sepa.engine.scheduling.Scheduler;

public class HttpsGate {
	protected static final Logger logger = LogManager.getLogger();

	protected EngineProperties properties;
	protected Scheduler scheduler;

	protected String serverInfo = "SEPA Gate-HTTPS/1.1";
	protected HttpServer server = null;

	protected IOReactorConfig config = IOReactorConfig.custom().setTcpNoDelay(true).setSoReuseAddress(true).build();

	public HttpsGate(EngineProperties properties, Scheduler scheduler) throws SEPASecurityException, SEPAProtocolException {

		try {
			SecureSPARQL11Handler handler = new SecureSPARQL11Handler(scheduler,properties.getSecurePath() + properties.getQueryPath(),properties.getSecurePath() + properties.getUpdatePath());
			WebAccessControlHandler wacHandler = new WebAccessControlHandler(properties.getWacPath());
			
			server = ServerBootstrap.bootstrap().setListenerPort(properties.getHttpsPort()).setServerInfo(serverInfo)
					.setIOReactorConfig(config).setSslContext(Dependability.getSSLContext())
					.setExceptionLogger(ExceptionLogger.STD_ERR)
					.registerHandler(properties.getRegisterPath(), new RegisterHandler())
					.registerHandler(properties.getSecurePath() + properties.getQueryPath(),handler)
					.registerHandler(properties.getSecurePath() + properties.getUpdatePath(),handler)
					.registerHandler(properties.getTokenRequestPath(), new JWTRequestHandler())
					.registerHandler(properties.getWacPath(), wacHandler)
					.registerHandler("/echo", new EchoHandler())
					.registerHandler("", new EchoHandler()).create();
		} catch (IllegalArgumentException e) {
			throw new SEPASecurityException(e);
		}
		
		try {
			server.start();
		} catch (IOException e) {
			throw new SEPAProtocolException(e);
		}

		System.out.println("SPARQL 1.1 SE Query  | " + EngineBeans.getSecureQueryURL());
		System.out.println("SPARQL 1.1 SE Update | " + EngineBeans.getSecureUpdateURL());
		System.out.println("Client registration  | " + EngineBeans.getRegistrationURL());
		System.out.println("Token request        | " + EngineBeans.getTokenRequestURL());
		System.out.println("SOLID Wac            | " + EngineBeans.getWacURL());
	}
	
	public void shutdown() {
		server.shutdown(5, TimeUnit.SECONDS);
		
		try {
			server.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS);
		} catch (InterruptedException e) {
			logger.debug(serverInfo+" interrupted: " + e.getMessage());
		}
	}
}
