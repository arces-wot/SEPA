/* This class implements the configuration properties of the Semantic Event Processing Architecture (SEPA) Engine
 * 
 * Authors:	Luca Roffia (luca.roffia@unibo.it)
 * 			Andrea Bisacchi (andrea.bisacchi5@studio.unibo.it)

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

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.gson.Gson;

import it.unibo.arces.wot.sepa.commons.exceptions.SEPAPropertiesException;

/**
 * <pre>
{
	"parameters": {
		"scheduler": {
			"queueSize": 100,
			"timeout": 3000
		},
		"processor": {
			"updateTimeout": 5000,
			"queryTimeout": 5000,
			"maxConcurrentRequests": 5
		},
		"spu": {
			"timeout": 2000
		},
		"gates": {
			"security": {
				"enabled" : true,
				"type" : "local|ldap|keycloak",
				"tls" : false
			},
			"ports": {
				"http": 8000,
				"ws": 9000,
				"https": 8443,
				"wss": 9443
			},
			"paths": {
				"update": "/update",
				"query": "/query",
				"subscribe": "/subscribe",
				"register": "/oauth/register",
				"tokenRequest": "/oauth/token",
				"securePath": "/secure",
				"wacPath": "/wac"
			}
		}
	}
}
 * </pre>
 */
public class EngineProperties {
	private static final transient Logger logger = LogManager.getLogger();

	private static final transient String defaultsFileName = "engine.jpar";

	private Parameters parameters = new Parameters();

	private EngineProperties() {}

	public static EngineProperties load(String propertiesFile, boolean secure) throws SEPAPropertiesException {
		EngineProperties result = EngineProperties.load(propertiesFile);
		result.parameters.gates.security.enabled = secure;
		return result;
	}

	public static EngineProperties load(String propertiesFile) throws SEPAPropertiesException {
		if (propertiesFile == null) {
			throw new SEPAPropertiesException(new IllegalArgumentException("Properties file is null"));
		}

		EngineProperties result;
		Gson gson = new Gson();

		try {
			result = gson.fromJson(new FileReader(propertiesFile), EngineProperties.class);
		} catch (Exception e) {
			logger.warn(e.getMessage());
			result = defaults();
			try {
				result.storeProperties(defaultsFileName);
			} catch (IOException e1) {
				logger.error(e1.getMessage());
				throw new SEPAPropertiesException(e1);
			}
			logger.warn("USING DEFAULTS. Edit \"" + defaultsFileName + "\" (if needed) and run again the broker");
		}
		return result;
	}

	public static void store(EngineProperties properties, String propertiesFile) throws IOException {
		properties.storeProperties(propertiesFile);
	}

	public String toString() {
		return new Gson().toJson(this);
	}


	protected static EngineProperties defaults() {
		EngineProperties result = new EngineProperties();

		// Scheduler
		result.parameters.scheduler.queueSize = 100;
		result.parameters.scheduler.timeout = 5000;

		// Processor
		result.parameters.processor.updateTimeout = 5000;
		result.parameters.processor.queryTimeout = 5000;
		result.parameters.processor.maxConcurrentRequests = 5;
		result.parameters.processor.reliableUpdate = true;

		// SPU
		result.parameters.spu.timeout = 5000;

		// Gates
		result.parameters.gates.security.enabled = false;
		result.parameters.gates.security.type = "local";
		result.parameters.gates.security.tls = false;
		
		// Gates -> Ports
		result.parameters.gates.ports.http = 8000;
		result.parameters.gates.ports.https = 8443;
		result.parameters.gates.ports.ws = 9000;
		result.parameters.gates.ports.wss = 9443;

		// Gates -> Paths
		result.parameters.gates.paths.secure = "/secure";
		result.parameters.gates.paths.update = "/update";
		result.parameters.gates.paths.query = "/query";
		result.parameters.gates.paths.subscribe = "/subscribe";
		result.parameters.gates.paths.unsubscribe = "/unsubscribe";
		result.parameters.gates.paths.register = "/oauth/register";
		result.parameters.gates.paths.tokenRequest = "/oauth/token";
		result.parameters.gates.paths.wac = "/wac";
		return result;
	}

	private void storeProperties(String propertiesFile) throws IOException {
		FileWriter out = new FileWriter(propertiesFile);
		out.write(this.toString());
		out.close();
	}

	public boolean isSecure() {
		return this.parameters.gates.security.enabled;
	}
	
	public boolean isTls() {
		return this.parameters.gates.security.tls;
	}
	
	public boolean isLDAPEnabled() {
		return this.parameters.gates.security.type.equals("ldap");
	}
	
	public boolean isLocalEnabled() {
		return this.parameters.gates.security.type.equals("local");
	}
	
	public boolean isKeycloakEnabled() {
		return this.parameters.gates.security.type.equals("keycloak");
	}
	
	public int getMaxConcurrentRequests() {
		return this.parameters.processor.maxConcurrentRequests;
	}

	public int getUpdateTimeout() {
		return this.parameters.processor.updateTimeout;
	}

	public int getQueryTimeout() {
		return this.parameters.processor.queryTimeout;
	}

	public int getSchedulingQueueSize() {
		return this.parameters.scheduler.queueSize;
	}

	public int getWsPort() {
		return this.parameters.gates.ports.ws;
	}

	public int getHttpPort() {
		return this.parameters.gates.ports.http;
	}

	public int getHttpsPort() {
		return this.parameters.gates.ports.https;
	}

	public int getWssPort() {
		return this.parameters.gates.ports.wss;
	}

	public String getUpdatePath() {
		return this.parameters.gates.paths.update;
	}

	public String getSubscribePath() {
		return this.parameters.gates.paths.subscribe;
	}

	public String getUnsubscribePath() {
		return this.parameters.gates.paths.unsubscribe;
	}

	public String getQueryPath() {
		return this.parameters.gates.paths.query;
	}

	public String getRegisterPath() {
		return this.parameters.gates.paths.register;
	}

	public String getTokenRequestPath() {
		return this.parameters.gates.paths.tokenRequest;
	}

	public String getSecurePath() {
		return this.parameters.gates.paths.secure;
	}

	public String getWacPath() {
		return this.parameters.gates.paths.wac;
	}
	
	public int getSPUProcessingTimeout() {
		return this.parameters.spu.timeout;
	}

	public boolean isUpdateReliable() {
		return this.parameters.processor.reliableUpdate;
	}

	public int getSchedulerTimeout() {
		return this.parameters.scheduler.timeout;
	}
	
	static private class Parameters {
		public Scheduler scheduler = new Scheduler();
		public Processor processor = new Processor();
		public Spu spu = new Spu();
		public Gates gates = new Gates();
	}

	static private class Scheduler {
		public int queueSize;
		public int timeout;

		public Scheduler(){
			queueSize = 100;
			timeout = 5000;
		}
	}

	static private class Processor {
		public int updateTimeout;
		public int queryTimeout;
		public int maxConcurrentRequests;
		public boolean reliableUpdate;

		public Processor(){
			reliableUpdate = true;
			updateTimeout = 5000;
			queryTimeout = 5000;
			maxConcurrentRequests = 5;
		}
	}

	static private class Spu {
		public int timeout;

		public Spu(){
			timeout = 5000;
		}
	}
	
	static private class Security {
		public boolean tls;
		public boolean enabled;
		public String type;
		
		public Security(){
			enabled = false;
			type = "local";
			tls = false;
		}
	}

	static private class Gates {
		public Security security = new Security();
		public Paths paths = new Paths();
		public Ports ports = new Ports();
	}

	static private class Paths {
		public String secure;
		public String update;
		public String query;
		public String subscribe;
		public String unsubscribe;
		public String register;
		public String tokenRequest;
		public String wac;

		public Paths(){
			secure       = "/secure";
			update       = "/update";
			query        = "/query";
			subscribe    = "/subscribe";
			unsubscribe  = "/unsubscribe";
			register     = "/oauth/register";
			tokenRequest = "/oauth/token";
			wac          = "/wac";
		}
	}

	static private class Ports {
		public int http;
		public int https;
		public int ws;
		public int wss;

		public Ports(){
			http  = 8000;
			https = 8443;
			ws    = 9000;
			wss   = 9443;
		}
	}
	
}
