/* Class for processing SPARQL 1.1 subscribe requests
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

package it.unibo.arces.wot.sepa.engine.processing;

import it.unibo.arces.wot.sepa.commons.response.Response;
import it.unibo.arces.wot.sepa.engine.scheduling.InternalSubscribeRequest;
import it.unibo.arces.wot.sepa.engine.scheduling.ScheduledRequest;
import it.unibo.arces.wot.sepa.logging.Logging;

class SubscribeProcessingThread extends Thread {
	private final Processor processor;

	public SubscribeProcessingThread(Processor processor) {
		this.processor = processor;

		setName("SEPA-Subscribe-Processor");
	}
	
	public void run() {
		while (processor.isRunning()) {
			try {
				// Wait request...
				ScheduledRequest request = processor.waitSubscribeRequest();
				Logging.logger.debug(">> " + request);

				// Process request
				Response response = processor.processSubscribe((InternalSubscribeRequest) request.getRequest());
				
				Logging.logger.debug("<< " + response);

				// Send back response
				processor.addResponse(request.getToken(), response);

			} catch (InterruptedException e) {
				Logging.logger.warn("Exit");
				return;
			}
		}
	}
}
