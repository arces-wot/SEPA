/* This class implements the processing of a SPARQL 1.1 UPDATE
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

import it.unibo.arces.wot.sepa.commons.protocol.SPARQL11Protocol;
import it.unibo.arces.wot.sepa.commons.request.UpdateRequest;
import it.unibo.arces.wot.sepa.commons.response.Response;
import it.unibo.arces.wot.sepa.engine.bean.ProcessorBeans;

public class UpdateProcessor {
	private SPARQL11Protocol endpoint;
	
	public UpdateProcessor(SPARQL11Protocol endpoint) {
		this.endpoint = endpoint;
	}

	public Response process(UpdateRequest req) {
		long start = System.currentTimeMillis();
		Response ret = endpoint.update(req);
		long stop = System.currentTimeMillis();

		ProcessorBeans.updateTimings(start, stop);
		
		return ret;
	}

	
}
