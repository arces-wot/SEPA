/* The engine internal representation of a query request
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

package it.unibo.arces.wot.sepa.engine.scheduling;

import java.util.Set;

import it.unibo.arces.wot.sepa.commons.exceptions.SEPASparqlParsingException;
import it.unibo.arces.wot.sepa.commons.security.ClientAuthorization;

public class InternalQueryRequest extends InternalUQRequest {
	private String internetMediaType = "application/sparql-results+json";

	public InternalQueryRequest(String sparql, Set<String> defaultGraphUri, Set<String> namedGraphUri) throws SEPASparqlParsingException {
		super(sparql, defaultGraphUri, namedGraphUri);
	}

	public InternalQueryRequest(String sparql, Set<String> defaultGraphUri, Set<String> namedGraphUri,
			ClientAuthorization auth, String mediaType) throws SEPASparqlParsingException {
		this(sparql, defaultGraphUri, namedGraphUri);

		internetMediaType = mediaType;
	}

	public String getInternetMediaType() {
		return internetMediaType;
	}

	@Override
	public String toString() {
		return "*QUERY* RDF DATA SET: {" + rdfDataSet + " USING GRAPHS: " + defaultGraphUri + " NAMED GRAPHS: "
				+ namedGraphUri + "} SPARQL: " + sparql;
	}

	@Override
	protected Set<String> getGraphURIs(String sparql) throws SEPASparqlParsingException {
		return JenaSparqlParsing.getQueryGraphURIs(sparql);
	}
}
