/* The engine internal abstract representation of a update or query request
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

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import it.unibo.arces.wot.sepa.commons.exceptions.SEPASparqlParsingException;
import it.unibo.arces.wot.sepa.commons.security.ClientAuthorization;

/**
 * An internal request has been validated and graph URIs are extracted.
 * 
 * Functions are also evaluated (e.g., now())
 * */
public abstract class InternalUQRequest extends InternalRequest {
	protected final Logger logger = LogManager.getLogger();
	
	protected String sparql;
	
	protected Set<String> defaultGraphUri = new HashSet<String>();
	protected Set<String> namedGraphUri = new HashSet<String>();
	protected Set<String> rdfDataSet = new HashSet<String>();
	
	public InternalUQRequest(String sparql,Set<String> defaultGraphUri,Set<String> namedGraphUri) throws SEPASparqlParsingException {
		super();
		if (sparql == null) throw new IllegalArgumentException("SPARQL is null");
		
		this.sparql = evaluateFunctions(sparql);
		
		rdfDataSet = getGraphURIs(sparql);
		logger.debug("getGraphURIs: "+rdfDataSet);
		
		if (defaultGraphUri != null) this.defaultGraphUri = defaultGraphUri;
		if (namedGraphUri != null) this.namedGraphUri = namedGraphUri;
		
		//if(!this.defaultGraphUri.isEmpty() && !rdfDataSet.isEmpty()) throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,"using-graph-uri conflicts with USING, USING NAMED or WITH");
		//if(!this.namedGraphUri.isEmpty() && !rdfDataSet.isEmpty()) throw new SPARQL11ProtocolException(HttpStatus.SC_BAD_REQUEST,"using-named-graph-uri conflicts with USING, USING NAMED or WITH");
	
		rdfDataSet.addAll(this.defaultGraphUri);
		rdfDataSet.addAll(this.namedGraphUri);
		
		logger.debug("RDF DATASET: "+ rdfDataSet);
	}
	
	protected abstract Set<String> getGraphURIs(String sparql) throws SEPASparqlParsingException;
	
	public String getSparql() {
		return sparql;
	}
	
	public Set<String> getDefaultGraphUri() {
		return defaultGraphUri;
	}
	
	public Set<String> getNamedGraphUri() {
		return namedGraphUri;
	}
	
	public Set<String> getRdfDataSet() {
		return rdfDataSet;
	}
	
	@Override
	public int hashCode() {
		return sparql.hashCode();
	}
	
	@Override
	public boolean equals(Object obj) {
		return sparql.equals(((InternalUQRequest)obj).sparql);
	}
	
	/* Override the SPARQL now() function to return the current UTC time as xsd:dateTimeStamp
	 
	 https://www.w3.org/TR/sparql11-query/#func-now
	 
	 17.4.5.1 now
 		
 		xsd:dateTime  NOW ()

		Returns an XSD dateTime value for the current query execution. 
		All calls to this function in any one query execution must return the same value. 
		The exact moment returned is not specified.

		now()	"2011-01-10T14:45:13.815-05:00"^^xsd:dateTime
		
	https://www.w3.org/TR/xmlschema11-2/#dateTime
	
	3.3.7 dateTime

		dateTime represents instants of time, optionally marked with a particular time zone offset.  
		
		Values representing the same instant but having different time zone offsets are equal but not identical.

	https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp

	3.4.28 dateTimeStamp
		[Definition:]   The dateTimeStamp datatype is ·derived· from dateTime by giving the value required to its explicitTimezone facet. 
		The result is that all values of dateTimeStamp are required to have explicit time zone offsets and the datatype is totally ordered.

	 * */
	private String evaluateFunctions(String sparql) {
		OffsetDateTime utc = OffsetDateTime.now(ZoneOffset.UTC);
		String timestamp = "'" + utc.toString() + "'^^xsd:dateTimeStamp";
		
		String temp = sparql.replace("now()", timestamp);
		
		return temp;		
	}
}
