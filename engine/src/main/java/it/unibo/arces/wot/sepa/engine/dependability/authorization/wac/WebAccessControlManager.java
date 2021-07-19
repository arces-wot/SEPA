package it.unibo.arces.wot.sepa.engine.dependability.authorization.wac;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import org.apache.jena.sparql.vocabulary.FOAF;
import org.apache.jena.vocabulary.RDF;

import it.unibo.arces.wot.sepa.commons.exceptions.SEPASecurityException;
import it.unibo.arces.wot.sepa.commons.protocol.SPARQL11Properties.QueryHTTPMethod;
import it.unibo.arces.wot.sepa.commons.protocol.SPARQL11Protocol;
import it.unibo.arces.wot.sepa.commons.request.QueryRequest;
import it.unibo.arces.wot.sepa.commons.response.QueryResponse;
import it.unibo.arces.wot.sepa.commons.sparql.Bindings;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.rdf.model.ResIterator;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.Selector;
import org.apache.jena.rdf.model.SimpleSelector;
import org.apache.jena.rdf.model.Statement;
import org.apache.jena.rdf.model.StmtIterator;

public class WebAccessControlManager {
	// http://solid.github.io/web-access-control-spec/

	/**
	 * Main method to check the permission granted to an agent for the requested
	 * resource. Return a PermissionSet, where for every type of permission it is
	 * stated if it is granted or not.
	 * 
	 * @param identifiers URI of the resource the agent is asking for
	 * @param permissions permission that the agent are requesting to the resource
	 * @param credentials credentials of the agent (WebID)
	 * @return PermissionSet that describe the permissions for the requested
	 *         resource
	 */
	public PermissionsBean handle(String identifiers, String credentials) {
		Model acl = this.getAclRecursive(identifiers, false);
		PermissionsBean allowedModes = this.createAuthorization(credentials, acl);
		return allowedModes;
	}

	/**
	 * Determines the available permissions for the given credentials and acl.
	 * 
	 * @param credentials credential of the agent requesting the resource
	 * @param acl         triples relevant for authorization
	 */
	private PermissionsBean createAuthorization(String credentials, Model acl) {
		PermissionsBean permissions = new PermissionsBean(false, false, false, false);

		List<Resource> ruleList = this.filterRules(acl, credentials);

		String ACL = "http://www.w3.org/ns/auth/acl#";

		if (this.hasPermission(acl, ACL + "Read", credentials, ruleList)) {
			permissions.setRead(true);
		}

		if (this.hasPermission(acl, ACL + "Write", credentials, ruleList)) {
			permissions.setWrite(true);
		}

		if (this.hasPermission(acl, ACL + "Append", credentials, ruleList)) {
			permissions.setAppend(true);
		}

		if (this.hasPermission(acl, ACL + "Control", credentials, ruleList)) {
			permissions.setControl(true);
		}

		return permissions;
	}

	private List<Resource> filterRules(Model acl, String credentials) {
		List<Resource> filteredRes = new ArrayList<>();

		Resource res = acl.getResource("http://www.w3.org/ns/auth/acl#Authorization");
		ResIterator iter = acl.listResourcesWithProperty(RDF.type, res);

		// TODO: we should filter out every rule which does not comply with
		// https://solid.github.io/web-access-control-spec/#authorization-conformance

		while (iter.hasNext()) {
			Resource authRule = iter.nextResource();

			if (this.applyFilters(credentials, acl, authRule)) {
				filteredRes.add(authRule);
			}
		}

		return filteredRes;
	}

	private boolean applyFilters(String credentials, Model acl, Resource authRule) {
		String ACL = "http://www.w3.org/ns/auth/acl#";
		Property aclAgent = acl.createProperty(ACL + "agent");
		Property aclAgentClass = acl.createProperty(ACL + "agentClass");
		Resource aclAuthenticatedAgent = acl.createResource(ACL + "AuthenticatedAgent");

		if (acl.contains(authRule, aclAgentClass, FOAF.Agent)) {
			return true;
		}

		boolean isAuthenticated = credentials != null && !credentials.isEmpty();

		if (isAuthenticated) {
			if (acl.contains(authRule, aclAgentClass, aclAuthenticatedAgent)) {
				return true;
			}

			Resource agentWebId = acl.createResource(credentials);
			if (acl.contains(authRule, aclAgent, agentWebId)) {
				return true;
			}

			// TODO: handle groups!
		}

		return false;
	}

	/**
	 * Checks if the given agent has permission to execute the given mode based on
	 * the triples in the ACL.
	 * 
	 * @param credentials agent who want the access
	 * @param acl         triples relevant for authorization
	 * @param mode        requested mode
	 */
	private boolean hasPermission(Model acl, String mode, String credentials, List<Resource> ruleList) {
		Resource modeRes = acl.getResource(mode);
		Property aclMode = acl.getProperty("http://www.w3.org/ns/auth/acl#mode");

		for (Resource authRule : ruleList) {
			if (acl.contains(authRule, aclMode, modeRes)) {
				return true;
			}
		}

		return false;
	}

	private String getAuxiliaryIdentifier(String resIdentifier) {
		return resIdentifier + ".acl";
	}

	private boolean isRootContainer(String resIdentifier) {
		// TODO: baseURL needs to be configurable, maybe it could be sent
		// directly by the SOLID server inside the request body!
		final String baseURL = this.ensureTrailingSlash("http://localhost:3000/");
		return this.ensureTrailingSlash(resIdentifier).equals(baseURL);
	}

	private String ensureTrailingSlash(String str) {
		// First, remove every trailing slash:
		while (str.charAt(str.length()) == '/') {
			str.substring(0, str.length());
		}
		// Then, add a single slash:
		str += "/";
		
		return str;
	}
	
	private URI getParentContainerFromURI(URI uri) {
		return uri.getPath().endsWith("/") ? uri.resolve("..") : uri.resolve(".");
	}
	
	private String getParentContainer(String id) {
		if (this.isRootContainer(id)) {
			return null;
		}
		
		// Trailing slash is necessary for URI library
		String uriWithTrailingSlash = this.ensureTrailingSlash(id);
	    try {
	    	URI uri = new URI(uriWithTrailingSlash);
	    	return this.getParentContainerFromURI(uri).toURL().getRef();
		} catch (URISyntaxException | MalformedURLException e) {
			e.printStackTrace();
			return null;
		}
	}

	private Model getResourceFromTriplestore(String resIdentifier) throws SEPASecurityException, IOException {
//		request = new QueryRequest(properties.getQueryMethod(), properties.getProtocolScheme(),
//				properties.getHost(), properties.getPort(), properties.getQueryPath(),
//				req.getSparql(), req.getDefaultGraphUri(), req.getNamedGraphUri(),
//				req.getBasicAuthorizationHeader(),req.getInternetMediaType(),QueryProcessorBeans.getTimeout(),0);
		
		QueryRequest request = new QueryRequest(QueryHTTPMethod.GET,
				"http", "localhost", 9999, "/blazegraph/sparql",
				"SELECT ?s ?p ?o WHERE { GRAPH <" + resIdentifier + "> {?s ?p ?o}}",
				null, null,	"JSON", 5000, 0);

		SPARQL11Protocol endpoint = new SPARQL11Protocol();
		QueryResponse ret = (QueryResponse) endpoint.query(request);
		endpoint.close();
		
		List<Bindings> bindings = ret.getBindingsResults().getBindings();
		if (bindings.size() <= 0) {
			return null;
		}
		
		Model data = ModelFactory.createDefaultModel();
		List<Statement> stmts = new ArrayList<>();

		for (Bindings b : bindings) {
			Resource s = data.createResource(b.getValue("s"));
			Property p = data.createProperty(b.getValue("p"));
			Resource o = data.createResource(b.getValue("o"));
			
			stmts.add(data.createStatement(s, p, o));
		}
		
		data.add(stmts);
		
		return data;
	}
	/**
	 * Returns the ACL triples that are relevant for the given identifier. These can
	 * either be from a corresponding ACL document or an ACL document higher up with
	 * defaults.
	 * 
	 * @param id      The resource identifiers of which we need the ACL triples.
	 * @param recurse Only used internally for recursion.
	 */
	private Model getAclRecursive(String id, boolean recurse) {

		// Obtain the direct ACL document for the resource, if it exists
		String aclIdentifier;
		try {
			aclIdentifier = this.getAuxiliaryIdentifier(id);
			Model data = this.getResourceFromTriplestore(aclIdentifier);
			if (data != null) {
				return this.filterData(data, recurse, id);
			}
		} catch (RuntimeException | SEPASecurityException | IOException e) {
			e.printStackTrace();
		}

		// Obtain the applicable ACL of the parent container
		String parent = this.getParentContainer(id);
		if (this.isRootContainer(id) || parent == null) {
			// Solid, §10.1: "In the event that a server can’t apply an ACL to a resource,
			// it MUST deny access."
			// https://solid.github.io/specification/protocol#web-access-control
			throw new RuntimeException("ACL file not found");
		} else {
			return this.getAclRecursive(parent, true);
		}
	}

	private Model filterData(Model data, boolean recurse, String object) {
		String ACL = "http://www.w3.org/ns/auth/acl#";

		Model filteredData = ModelFactory.createDefaultModel();

		Resource resIdentifier = filteredData.getResource(object);
		Property predicate;
		if (recurse) {
			predicate = filteredData.getProperty(ACL + "default");
		} else {
			predicate = filteredData.getProperty(ACL + "accessTo");
		}

		ResIterator iter = data.listResourcesWithProperty(predicate, resIdentifier);
		while (iter.hasNext()) {
			Resource rule = iter.next();
			
			Selector stmtSelector = new SimpleSelector(rule, (Property) null, (RDFNode) null);
			StmtIterator ruleStatements = data.listStatements(stmtSelector);
			while (ruleStatements.hasNext()) {
				filteredData.add(ruleStatements.next());
			}
		}

		return filteredData;
	}

}
