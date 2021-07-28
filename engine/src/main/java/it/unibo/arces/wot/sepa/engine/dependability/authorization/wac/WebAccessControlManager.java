package it.unibo.arces.wot.sepa.engine.dependability.authorization.wac;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.jena.sparql.vocabulary.FOAF;
import org.apache.jena.vocabulary.RDF;

import it.unibo.arces.wot.sepa.commons.exceptions.SEPASecurityException;
import it.unibo.arces.wot.sepa.commons.protocol.SPARQL11Protocol;
import it.unibo.arces.wot.sepa.commons.request.QueryRequest;
import it.unibo.arces.wot.sepa.commons.response.QueryResponse;
import it.unibo.arces.wot.sepa.commons.sparql.Bindings;
import it.unibo.arces.wot.sepa.engine.bean.ProcessorBeans;
import it.unibo.arces.wot.sepa.engine.bean.QueryProcessorBeans;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.NodeIterator;
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

	protected final String ACL = "http://www.w3.org/ns/auth/acl#";
	protected final String VCARD = "http://www.w3.org/2006/vcard/ns#";

	/**
	 * Main method to get the permissions granted to an agent for the requested
	 * resource. Return a PermissionsBean, where for every type of permission it is
	 * stated if it is granted or not.
	 * 
	 * @param rootId      URI of the root resource
	 * @param resourceId  URI of the resource the agent is asking for
	 * @param credentials credentials of the agent (WebID)
	 * @return a PermissionsBean instance that describes the permissions for the
	 *         requested resource and the given agent
	 */
	public PermissionsBean handle(String rootId, String resourceId, String credentials) {
		String baseURL = this.ensureTrailingSlash(rootId);

		Model acl = this.getAclGraph(resourceId, baseURL);
		return this.getAuthorizations(acl, credentials);
	}

	/**
	 * Determines the available permissions for the given credentials and ACL
	 * resource.
	 * 
	 * @param acl         the content of the relevant ACL resource
	 * @param credentials credentials of the agent requesting the resource
	 * @return a PermissionsBean instance that describes the permissions for the
	 *         requested resource and the given agent
	 */
	private PermissionsBean getAuthorizations(Model acl, String credentials) {
		PermissionsBean permissions = new PermissionsBean(false, false, false, false);

		List<Resource> ruleList = this.filterRules(acl, credentials);

		if (this.hasPermission(acl, ruleList, credentials, ACL + "Read")) {
			permissions.setRead(true);
		}

		if (this.hasPermission(acl, ruleList, credentials, ACL + "Write")) {
			permissions.setWrite(true);
		}

		if (this.hasPermission(acl, ruleList, credentials, ACL + "Append")) {
			permissions.setAppend(true);
		}

		if (this.hasPermission(acl, ruleList, credentials, ACL + "Control")) {
			permissions.setControl(true);
		}

		return permissions;
	}

	private List<Resource> filterRules(Model acl, String credentials) {
		List<Resource> filteredRes = new ArrayList<>();

		Resource res = acl.getResource(ACL + "Authorization");
		ResIterator iter = acl.listResourcesWithProperty(RDF.type, res);

		// TODO: we should filter out every rule which does not comply with
		// https://solid.github.io/web-access-control-spec/#authorization-conformance

		while (iter.hasNext()) {
			Resource authRule = iter.nextResource();

			if (this.applyFilters(acl, credentials, authRule)) {
				filteredRes.add(authRule);
			}
		}

		return filteredRes;
	}

	private boolean applyFilters(Model acl, String credentials, Resource authRule) {
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

			if (this.checkGroup(acl, authRule, credentials)) {
				return true;
			}

			// Add TRUSTED_APPS!!!
		}

		return false;
	}

	private boolean checkGroup(Model acl, Resource authRule, String credentials) {
		Property aclAgentGroup = acl.createProperty(ACL + "agentGroup");
		NodeIterator iter = acl.listObjectsOfProperty(authRule, aclAgentGroup);
		while (iter.hasNext()) {
			RDFNode group = iter.next();

			if (this.isMemberOfGroup(acl, group.asResource(), credentials)) {
				return true;
			}
		}

		return false;
	}

	private boolean isMemberOfGroup(Model acl, Resource group, String credentials) {
		String groupUri = group.toString();
		String groupResourceId = groupUri.split("#")[0];

		try {
			Model groupData = this.getResourceFromTriplestore(groupResourceId);

			Property vcardHasMember = groupData.createProperty(VCARD + "hasMember");
			Resource agent = groupData.createResource(credentials);
			
			return groupData.contains(group, vcardHasMember, agent);
		} catch (SEPASecurityException | IOException e) {
			e.printStackTrace();
			return false;
		}
	}

	/**
	 * Checks if the given agent has permission to execute the given mode based on
	 * the triples in the ACL.
	 * 
	 * @param acl         triples relevant for authorization
	 * @param ruleList    list of relevant rule URIs
	 * @param credentials agent who want the access
	 * @param mode        requested mode
	 * @return true if there's at least a rule that authorizes the agent to access
	 *         the required resource with the required mode
	 */
	private boolean hasPermission(Model acl, List<Resource> ruleList, String credentials, String mode) {
		Resource modeRes = acl.getResource(mode);
		Property aclMode = acl.getProperty(ACL + "mode");

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

	private boolean isRootContainer(String resIdentifier, String rootId) {
		return this.ensureTrailingSlash(resIdentifier).equals(rootId);
	}

	private String ensureTrailingSlash(String str) {
		// First, remove every trailing slash:
		while (str.charAt(str.length() - 1) == '/') {
			str = str.substring(0, str.length() - 1);
		}
		// Then, add a single slash:
		str += "/";

		return str;
	}

	private URI getParentContainerFromURI(URI uri) {
		return uri.getPath().endsWith("/") ? uri.resolve("..") : uri.resolve(".");
	}

	private String getParentContainer(String resourceId, String rootId) throws URISyntaxException {
		// Trailing slash is necessary for URI library
		String uriWithTrailingSlash = this.ensureTrailingSlash(resourceId);
		URI uri = new URI(uriWithTrailingSlash);
		URI parentUri = this.getParentContainerFromURI(uri);
		return parentUri.toString();
	}

	private Model getResourceFromTriplestore(String resIdentifier) throws SEPASecurityException, IOException {
		String query = "SELECT ?s ?p ?o WHERE { GRAPH <" + resIdentifier + "> {?s ?p ?o}}";
		Set<String> emptyGraphsSet = new HashSet<>();

		QueryRequest request = new QueryRequest(ProcessorBeans.getEndpointQueryMethod(),
				ProcessorBeans.getEndpointProtocolScheme(), ProcessorBeans.getEndpointHost(),
				ProcessorBeans.getEndpointPort(), ProcessorBeans.getEndpointQueryPath(), query, emptyGraphsSet,
				emptyGraphsSet, "", "application/json", QueryProcessorBeans.getTimeout(), QueryProcessorBeans.getTimeoutNRetry());

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
	 * @param resourceId the identifier of the resource of which we need the
	 *                   associated ACL resource
	 * @param rootId     the root resource identifier
	 * @return the content of the ACL resource associated to the given resource
	 */
	private Model getAclGraph(String resourceId, String rootId) {
		Model aclGraph = null;

		String currentResourceId = resourceId;
		boolean directACL = true;
		boolean found = false;

		while (!found) {
			String aclIdentifier = this.getAuxiliaryIdentifier(currentResourceId);

			try {
				aclGraph = this.getResourceFromTriplestore(aclIdentifier);
			} catch (SEPASecurityException | IOException e) {
				e.printStackTrace();
				aclGraph = null;
			}

			if (aclGraph != null) {
				found = true; // this forces to while-loop to stop
				aclGraph = this.filterData(aclGraph, directACL, resourceId);
			} else {
				directACL = false;
				found = false;

				if (this.isRootContainer(currentResourceId, rootId)) {
					return null;
				}

				try {
					currentResourceId = this.getParentContainer(currentResourceId, rootId);
				} catch (URISyntaxException e) {
					e.printStackTrace();
					return null;
				}
			}
		}

		return aclGraph;
	}

	private Model filterData(Model data, boolean directACL, String object) {
		Model filteredData = ModelFactory.createDefaultModel();

		Resource resIdentifier = filteredData.getResource(object);
		Property predicate;
		if (directACL) {
			predicate = filteredData.getProperty(ACL + "accessTo");
		} else {
			predicate = filteredData.getProperty(ACL + "default");
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
