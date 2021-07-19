package it.unibo.arces.wot.sepa.engine.dependability.authorization.wac;

import java.io.IOException;
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
	// TODO: implement WAC
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
	 * Checks if the authorization grants the agent permission to use the given
	 * mode.
	 * 
	 * @param permissions  permissions that the agent is requesting
	 * @param allowedModes permission that are granted (taken from the acl of the
	 *                     resource)
	 */
//	private void checkPermissions(PermissionSet permissions, PermissionSet allowedModes) {
//		for(String mode : permissions.getTruthyPermissions()) {
//			if(allowedModes.getPermissions().get(mode) == false) {
//				System.err.println("WAC error! Requested mode [" + mode + "] is not allowed.");
//			}
//		}
//	}

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

		boolean isAuthenticated = credentials != null;

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
		return resIdentifier.equals("http://localhost:3000/");
	}

	private String getParentContainer(String id) {
		return id.substring(0, id.lastIndexOf("/")+1);
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
		
		Model data = ModelFactory.createDefaultModel();
		List<Statement> stmts = new ArrayList<>();
		
		for (Bindings b : ret.getBindingsResults().getBindings()) {
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
//		String ACL = "http://www.w3.org/ns/auth/acl#";
//		// String FOAF = "http://xmlns.com/foaf/0.1/";
//		String aclPrefix = "http://localhost:3000/resource.ttl.acl";
//
//		Model model = ModelFactory.createDefaultModel();
//
//		Resource aclAuthorization = model.createResource(ACL + "Authorization");
//		Resource aclRead = model.createResource(ACL + "Read");
//		Resource aclWrite = model.createResource(ACL + "Write");
//		Resource aclAppend = model.createResource(ACL + "Append");
//		Resource aclControl = model.createResource(ACL + "Control");
//		Property aclAgent = model.createProperty(ACL + "agent");
//		Property aclAgentClass = model.createProperty(ACL + "agentClass");
//		Property aclAgentGroup = model.createProperty(ACL + "agentGroup");
//		Property aclAccessTo = model.createProperty(ACL + "accessTo");
//		Property aclMode = model.createProperty(ACL + "mode");
//
//		Resource userTestAgent = model.createResource("http://localhost:3000/user_test#me");
//		Resource testGroup = model.createResource("http://localhost:3000/test_group#test");
//		Resource resource = model.createResource("http://localhost:3000/resource.ttl");
//
//		model.createResource(aclPrefix + "#auth1").addProperty(RDF.type, aclAuthorization)
//				.addProperty(aclAgent, userTestAgent).addProperty(aclMode, aclRead).addProperty(aclMode, aclWrite)
//				.addProperty(aclMode, aclAppend).addProperty(aclMode, aclControl).addProperty(aclAccessTo, resource);
//
//		model.createResource(aclPrefix + "#auth2").addProperty(RDF.type, aclAuthorization)
//				.addProperty(aclAgentGroup, testGroup).addProperty(aclMode, aclRead).addProperty(aclMode, aclWrite)
//				.addProperty(aclAccessTo, resource);
//
//		model.createResource(aclPrefix + "#auth3").addProperty(RDF.type, aclAuthorization)
//				.addProperty(aclAgentClass, FOAF.Agent).addProperty(aclMode, aclRead)
//				.addProperty(aclAccessTo, resource);
//
//		return model;

		/*
		 * 1. Use the document's own ACL resource if it exists (in which case, stop
		 * here). 2. Otherwise, look for authorizations to inherit from the ACL of the
		 * document's container. If those are found, stop here. 3. Failing that, check
		 * the container's parent container to see if that has its own ACL file, and see
		 * if there are any permissions to inherit. 4. Failing that, move up the
		 * container hierarchy until you find a container with an existing ACL file,
		 * which has some permissions to inherit. 5. The root container of a user's
		 * account MUST have an ACL resource specified. (If all else fails, the search
		 * stops there.)
		 */

		// Obtain the direct ACL document for the resource, if it exists
		String aclIdentifier;
		try {
			aclIdentifier = this.getAuxiliaryIdentifier(id);
			Model data = this.getResourceFromTriplestore(aclIdentifier);
			return this.filterData(data, recurse, id);
		} catch (RuntimeException | SEPASecurityException | IOException e) {
			e.printStackTrace();
		}

		// Obtain the applicable ACL of the parent container
		if (this.isRootContainer(id)) {
			// Solid, §10.1: "In the event that a server can’t apply an ACL to a resource,
			// it MUST deny access."
			// https://solid.github.io/specification/protocol#web-access-control
			throw new RuntimeException("ACL file not found");
		}
		String parent = this.getParentContainer(id);
		return this.getAclRecursive(parent, true);
	}

	private Model filterData(Model data, boolean recurse, String object) {
		String ACL = "http://www.w3.org/ns/auth/acl#";

		Model filteredData = ModelFactory.createDefaultModel();

		Resource aclIdentifier = filteredData.getResource(object);
		Property predicate;
		if (recurse) {
			predicate = filteredData.getProperty(ACL + "default");
		} else {
			predicate = filteredData.getProperty(ACL + "accessTo");
		}

		ResIterator iter = data.listResourcesWithProperty(predicate, aclIdentifier);
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
