package it.unibo.arces.wot.sepa.engine.dependability.authorization;


import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.jena.sparql.lang.SPARQLParser;

import com.google.gson.JsonObject;
import com.nimbusds.jwt.SignedJWT;

import it.unibo.arces.wot.sepa.engine.scheduling.JenaSparqlParsing;

import org.apache.jena.query.*;

public class WebAccessControlManager {
	//TODO: implement WAC
	// https://github.com/solid/web-access-control-spec/blob/main/README-v0.5.0.md
	
	/**
	 * Main method to check the permission granted to an agent for the requested resource. Return a PermissionSet,
	 * where for every type of permission it is stated if it is granted or not.
	 * @param identifiers URI of the resource the agent is asking for
	 * @param permissions permission that the agent are requesting to the resource
	 * @param credentials credentials of the agent (WebID)
	 * @return PermissionSet that describe the permissions for the requested resource
	 * */
	public PermissionSet handle ( String identifiers, PermissionSet permissions, String credentials ) {
		ResultSet acl = this.getAclRecursive(identifiers, false);
		PermissionSet allowedModes  = this.createAuthorization(credentials, acl);
		this.checkPermission(permissions, allowedModes);
		
		
		return allowedModes;
	}
	
	/**
	 * Checks if the authorization grants the agent permission to use the given mode.
	 * @param permissions permissions that the agent is requesting
	 * @param allowedModes permission that are granted (taken from the acl of the resource)
	 * */
	private void checkPermission(PermissionSet permissions, PermissionSet allowedModes) {
		
	}

	/**
	 * Determines the available permissions for the given credentials and acl.
	 * @param credentials credential of the agent requesting the resource
	 * @param acl triples relevant for authorization
	 * */
	private PermissionSet createAuthorization(String credentials, ResultSet acl) {
		PermissionSet permissions = new PermissionSet(false, false, false, false);
		
		//foreach mode check if the user has access
		for (String mode : permissions.getPermissions().keySet()) {
			permissions.getPermissions().replace(mode, this.hasPermission(credentials, acl, mode));
		}
		
		return permissions;
	}

	/**
	 * Checks if the given agent has permission to execute the given mode based on the triples in the ACL.
	 * @param credentials agent who want the access
	 * @param acl triples relevant for authorization
	 * @param mode requested mode
	 * */
	private Boolean hasPermission(String credentials, ResultSet acl, String mode) {
		return null;
	}

	/**
	 * Returns the ACL triples that are relevant for the given identifier.
	 * These can either be from a corresponding ACL document or an ACL document higher up with defaults.
	 * @param id The resource identifiers of which we need the ACL triples.
	 * @param recurse Only used internally for recursion.
	 * */
	private ResultSet getAclRecursive (String id, boolean recurse) {
		/*
		1. Use the document's own ACL resource if it exists (in which case, stop here).
		2. Otherwise, look for authorizations to inherit from the ACL of the document's container. If those are found, stop here.
		3. Failing that, check the container's parent container to see if that has its own ACL file, and see if there are any permissions to inherit.
		4. Failing that, move up the container hierarchy until you find a container with an existing ACL file, which has some permissions to inherit.
		5. The root container of a user's account MUST have an ACL resource specified. (If all else fails, the search stops there.)
		*/
		return null;
	}
	
}
