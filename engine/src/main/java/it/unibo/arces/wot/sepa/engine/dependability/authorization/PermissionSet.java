package it.unibo.arces.wot.sepa.engine.dependability.authorization;

import java.util.HashMap;
import java.util.Map;

public class PermissionSet {
	private Map <String, Boolean> permissions;

	public PermissionSet(boolean read, boolean write, boolean append, boolean control) {
		this.permissions = new HashMap();
		permissions.put("read", read);
		permissions.put("write", write);
		permissions.put("append", append);
		permissions.put("control", control);
		
	}

	public Map<String,Boolean> getPermissions() {
		return permissions;
	}

	public void setPermissions(Map<String,Boolean> permissions) {
		this.permissions = permissions;
	}
	
	public void changePermission(String mode, boolean newPermissionState) {
		
	}
	
	

}
