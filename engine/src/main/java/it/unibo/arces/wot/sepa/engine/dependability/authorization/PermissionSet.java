package it.unibo.arces.wot.sepa.engine.dependability.authorization;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PermissionSet {
	private Map <String, Boolean> permissions;

	public PermissionSet(boolean read, boolean write, boolean append, boolean control) {
		this.permissions = new HashMap<String, Boolean>();
		permissions.put("read", read);
		permissions.put("write", write);
		permissions.put("append", append);
		permissions.put("control", control);
	}

	public Map<String,Boolean> getPermissions() {
		return permissions;
	}
	
	public List<String> getTruthyPermissions() {
		List<String> truthyPermissions = new ArrayList<>();
		this.permissions.forEach((String mode, Boolean val) -> {if(val) truthyPermissions.add(mode);});
		return truthyPermissions;
	}

	public void setPermissions(Map<String,Boolean> permissions) {
		this.permissions = permissions;
	}
	
	public void changePermission(String mode, boolean newPermissionState) {
		if (this.permissions.containsKey(mode)) {
			this.permissions.replace(mode, newPermissionState);
		}
	}
	
	

}
