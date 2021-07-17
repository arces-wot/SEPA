package it.unibo.arces.wot.sepa.engine.dependability.authorization.wac;

import java.util.ArrayList;
import java.util.List;

public class PermissionsBean {
	private boolean read;
	private boolean write;
	private boolean append;
	private boolean control;

	public PermissionsBean() {
		this.read = false;
		this.write = false;
		this.append = false;
		this.control = false;
	}
	
	public PermissionsBean(boolean read, boolean write, boolean append, boolean control) {
		this.read = read;
		this.write = write;
		this.append = append || write; // "write" logically implies "append"
		this.control = control;
	}
	
	public List<String> getTruthyPermissions() {
		List<String> truthyPermissions = new ArrayList<>();
		
		if (this.read) truthyPermissions.add("read");
		
		if (this.write) {
			truthyPermissions.add("write");
			truthyPermissions.add("append"); // "write" logically implies "append"
		} else if (this.append) truthyPermissions.add("append");
		
		if (this.control) truthyPermissions.add("control");
		
		return truthyPermissions;
	}

	public boolean isRead() {
		return read;
	}

	public void setRead(boolean read) {
		this.read = read;
	}

	public boolean isWrite() {
		return write;
	}

	public void setWrite(boolean write) {
		this.write = write;
		if (this.write) this.append = true; // "write" logically implies "append"
	}

	public boolean isAppend() {
		return append || write; // "write" logically implies "append"
	}

	public void setAppend(boolean append) {
		this.append = append || this.write; // "write" logically implies "append"
		if (!this.append) this.write = false; // "NOT append" logically implies "NOT write"
	}

	public boolean isControl() {
		return control;
	}

	public void setControl(boolean control) {
		this.control = control;
	}

}
