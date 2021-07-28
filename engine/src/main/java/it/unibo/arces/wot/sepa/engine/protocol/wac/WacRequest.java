package it.unibo.arces.wot.sepa.engine.protocol.wac;

public class WacRequest {
	private String rootIdentifier;
	private String resIdentifier;
	private String webid;

	
	public WacRequest() {
		this.rootIdentifier = "";
		this.resIdentifier = "";
		this.webid = "";
	}
	
	public WacRequest(String rootIdentifier, String resIdentifier, String webid) {
		this.rootIdentifier = rootIdentifier;
		this.resIdentifier = resIdentifier;
		this.webid = webid;
	}
	
	public String getRootIdentifier() {
		return rootIdentifier;
	}
	
	public void setRootIdentifier(String rootIdentifier) {
		this.rootIdentifier = rootIdentifier;
	}
	
	public String getResIdentifier() {
		return resIdentifier;
	}
	
	public void setResIdentifier(String resIdentifier) {
		this.resIdentifier = resIdentifier;
	}
	
	public String getWebid() {
		return webid;
	}
	
	public void setWebid(String webid) {
		this.webid = webid;
	}
	
}
