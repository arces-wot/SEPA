package it.unibo.arces.wot.sepa.engine.protocol.wac;

public class WacRequest {
	private String webid;
	private String resIdentifier;
	
	public WacRequest() {
		this.webid = "";
		this.resIdentifier = "";
	}
	
	public WacRequest(String webid, String resIdentifier) {
		this.webid = webid;
		this.resIdentifier = resIdentifier;
	}
	
	public String getWebid() {
		return webid;
	}
	
	public void setWebid(String webid) {
		this.webid = webid;
	}
	
	public String getResIdentifier() {
		return resIdentifier;
	}
	
	public void setResIdentifier(String resIdentifier) {
		this.resIdentifier = resIdentifier;
	}
	
}
