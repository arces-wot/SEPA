package it.unibo.arces.wot.sepa.engine.protocol.wac;

import java.util.ArrayList;
import java.util.List;

public class WacStandaloneRequest {
	private String rootIdentifier;
	private List<String> resIdentifier;
	private String webid;

	
	public WacStandaloneRequest() {
		this.rootIdentifier = "";
		this.resIdentifier = new ArrayList<String>();
		this.webid = "";
	}
	
	public WacStandaloneRequest(String rootIdentifier, List<String> resIdentifier, String webid) {
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
	
	public List<String> getResIdentifier() {
		return resIdentifier;
	}
	
	public void setResIdentifier(List<String> resIdentifier) {
		this.resIdentifier = resIdentifier;
	}
	
	public String getWebid() {
		return webid;
	}
	
	public void setWebid(String webid) {
		this.webid = webid;
	}

}
