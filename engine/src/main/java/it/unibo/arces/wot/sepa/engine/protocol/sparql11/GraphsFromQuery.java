package it.unibo.arces.wot.sepa.engine.protocol.sparql11;

import java.util.List;

public class GraphsFromQuery {
	private List<String> graphsToBeRead;
	private List<String> graphsToBeWritten;
	private List<String> graphsToBeDeleted;
	private String roodId;
	
	public GraphsFromQuery() {
		super();
	}
	public List<String> getGraphsToBeRead() {
		return graphsToBeRead;
	}
	public void setGraphsToBeRead(List<String> graphsToBeRead) {
		this.graphsToBeRead = graphsToBeRead;
	}
	public List<String> getGraphsToBeWritten() {
		return graphsToBeWritten;
	}
	public void setGraphsToBeWritten(List<String> graphsToBeWritten) {
		this.graphsToBeWritten = graphsToBeWritten;
	}
	public List<String> getGraphsToBeDeleted() {
		return graphsToBeDeleted;
	}
	public void setGraphsToBeDeleted(List<String> graphsToBeDeleted) {
		this.graphsToBeDeleted = graphsToBeDeleted;
	}
	public String getRoodId() {
		return roodId;
	}
	public void setRoodId(String roodId) {
		this.roodId = roodId;
	}
	
	

}
