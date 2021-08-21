package it.unibo.arces.wot.sepa.engine.protocol.sparql11;

import java.util.Set;

public class GraphsFromQuery {
	private Set<String> graphsToRead;
	private Set<String> graphsToWrite;
	private Set<String> graphsToAppend;
	private Set<String> graphsToDelete;
	
	public GraphsFromQuery() {
		super();
		this.graphsToRead = null;
		this.graphsToWrite = null;
		this.graphsToAppend = null;
		this.graphsToDelete = null;
	}
	public Set<String> getGraphsToRead() {
		return graphsToRead;
	}
	public void setGraphsToRead(Set<String> graphsToRead) {
		this.graphsToRead = graphsToRead;
	}
	public Set<String> getGraphsToWrite() {
		return graphsToWrite;
	}
	public void setGraphsToWrite(Set<String> graphsToWrite) {
		this.graphsToWrite = graphsToWrite;
	}
	public Set<String> getGraphsToAppend() {
		return graphsToAppend;
	}
	public void setGraphsToAppend(Set<String> graphsToAppend) {
		this.graphsToAppend = graphsToAppend;
	}
	public Set<String> getGraphsToDelete() {
		return graphsToDelete;
	}
	public void setGraphsToDelete(Set<String> graphsToDelete) {
		this.graphsToDelete = graphsToDelete;
	}
	
	public void mergeWith(GraphsFromQuery other) {
		if (other == null)
			return;
		
		if (other.graphsToRead != null){
			if (this.graphsToRead != null)
				this.graphsToRead.addAll(other.graphsToRead);
			else
				this.setGraphsToRead(other.graphsToRead);
		}
		
		if (other.graphsToWrite != null){
			if (this.graphsToWrite != null)
				this.graphsToWrite.addAll(other.graphsToWrite);
			else
				this.setGraphsToWrite(other.graphsToWrite);
		}
		
		if (other.graphsToAppend != null){
			if (this.graphsToAppend != null)
				this.graphsToAppend.addAll(other.graphsToAppend);
			else
				this.setGraphsToAppend(other.graphsToAppend);
		}
		
		if (other.graphsToDelete != null) {
			if (this.graphsToDelete != null)
				this.graphsToDelete.addAll(other.graphsToDelete);
			else
				this.setGraphsToDelete(other.graphsToDelete);
		}
	}
}
