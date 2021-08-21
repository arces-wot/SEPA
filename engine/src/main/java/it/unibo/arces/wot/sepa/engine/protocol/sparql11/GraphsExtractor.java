package it.unibo.arces.wot.sepa.engine.protocol.sparql11;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Stack;

import org.apache.jena.graph.Node;
import org.apache.jena.query.Query;
import org.apache.jena.query.QueryFactory;
import org.apache.jena.sparql.core.DatasetDescription;
import org.apache.jena.sparql.core.Prologue;
import org.apache.jena.sparql.core.Quad;
import org.apache.jena.sparql.lang.ParserSPARQL11Update;
import org.apache.jena.sparql.modify.UpdateRequestSink;
import org.apache.jena.sparql.modify.request.Target;
import org.apache.jena.sparql.modify.request.UpdateAdd;
import org.apache.jena.sparql.modify.request.UpdateBinaryOp;
import org.apache.jena.sparql.modify.request.UpdateCopy;
import org.apache.jena.sparql.modify.request.UpdateCreate;
import org.apache.jena.sparql.modify.request.UpdateData;
import org.apache.jena.sparql.modify.request.UpdateDataDelete;
import org.apache.jena.sparql.modify.request.UpdateDataInsert;
import org.apache.jena.sparql.modify.request.UpdateWithUsing;
import org.apache.jena.sparql.modify.request.UpdateModify;
import org.apache.jena.sparql.modify.request.UpdateDeleteInsert;
import org.apache.jena.sparql.modify.request.UpdateDeleteWhere;
import org.apache.jena.sparql.modify.request.UpdateDropClear;
import org.apache.jena.sparql.modify.request.UpdateDrop;
import org.apache.jena.sparql.modify.request.UpdateClear;
import org.apache.jena.sparql.modify.request.UpdateLoad;
import org.apache.jena.sparql.modify.request.UpdateMove;
import org.apache.jena.sparql.syntax.Element;
import org.apache.jena.sparql.syntax.ElementExists;
import org.apache.jena.sparql.syntax.ElementGroup;
import org.apache.jena.sparql.syntax.ElementNamedGraph;
import org.apache.jena.sparql.syntax.ElementNotExists;
import org.apache.jena.update.Update;
import org.apache.jena.update.UpdateRequest;

import it.unibo.arces.wot.sepa.commons.exceptions.SEPASparqlParsingException;
import it.unibo.arces.wot.sepa.engine.scheduling.InternalQueryRequest;
import it.unibo.arces.wot.sepa.engine.scheduling.InternalUpdateRequest;

public class GraphsExtractor {
	public static void main(String[] args) throws SEPASparqlParsingException {
		// TODO
	}
	
	protected final static String arqDefaultGraphNodeUri = "urn:x-arq:DefaultGraphNode";
	protected final static String defaultGraph = "?DEFAULT";
	protected final static String graphVariable = "?GRAPH_VARIABLE";

	public static GraphsFromQuery getQueryGraphs(InternalQueryRequest sparqlQuery) throws SEPASparqlParsingException {
		// REQUEST PARAMETERS
		Set<String> default_graph_uri = sparqlQuery.getDefaultGraphUri();
		Set<String> named_graph_uri = sparqlQuery.getNamedGraphUri();
		
		// QUERY PARSING
		Query q = null;
		try {
			q = QueryFactory.create(sparqlQuery.getSparql());
		} catch (Exception e) {
			throw new SEPASparqlParsingException(e.getMessage());
		}
		
		// FROM / FROM NAMED
		Set<String> from = new HashSet<>();
		Set<String> fromNamed = new HashSet<>();

		if (q.hasDatasetDescription()) {
			DatasetDescription dd = q.getDatasetDescription();
			
			
			from.addAll(dd.getDefaultGraphURIs());
			fromNamed.addAll(dd.getNamedGraphURIs());
		}
		
		// GRAPHS CHECK (https://www.w3.org/TR/2013/REC-sparql11-protocol-20130321/#dataset)
		/*
		 * If different RDF Datasets are specified in both the protocol request
		 * and the SPARQL query string, then the SPARQL service must execute the
		 * query using the RDF Dataset given in the protocol request.
		 */
		if (default_graph_uri.size() > 0 && from.size() > 0) {
			if (!default_graph_uri.equals(from))
				from = default_graph_uri;
		}
		if (named_graph_uri.size() > 0 && fromNamed.size() > 0)
			if (!named_graph_uri.equals(fromNamed))
				fromNamed = named_graph_uri;
		
		// WHERE
		Set<String> whereGraphs = new HashSet<>();
		whereGraphs.addAll(extractGraphsFromWherePattern(q.getQueryPattern()));
		
		// GRAPHS PROCESSING
		if (whereGraphs.contains(graphVariable)) {
			// TODO: relax this constraint!
			// Remember to also check for trailing VALUES statement:
			// q.hasValues() -> q.getValuesVariables()/q.getValuesData()
			throw new SEPASparqlParsingException("Using graph variables is"
					+ " currently forbidden for security reasons.");
		}
		if (whereGraphs.contains(defaultGraph)) {
			if (from.size() > 0) {
				whereGraphs.remove(defaultGraph);
				whereGraphs.addAll(from);
			} else {
				throw new SEPASparqlParsingException("Referring to an empty"
						+ " DEFAULT graph is forbidden.");
			}
		}
		
		// RESULT PREPARATION
		GraphsFromQuery result = new GraphsFromQuery();
		result.setGraphsToRead(whereGraphs);
		return result;
	}

	public static GraphsFromQuery getUpdateGraphs(InternalUpdateRequest sparqlUpdate) throws SEPASparqlParsingException {
		// REQUEST PARAMETERS
		Set<String> using_graph_uri = sparqlUpdate.getDefaultGraphUri();
		Set<String> using_named_graph_uri = sparqlUpdate.getNamedGraphUri();
		
		// UPDATE PARSING
		UpdateRequest upd = new UpdateRequest();
		UpdateRequestSink sink = new UpdateRequestSink(upd);
		try {
			new ParserSPARQL11Update().parse(sink, new Prologue(), sparqlUpdate.getSparql());
		} catch (Exception e) {
			throw new SEPASparqlParsingException(e.getMessage());
		}

		GraphsFromQuery result = new GraphsFromQuery();
		GraphsFromQuery partialResult = null;
		for (Update op : upd.getOperations()) {
			// UpdateWithUsing -> UpdateModify -> UpdateDeleteInsert
			if (op instanceof UpdateWithUsing && op instanceof UpdateModify && op instanceof UpdateDeleteInsert) {
				// DELETE/INSERT/WHERE
				UpdateDeleteInsert diw = (UpdateDeleteInsert) op;
				partialResult = processDeleteInsertWhere(diw, using_graph_uri, using_named_graph_uri);
			}
			// UpdateDeleteWhere
			else if (op instanceof UpdateDeleteWhere) {
				// DELETE WHERE
				UpdateDeleteWhere dw = (UpdateDeleteWhere) op;
				partialResult = processDeleteWhere(dw, using_graph_uri, using_named_graph_uri);
			}
			// UpdateData -> (UpdateDataDelete, UpdateDataInsert)
			else if (op instanceof UpdateData) {
				if (op instanceof UpdateDataDelete) {
					// DELETE DATA
					UpdateDataDelete dd = (UpdateDataDelete) op;
					partialResult = processDeleteData(dd);
				} else if (op instanceof UpdateDataInsert) {
					// INSERT DATA
					UpdateDataInsert di = (UpdateDataInsert) op;
					partialResult = processInsertData(di);
				}
			}
			// UpdateLoad
			else if (op instanceof UpdateLoad) {
				// LOAD
				UpdateLoad l = (UpdateLoad) op;
				partialResult = processLoad(l);
			}
			// UpdateDropClear -> (UpdateDrop, UpdateClear)
			else if (op instanceof UpdateDropClear) {
				if (op instanceof UpdateDrop) {
					// DROP
					UpdateDrop d = (UpdateDrop) op;
					partialResult = processDrop(d);
				} else if (op instanceof UpdateDataInsert) {
					// CLEAR
					UpdateClear c = (UpdateClear) op;
					partialResult = processClear(c);
				}
			}
			// UpdateCreate
			else if (op instanceof UpdateCreate) {
				// CREATE
				UpdateCreate c = (UpdateCreate) op;
				partialResult = processCreate(c);
			}
			// UpdateBinaryOp -> (UpdateCopy, UpdateMove, UpdateAdd)
			else if (op instanceof UpdateBinaryOp) {
				if (op instanceof UpdateCopy) {
					// COPY
					UpdateCopy c = (UpdateCopy) op;
					partialResult = processCopy(c);
				} else if (op instanceof UpdateMove) {
					// MOVE
					UpdateMove m = (UpdateMove) op;
					partialResult = processMove(m);
				} else if (op instanceof UpdateAdd) {
					// ADD
					UpdateAdd a = (UpdateAdd) op;
					partialResult = processAdd(a);
				}
			}
			
			// MERGE CURRENT RESULT INTO FINAL RESULT
			result.mergeWith(partialResult);
		}

		return result;
	}

	private static GraphsFromQuery processDeleteInsertWhere(UpdateDeleteInsert diw,
			Set<String> using_graph_uri, Set<String> using_named_graph_uri) throws SEPASparqlParsingException {
		String with = null;
		Set<String> using = new HashSet<>();
		Set<String> usingNamed = new HashSet<>();
		Set<String> deleteGraphs = new HashSet<>();
		Set<String> insertGraphs = new HashSet<>();
		Set<String> whereGraphs = new HashSet<>();
		
		// WITH
		Node node = diw.getWithIRI();
		if (node != null && node.isURI())
			with = node.getURI();

		// USING
		using.addAll(processNodeList(diw.getUsing()));

		// USING NAMED
		usingNamed.addAll(processNodeList(diw.getUsingNamed()));
		
		// VALIDITY CHECK (https://www.w3.org/TR/2013/REC-sparql11-protocol-20130321/#update-dataset)
		if (using_graph_uri.size() > 0 || using_named_graph_uri.size() > 0) {
			if (with != null || using.size() > 0 || usingNamed.size() > 0) 
				throw new SEPASparqlParsingException("It is an error to"
						+ " supply the using-graph-uri or using-named-graph-uri"
						+ " parameters when using this protocol to convey"
						+ " a SPARQL 1.1 Update request that contains an"
						+ " operation that uses the USING, USING NAMED,"
						+ " or WITH clause.");
		}
		if (using_graph_uri.size() > 0 || using_named_graph_uri.size() > 0) {
			using = using_graph_uri;
			usingNamed = using_named_graph_uri;
		}

		// DELETE { GRAPH ... }
		deleteGraphs.addAll(processQuadList(diw.getDeleteQuads()));
		
		// VALIDITY CHECK
		if (deleteGraphs.contains(defaultGraph)) {
			if (with != null) {
				deleteGraphs.remove(defaultGraph);
				deleteGraphs.add(with);
			} else {
				// TODO: relax this constraint!
				throw new SEPASparqlParsingException("Referring to an empty"
					+ " DEFAULT graph in the [DELETE] clause is currently"
					+ " forbidden for security reasons.");
			}
		}
		if (deleteGraphs.contains(graphVariable))
			// TODO: relax this constraint!
			throw new SEPASparqlParsingException("Using graph variables in the"
					+ " [DELETE] clause is currently forbidden.");

		// INSERT { GRAPH ... }
		insertGraphs.addAll(processQuadList(diw.getInsertQuads()));
		
		// VALIDITY CHECK
		if (insertGraphs.contains(defaultGraph)) {
			if (with != null) {
				insertGraphs.remove(defaultGraph);
				insertGraphs.add(with);
			} else {
				// TODO: relax this constraint!
				throw new SEPASparqlParsingException("Referring to an empty"
					+ " DEFAULT graph in the [INSERT] clause is currently"
					+ " forbidden for security reasons.");
			}
		}
		if (insertGraphs.contains(graphVariable))
			// TODO: relax this constraint!
			throw new SEPASparqlParsingException("Using graph variables in the"
					+ " [INSERT] clause is currently forbidden.");
		
		// WHERE { GRAPH ... }
		whereGraphs.addAll(extractGraphsFromWherePattern(diw.getWherePattern()));
		
		// VALIDITY CHECK
		if (whereGraphs.contains(defaultGraph)) {
			if (using.size() > 0) {
				whereGraphs.remove(defaultGraph);
				whereGraphs.addAll(using);
			} else if (with != null) {
				whereGraphs.remove(defaultGraph);
				whereGraphs.add(with);
			} else {
				// TODO: relax this constraint!
				throw new SEPASparqlParsingException("Referring to an empty"
					+ " DEFAULT graph in the [WHERE] clause is currently"
					+ " forbidden for security reasons.");
			}
		}
		if (whereGraphs.contains(graphVariable))
			// TODO: relax this constraint!
			throw new SEPASparqlParsingException("Using graph variables in the"
					+ " [WHERE] clause is currently forbidden.");
		
		// RESULT PREPARATION
		GraphsFromQuery result = new GraphsFromQuery();
		result.setGraphsToRead(whereGraphs);
		result.setGraphsToAppend(insertGraphs);
		result.setGraphsToWrite(deleteGraphs);
		return result;
	}
	
	private static GraphsFromQuery processDeleteWhere(UpdateDeleteWhere dw,
			Set<String> using_graph_uri, Set<String> using_named_graph_uri) throws SEPASparqlParsingException {
		Set<String> deleteWhereGraphs = new HashSet<>();
		deleteWhereGraphs.addAll(processQuadList(dw.getQuads()));
		
		// VALIDITY CHECK
		if (deleteWhereGraphs.contains(defaultGraph)) {
			if (using_graph_uri.size() > 0) {
				deleteWhereGraphs.remove(defaultGraph);
				deleteWhereGraphs.addAll(using_graph_uri);
			} else {
				throw new SEPASparqlParsingException("Referring to an empty"
					+ " DEFAULT graph is forbidden for security reasons.");
			}
		}
		if (deleteWhereGraphs.contains(graphVariable))
			if (using_named_graph_uri.size() > 0) {
				deleteWhereGraphs.remove(graphVariable);
				deleteWhereGraphs.addAll(using_named_graph_uri);
			} else {
				throw new SEPASparqlParsingException("Referring to an empty"
					+ " set of NAMED graphs is forbidden for security reasons.");
			}
		
		// RESULT PREPARATION
		GraphsFromQuery result = new GraphsFromQuery();
		result.setGraphsToRead(deleteWhereGraphs);
		result.setGraphsToWrite(deleteWhereGraphs);
		return result;
	}

	private static GraphsFromQuery processDeleteData(UpdateDataDelete dd) throws SEPASparqlParsingException {
		Set<String> deleteGraphs = new HashSet<>();
		deleteGraphs.addAll(processQuadList(dd.getQuads()));
		
		// VALIDITY CHECK
		if (deleteGraphs.contains(defaultGraph)) {
			throw new SEPASparqlParsingException("Performing an [DELETE DATA]"
					+ " update that removes triples from the DEFAULT graph"
					+ " is forbidden for security reasons.");
		}
		if (deleteGraphs.contains(graphVariable))
			// GRAPH ?g -> ?g belongs to all the existing NAMED graphs
			throw new SEPASparqlParsingException("Using a graph variable"
					+ " inside an [DELETE DATA] update is forbidden for security"
					+ " reasons.");
		
		// RESULT PREPARATION
		GraphsFromQuery result = new GraphsFromQuery();
		result.setGraphsToWrite(deleteGraphs);
		return result;
	}
	
	private static GraphsFromQuery processInsertData(UpdateDataInsert di) throws SEPASparqlParsingException {
		Set<String> insertGraphs = new HashSet<>();
		insertGraphs.addAll(processQuadList(di.getQuads()));
		
		// VALIDITY CHECK
		if (insertGraphs.contains(defaultGraph)) {
			throw new SEPASparqlParsingException("Performing an [INSERT DATA]"
					+ " update that stores triples inside the DEFAULT graph"
					+ " is forbidden for security reasons.");
		}
		if (insertGraphs.contains(graphVariable))
			// GRAPH ?g -> ?g belongs to all the existing NAMED graphs
			throw new SEPASparqlParsingException("Using a graph variable"
					+ " inside an [INSERT DATA] update is forbidden for security"
					+ " reasons.");
		
		// RESULT PREPARATION
		GraphsFromQuery result = new GraphsFromQuery();
		result.setGraphsToAppend(insertGraphs);
		return result;
	}

	private static GraphsFromQuery processDrop(UpdateDrop d) throws SEPASparqlParsingException {
		Target toDrop = d.getTarget();
		Set<String> dropGraphs = new HashSet<>();
		
		// VALIDITY CHECK
		if (toDrop.isOneNamedGraph()) {
			// GRAPH <graph_iri>
			dropGraphs.add(toDrop.getGraph().getURI());
		} else if (toDrop.isDefault()) {
			// DEFAULT
			throw new SEPASparqlParsingException("Performing a [DROP DEFAULT]"
					+ " update is forbidden for security reasons.");
		} else if (toDrop.isAllNamed()) {
			// NAMED
			throw new SEPASparqlParsingException("Performing a [DROP NAMED]"
					+ " update is forbidden for security reasons.");
		} else if (toDrop.isAll()) {
			// ALL
			throw new SEPASparqlParsingException("Performing a [DROP ALL]"
					+ " update is forbidden for security reasons.");
		}
		
		// RESULT PREPARATION
		GraphsFromQuery result = new GraphsFromQuery();
		result.setGraphsToDelete(dropGraphs);
		return result;
	}
	
	private static GraphsFromQuery processClear(UpdateClear c) throws SEPASparqlParsingException {
		Target toClear = c.getTarget();
		Set<String> clearGraphs = new HashSet<>();
		
		// VALIDITY CHECK
		if (toClear.isOneNamedGraph()) {
			// GRAPH <graph_iri>
			clearGraphs.add(toClear.getGraph().getURI());
		} else if (toClear.isDefault()) {
			// DEFAULT
			throw new SEPASparqlParsingException("Performing a [CLEAR DEFAULT]"
					+ " update is forbidden for security reasons.");
		} else if (toClear.isAllNamed()) {
			// NAMED
			throw new SEPASparqlParsingException("Performing a [CLEAR NAMED]"
					+ " update is forbidden for security reasons.");
		} else if (toClear.isAll()) {
			// ALL
			throw new SEPASparqlParsingException("Performing a [CLEAR ALL]"
					+ " update is forbidden for security reasons.");
		}
		
		// RESULT PREPARATION
		GraphsFromQuery result = new GraphsFromQuery();
		result.setGraphsToWrite(clearGraphs);
		return result;
	}
	
	private static GraphsFromQuery processLoad(UpdateLoad l) throws SEPASparqlParsingException {
		Node dest = l.getDest();
		Set<String> loadGraphs = new HashSet<>();

		// VALIDITY CHECK
		if (dest == null) {
			throw new SEPASparqlParsingException("Performing a [LOAD] update into"
					+ " the DEFAULT graph is forbidden for security reasons.");
		} else {
			String loadTo = dest.getURI();
			loadGraphs.add(loadTo);
		}
		
		// RESULT PREPARATION
		GraphsFromQuery result = new GraphsFromQuery();
		result.setGraphsToAppend(loadGraphs);
		return result;
	}

	private static GraphsFromQuery processCreate(UpdateCreate c) throws SEPASparqlParsingException {
		Set<String> createGraphs = new HashSet<>();
		createGraphs.add(c.getGraph().getURI());
		
		// RESULT PREPARATION
		GraphsFromQuery result = new GraphsFromQuery();
		//  TODO: Append or Write mode? acl:createGraph mode?
		result.setGraphsToAppend(createGraphs);
		return result;
	}
	
	private static GraphsFromQuery processCopy(UpdateCopy c) throws SEPASparqlParsingException {
		Target src = c.getSrc();
		Target dest = c.getDest();
		Set<String> copyFrom = new HashSet<>();
		Set<String> copyTo = new HashSet<>();
		
		// VALIDITY CHECK
		if (src.isOneNamedGraph()) {
			// GRAPH <graph_iri>
			copyFrom.add(src.getGraph().getURI());
		} else if (src.isDefault()) {
			// DEFAULT
			throw new SEPASparqlParsingException("Performing a [COPY DEFAULT TO any]"
					+ " update is forbidden for security reasons.");
		}
		
		if (dest.isOneNamedGraph()) {
			// GRAPH <graph_iri>
			copyTo.add(dest.getGraph().getURI());
		} else if (dest.isDefault()) {
			// DEFAULT
			throw new SEPASparqlParsingException("Performing a [COPY any TO DEFAULT]"
					+ " update is forbidden for security reasons.");
		}
		
		// RESULT PREPARATION
		GraphsFromQuery result = new GraphsFromQuery();
		result.setGraphsToRead(copyFrom);
		result.setGraphsToWrite(copyTo);
		return result;
	}
	
	private static GraphsFromQuery processMove(UpdateMove m) throws SEPASparqlParsingException {
		Target src = m.getSrc();
		Target dest = m.getDest();
		Set<String> moveFrom = new HashSet<>();
		Set<String> moveTo = new HashSet<>();
		
		// VALIDITY CHECK
		if (src.isOneNamedGraph()) {
			// GRAPH <graph_iri>
			moveFrom.add(src.getGraph().getURI());
		} else if (src.isDefault()) {
			// DEFAULT
			throw new SEPASparqlParsingException("Performing a [MOVE DEFAULT TO any]"
					+ " update is forbidden for security reasons.");
		}
		
		if (dest.isOneNamedGraph()) {
			// GRAPH <graph_iri>
			moveTo.add(dest.getGraph().getURI());
		} else if (dest.isDefault()) {
			// DEFAULT
			throw new SEPASparqlParsingException("Performing a [MOVE any TO DEFAULT]"
					+ " update is forbidden for security reasons.");
		}
		
		// RESULT PREPARATION
		GraphsFromQuery result = new GraphsFromQuery();
		result.setGraphsToRead(moveFrom);
		result.setGraphsToDelete(moveFrom);
		result.setGraphsToWrite(moveTo);
		return result;
	}
	
	private static GraphsFromQuery processAdd(UpdateAdd a) throws SEPASparqlParsingException {
		Target src = a.getSrc();
		Target dest = a.getDest();
		Set<String> addFrom = new HashSet<>();
		Set<String> addTo = new HashSet<>();
		
		// VALIDITY CHECK
		if (src.isOneNamedGraph()) {
			// GRAPH <graph_iri>
			addFrom.add(src.getGraph().getURI());
		} else if (src.isDefault()) {
			// DEFAULT
			throw new SEPASparqlParsingException("Performing a [ADD DEFAULT TO any]"
					+ " update is forbidden for security reasons.");
		}
		
		if (dest.isOneNamedGraph()) {
			// GRAPH <graph_iri>
			addTo.add(dest.getGraph().getURI());
		} else if (dest.isDefault()) {
			// DEFAULT
			throw new SEPASparqlParsingException("Performing a [ADD any TO DEFAULT]"
					+ " update is forbidden for security reasons.");
		}
		
		// RESULT PREPARATION
		GraphsFromQuery result = new GraphsFromQuery();
		result.setGraphsToRead(addFrom);
		result.setGraphsToAppend(addTo);
		return result;
	}
	
	private static Set<String> processNodeList(List<Node> list) {
		Set<String> result = new HashSet<>();
		Set<String> graphVariables = new HashSet<>();
		
		for (Node n : list) {
			if (n.isURI()) {
				String uri = n.getURI();
				if (uri.equals(arqDefaultGraphNodeUri)) uri = defaultGraph;
				result.add(uri);
			} else if (n.isVariable()) {
				result.add(graphVariable);
				graphVariables.add(n.getName());
			}
		}
		
		return result;
	}
	
	private static Set<String> processQuadList(List<Quad> list) {
		Set<String> result = new HashSet<>();
		Set<String> graphVariables = new HashSet<>();
		
		for (Quad q : list) {
			Node n = q.getGraph();
			if (n.isURI()) {
				String uri = n.getURI();
				if (uri.equals(arqDefaultGraphNodeUri)) uri = defaultGraph;
				result.add(uri);
			} else if (n.isVariable()) {
				result.add(graphVariable);
				graphVariables.add(n.getName());
			}
		}
		
		return result;
	}
	
	private static Set<String> extractGraphsFromWherePattern(Element wherePattern) {
		return (wherePattern == null) ? new HashSet<>() : extractGraphs(wherePattern);
	}
	
	private static Set<String> extractGraphs(Element rootElement) {
		Set<String> result = new HashSet<String>();
		Set<String> graphVariables = new HashSet<>();

		// Depth-First Tree search (iteration based)
		Stack<Element> toBeParsed = new Stack<>();
		toBeParsed.push(rootElement);
		while (toBeParsed.size() > 0) {
			Element e = toBeParsed.pop();
			if (e == null) continue;
			
//			[ ] ElementFilter -> getExpr (Expr) [?] [[FILTER(?g = <graph_iri>)]]
//			[ ] ElementAssign -> getExpr (Expr) [?] , getVar (Var) [[SPARQL* LET?]]
//			[ ] ElementBind -> getExpr (Expr) , getVar (Var) [[BIND(<graph_iri> as ?g)]]

//			[ ] ElementUnion -> getElements (List<Element>) [[{...} UNION {...}]]
//			[ ] ElementOptional -> getOptionalElement (Element) [[OPTIONAL {...}]]
//			[*] ElementGroup -> getElements (List<Element>) [[{{...}{...}{...}}]]
//			[*] ElementNamedGraph -> getElement (Element), getGraphNameNode (Node) [[GRAPH <graph_iri> {...}]]
//			[ ] ElementMinus -> getMinusElement (Element) [[{...} MINUS {...}]]
//			[ ] ElementSubQuery -> getQuery (Query)

//			[ ] ElementService -> STILL NOT SUPPORTED [?]

//		  	[ ] ElementTriplesBlock -> getPattern (BasicPattern) [no graphs] [[{BGP}]]
//				[ ] ElementPathBlock -> getPattern (PathBlock) [no graphs] [[{BGP}]]
//				[ ] ElementData -> ???
			
//			[+] Element1 -> getElement (Element) {
//				[ ] ElementDataset -> unused in parser ???
//				[*] ElementExists -> [[EXISTS {...}]]
//				[*] ElementNotExists -> [[NOT EXISTS {...}]]
//			}
			
			if (e instanceof ElementGroup) {
				ElementGroup group = (ElementGroup) e;
				for (Element subElement : group.getElements()) {
					toBeParsed.push(subElement);
				}
			} else if (e instanceof ElementNamedGraph) {
				ElementNamedGraph namedGraph = (ElementNamedGraph) e;
				Node namedNode = namedGraph.getGraphNameNode();

				// TODO: duplicated code, see processNodeList() and processQuadList()
				if (namedNode.isURI()) {
					// GRAPH <uri> { ... }
					String uri = namedNode.getURI();
					if (uri.equals(arqDefaultGraphNodeUri)) uri = defaultGraph;
					result.add(uri);
				} else if (namedNode.isVariable()) {
					// GRAPH ?g { ... }
					result.add(graphVariable);
					graphVariables.add(namedNode.getName());
				}
			} else if (e instanceof ElementExists) {
				ElementExists exists = (ElementExists) e;
				toBeParsed.push(exists.getElement());
			} else if (e instanceof ElementNotExists) {
				ElementNotExists exists = (ElementNotExists) e;
				toBeParsed.push(exists.getElement());
			}

		}

		return result;
	}
}
