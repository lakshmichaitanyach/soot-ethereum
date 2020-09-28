package dfa;

import java.util.*;
import soot.*;
import soot.jimple.AssignStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.IntConstant;
import soot.jimple.InvokeExpr;
import soot.jimple.Jimple;
import soot.jimple.LongConstant;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;
import soot.jimple.VirtualInvokeExpr;
import soot.toolkits.graph.*;
import soot.toolkits.scalar.BackwardFlowAnalysis;
import soot.toolkits.scalar.FlowSet;
import soot.util.Chain;


public class AnalysisTransformer extends SceneTransformer 
{

	@Override
	protected void internalTransform(String arg0, Map arg1) {

		// Get Main Method
		SootMethod sMethod = Scene.v().getMainMethod();

		// Create graph based on the method
		UnitGraph graph = new BriefUnitGraph(sMethod.getActiveBody());

		// Perform LV Analysis on the Graph
		LiveVariableAnalysis analysis = new LiveVariableAnalysis(graph);

		// Print live variables at the entry and exit of each node
		Iterator<Unit> unitIt = graph.iterator();
		analysis.getFlowBefore(unitIt.next());

		
		Set<String> activeList = new HashSet<>();
		Set<String> nonActiveList = new HashSet<>();
		
		Chain units = graph.getBody().getUnits();
		Value base = null;
		Stmt stm =null;
		
		Set<String> whiteList = new HashSet<>();
		whiteList.add("send");
		whiteList.add("build");
		
		Set<String> blackList = new HashSet<>();
		blackList.add("stealData");
		
		HashMap<String, Integer> threatMap = new HashMap<>();
		threatMap.put("\"password\"",15);
		threatMap.put("\"imei\"",20);
		
		
		while (unitIt.hasNext()) {
			Unit s = unitIt.next();
			stm = (Stmt)s;
			if (stm.containsInvokeExpr()) { 
				if(!stm.getInvokeExpr().toString().contains("specialinvoke") && !stm.getInvokeExpr().getMethod().getDeclaringClass().toString().contains("java")) {
					if (stm.getInvokeExpr().getMethod().hasActiveBody()) {
						if(blackList.contains(stm.getInvokeExpr().getMethod().getName()))
						{
							nonActiveList.add(stm.getInvokeExpr().getMethod().getName()); //GET NAME OF THE INVOKE EXPRESSION statement (specialinvoke)
							continue;
						}
						activeList.add(stm.getInvokeExpr().getMethod().getName()); //GET NAME OF THE INVOKE EXPRESSION statement (specialinvoke)
						if(stm.getInvokeExpr().toString().contains("setMalware")) {
							InvokeExpr ie = stm.getInvokeExpr();
							InstanceInvokeExpr iie = (InstanceInvokeExpr)ie;
							base = iie.getBase();
						}
					}
					else{
						if(!stm.getInvokeExpr().getMethod().getName().contains("get") && !whiteList.contains(stm.getInvokeExpr().getMethod().getName()))
							nonActiveList.add(stm.getInvokeExpr().getMethod().getName());
					}
				}	
			}
		}
		

//		Iterator argsIt = stm.getInvokeExpr().getArgs().iterator();
//		
//		System.out.println(stm.getInvokeExpr().toString());
//									
//		while(argsIt.hasNext()) {
//			System.out.println(argsIt.next().toString());
//		}
					System.out.println("Active Method Calls");
					for(String s : activeList)
					{
						System.out.println("\t"+s);
					}

					System.out.println("Non Active Method Calls");
					for(String s : nonActiveList)//ITERATE THROUGH LIST OF STATEMENT NAMES
					{						
						
						System.out.println("\t"+s +" --> Possible Malware found");
						LinkedList<Value> args = new LinkedList<>();
						args.add(StringConstant.v(s));
						args.add(StringConstant.v("Malware"));
						args.add(StringConstant.v("Date"));
						
						SootMethodRef setMalwareRef = Scene.v().getMethod("<dfa.Malware: org.web3j.protocol.core.RemoteCall setMalware(java.lang.String,java.lang.String,java.lang.String)>").makeRef();						
						SootMethodRef blockChainMethodRef = Scene.v().getMethod("<org.web3j.protocol.core.RemoteCall: java.lang.Object send()>").makeRef();
						Local tmp = Jimple.v().newLocal("$r"+Integer.toString(graph.getBody().getLocalCount()), RefType.v("org.web3j.protocol.core.RemoteCall"));
						graph.getBody().getLocals().add(tmp);
						VirtualInvokeExpr vr = Jimple.v().newVirtualInvokeExpr((Local) base, setMalwareRef, args);
						AssignStmt a = Jimple.v().newAssignStmt(tmp, vr);
						units.insertBefore(a,stm);
						LinkedList<Value> args1 = new LinkedList<>();						
						units.insertBefore(Jimple.v().newInvokeStmt(Jimple.v().newVirtualInvokeExpr((Local)a.getLeftOp(), blockChainMethodRef, args1)),stm);
						System.out.println("\tMalware Details inserted into blockchain");
						
						//CREATE A HASHMAP
						//INSIDE WE ADD EACH FUNCTION AND ARGUMENTS
						//BASED ON THE ARGUMENTS WE CALCULATE THE AVERAGES
					}
					
					
					Iterator<Unit> unitIt1 = graph.iterator();
					
					while (unitIt1.hasNext()) {
						Unit s = unitIt1.next();
						stm = (Stmt)s;
						if (stm.containsInvokeExpr()) { 
							if(nonActiveList.contains(stm.getInvokeExpr().getMethod().getName().toString())) {
								List<Value> args = stm.getInvokeExpr().getArgs();
								
								System.out.println(stm.getInvokeExpr().toString());
								int sum = 0;
								for(Value v : args) {
									if(threatMap.containsKey(v.toString())) {
										sum+= threatMap.get(v.toString());
									}
									else
										sum+=1;
								}
								int avgThreat = sum / stm.getInvokeExpr().getArgCount();								
								if(avgThreat>8)
									System.out.println(stm.getInvokeExpr().getMethod().getName().toString() +" is a Confirmed Malware");
								//INSERT MOST IMPORTANT MALWARE HERE
							}
						}
					}

	}
}