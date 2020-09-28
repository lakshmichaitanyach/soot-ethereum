import dfa.AnalysisTransformer;

//import dfa.MyAnalysisTagger;
import soot.PackManager;
import soot.Transform;

public class Main {

	public static void main(String[] args) {
		PackManager.v().getPack("wjtp").add(new Transform("wjtp.dfa", new AnalysisTransformer()));
		  
		  soot.Main.main(args);

	}

}
