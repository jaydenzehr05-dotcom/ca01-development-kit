// @category CA01
// Read-only static survey of authentic CA01 PROC_DISPLAY imports/call sites.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class CA01DisplaySurvey extends GhidraScript {
    static boolean relevant(String s) {
        return s.startsWith("sysDis") || s.startsWith("rq_fls") ||
               s.startsWith("fs_mpl") || s.startsWith("rq_tsk") ||
               s.startsWith("rq_msg") || s.startsWith("rq_ipc") ||
               s.startsWith("egl") || s.startsWith("gl") ||
               s.startsWith("vg") || s.startsWith("uie") ||
               s.startsWith("gdr") || s.startsWith("fs_sys");
    }
    public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=1) throw new IllegalArgumentException("Need output folder");
        File directory=new File(args[0]);directory.mkdirs();
        FunctionManager functions=currentProgram.getFunctionManager();
        ReferenceManager refs=currentProgram.getReferenceManager();
        HashMap<String,Function> selected=new HashMap<>();
        try(PrintWriter out=new PrintWriter(new FileWriter(new File(directory,"ghidra-display-survey.txt")));
            PrintWriter calls=new PrintWriter(new FileWriter(new File(directory,"external-calls.tsv")))) {
            out.println("PROGRAM "+currentProgram.getName());
            out.println("LANGUAGE "+currentProgram.getLanguage().getLanguageID());
            out.println("ENTRY "+currentProgram.getSymbolTable().getExternalEntryPointIterator().hasNext());
            out.println("FUNCTION_COUNT "+functions.getFunctionCount());
            for(MemoryBlock b:currentProgram.getMemory().getBlocks())
                out.println("BLOCK "+b.getName()+" "+b.getStart()+" "+b.getSize());
            calls.println("import\timport_address\txref\tcaller_address\tcaller_name");
            int count=0, refsCount=0;
            FunctionIterator it=functions.getExternalFunctions();
            while(it.hasNext()) {
                Function target=it.next();
                String n=target.getName();
                if(!relevant(n))continue;
                count++;
                ReferenceIterator uses=refs.getReferencesTo(target.getEntryPoint());
                int countRefs=0;
                while(uses.hasNext()) {
                    Reference r=uses.next();countRefs++;refsCount++;
                    Function parent=functions.getFunctionContaining(r.getFromAddress());
                    if(parent!=null && !parent.isExternal())
                        selected.put(parent.getEntryPoint().toString(),parent);
                    calls.println(n+"\t"+target.getEntryPoint()+"\t"+
                        r.getFromAddress()+"\t"+(parent==null?"":parent.getEntryPoint())+"\t"+
                        (parent==null?"":parent.getName()));
                }
                out.println("IMPORT "+n+" refs="+countRefs+" entry="+target.getEntryPoint());
            }
            out.println("RELEVANT_IMPORTS "+count+" TOTAL_XREFS "+refsCount);
            out.println("UNIQUE_DIRECT_CALLERS "+selected.size());
            int total=0;
            for(Function fn:selected.values()){
                if(total<140) out.println("CALLER "+fn.getEntryPoint()+" "+fn.getName());
                total++;
            }
        }
        ArrayList<Function> candidates=new ArrayList<>(selected.values());
        candidates.sort((a,b)->Long.compare(
            b.getBody().getNumAddresses(),a.getBody().getNumAddresses()));
        DecompInterface decomp=new DecompInterface();
        decomp.toggleCCode(true);decomp.toggleSyntaxTree(false);
        decomp.openProgram(currentProgram);
        try(PrintWriter out=new PrintWriter(new FileWriter(new File(directory,"decompiled-caller-sample.txt")))) {
            int n=0;
            for(Function f:candidates) {
                if(n>=28 || monitor.isCancelled())break;
                if(f.isExternal())continue;
                DecompileResults r=decomp.decompileFunction(f,35,monitor);
                out.println("\n==== "+f.getName()+" @ "+f.getEntryPoint()+" size="+f.getBody().getNumAddresses()+" ====");
                out.println("COMPLETE "+r.decompileCompleted()+" "+r.getErrorMessage());
                if(r.decompileCompleted() && r.getDecompiledFunction()!=null) {
                    String c=r.getDecompiledFunction().getC();
                    out.println(c.length()>18000?c.substring(0,18000)+"\nTRUNCATED":c);
                }
                n++;
            }
            println("CA01 DISPLAY completed decompilation of "+n+" functions");
        }
        decomp.dispose();
        println("CA01 DISPLAY SURVEY COMPLETE "+directory.getAbsolutePath());
    }
}
