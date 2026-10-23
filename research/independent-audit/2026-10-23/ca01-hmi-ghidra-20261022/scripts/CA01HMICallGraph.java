// @category CA01
// Read-only ARM GUI call graph / decompilation. Never execute recovered firmware.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;
import java.io.*;

public class CA01HMICallGraph extends GhidraScript {
    private boolean inTarget(String s) {
        return s.startsWith("egl") || s.startsWith("glDraw") || s.equals("glViewport")
           || s.equals("glClear") || s.equals("glTexImage2D") || s.equals("glBindTexture")
           || s.equals("glGenTextures") || s.startsWith("rq_msg_")
           || s.startsWith("rq_ipc_") || s.startsWith("sysDisMng")
           || s.startsWith("disHmi") || s.startsWith("uieIni");
    }
    private void add(LinkedHashMap<String,Function> map,Function f){
        if(f!=null && !f.isExternal())map.putIfAbsent(f.getEntryPoint().toString(),f);
    }
    public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=1)throw new IllegalArgumentException("Output directory required");
        File out=new File(args[0]);out.mkdirs();
        FunctionManager fm=currentProgram.getFunctionManager();
        ReferenceManager rm=currentProgram.getReferenceManager();
        LinkedHashMap<String,Function> selected=new LinkedHashMap<>();
        Address mainAddr=currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x123eb8);
        add(selected,fm.getFunctionAt(mainAddr));
        add(selected,fm.getFunctionContaining(mainAddr));
        try(PrintWriter w=new PrintWriter(new FileWriter(new File(out,"call-graph.txt")));
            PrintWriter refs=new PrintWriter(new FileWriter(new File(out,"plt-xrefs.tsv")))){
            refs.println("target\tplt_address\tfrom_address\tcaller_address\tcaller_name");
            w.println("CA01 PROC_HMI CALL-GRAPH: Ghidra analyzed code references, not runtime proof");
            w.println("FUNCTIONS "+fm.getFunctionCount());
            w.println("MAIN_FROM__LIBC_START_MAIN "+mainAddr+" function="+fm.getFunctionContaining(mainAddr));
            FunctionIterator it=fm.getFunctions(true);
            int targetCount=0;
            while(it.hasNext()){
                Function f=it.next();
                if(f.isExternal())continue;
                String name=f.getName();
                if(!inTarget(name))continue;
                targetCount++;
                ReferenceIterator rit=rm.getReferencesTo(f.getEntryPoint());
                LinkedHashMap<String,Function> callers=new LinkedHashMap<>();
                int nref=0;
                while(rit.hasNext()){
                    Reference ref=rit.next();nref++;
                    Function caller=fm.getFunctionContaining(ref.getFromAddress());
                    if(caller!=null && !caller.isExternal()){
                        callers.putIfAbsent(caller.getEntryPoint().toString(),caller);
                        refs.println(name+"\t"+f.getEntryPoint()+"\t"+ref.getFromAddress()+"\t"+
                            caller.getEntryPoint()+"\t"+caller.getName());
                    }
                }
                w.println("TARGET "+name+" PLT="+f.getEntryPoint()+" REF_COUNT="+nref+
                    " DIRECT_CALLERS="+callers.size());
                int cnt=0;
                for(Function caller:callers.values()){
                    if(cnt<28)w.println("  CALLER "+caller.getEntryPoint()+" "+caller.getName()+
                        " SIZE="+caller.getBody().getNumAddresses());
                    if(cnt<8 && selected.size()<150)add(selected,caller);
                    cnt++;
                }
            }
            w.println("TARGET_FUNCTIONS "+targetCount);
            w.println("DECOMP_CANDIDATES "+selected.size());
        }
        DecompInterface iface=new DecompInterface();
        iface.toggleCCode(true);iface.toggleSyntaxTree(false);
        iface.openProgram(currentProgram);
        try(PrintWriter w=new PrintWriter(new FileWriter(new File(out,"decompiled-graphics-main.txt")))){
            int count=0;
            for(Function f:selected.values()){
                if(count>=65 || monitor.isCancelled())break;
                if(f.getBody().getNumAddresses()>23000)continue;
                DecompileResults result=iface.decompileFunction(f,35,monitor);
                w.println("\n===== DECOMP "+f.getEntryPoint()+" "+f.getName()+
                    " ADDRESSES="+f.getBody().getNumAddresses()+" =====");
                w.println("SUCCESS "+result.decompileCompleted()+" ERROR "+result.getErrorMessage());
                if(result.decompileCompleted() && result.getDecompiledFunction()!=null){
                    String c=result.getDecompiledFunction().getC();
                    w.println(c.length()>22000?c.substring(0,22000)+"\n/* truncated */":c);
                }
                count++;
                if(count%10==0)println("DECOMP_PROGRESS "+count);
            }
            println("CALL_GRAPH_DECOMP_DONE "+count);
        }
        iface.dispose();
        println("CA01_HMI_CALL_GRAPH_COMPLETE "+out);
    }
}
