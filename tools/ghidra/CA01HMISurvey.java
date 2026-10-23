// @category CA01
// Static firmware provenance only: never executes the recovered program.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import java.io.*;
import java.util.*;

public class CA01HMISurvey extends GhidraScript {
    private boolean relevant(String s) {
        return s.startsWith("egl") || (s.startsWith("gl") && s.length()>2 && Character.isUpperCase(s.charAt(2)))
          || s.startsWith("vg") || s.startsWith("rq_") || s.startsWith("uie")
          || s.startsWith("sysDis") || s.startsWith("dis") || s.startsWith("gdr")
          || s.startsWith("task") || s.startsWith("pthread") || s.startsWith("X");
    }
    private void log(PrintWriter w,String s){ w.println(s); println(s); }
    private String clean(String v) {return v.replace("\n"," ").replace("\r"," ");}
    public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=1)throw new IllegalArgumentException("Output directory needed");
        File outDir=new File(args[0]);outDir.mkdirs();
        FunctionManager fm=currentProgram.getFunctionManager();
        ReferenceManager rm=currentProgram.getReferenceManager();
        ArrayList<Function> selected=new ArrayList<>();
        HashSet<String> seen=new HashSet<>();
        try(PrintWriter w=new PrintWriter(new FileWriter(new File(outDir,"survey.txt")));
            PrintWriter refsOut=new PrintWriter(new FileWriter(new File(outDir,"references.tsv")))) {
            log(w,"PROGRAM "+currentProgram.getName());
            log(w,"LANG "+currentProgram.getLanguage().getLanguageID());
            log(w,"BASE "+currentProgram.getImageBase());
            log(w,"FUNC_COUNT "+fm.getFunctionCount());
            log(w,"ENTRY_SET "+currentProgram.getSymbolTable().getExternalEntryPointIterator().hasNext());
            for(MemoryBlock b:currentProgram.getMemory().getBlocks())log(w,"BLOCK "+b.getName()+" start="+b.getStart()+" size="+b.getSize());
            Address elfEntry=currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0xd8f8);
            Function entryFunc=fm.getFunctionContaining(elfEntry);
            log(w,"ELF_ENTRY "+elfEntry+" FUNC "+(entryFunc==null?"NONE":entryFunc.getName()+" "+entryFunc.getEntryPoint()));
            if(entryFunc!=null){selected.add(entryFunc);seen.add(entryFunc.getEntryPoint().toString());}
            String[] special={"main","_start","__libc_start_main","eglGetDisplay","eglInitialize","eglChooseConfig","eglCreateContext","eglCreateWindowSurface","eglCreatePbufferSurface","eglMakeCurrent","eglSwapBuffers","eglGetProcAddress","glViewport","glDrawArrays","glClear","vgCreatePaint","vgDrawPath","rq_msg_Receive","rq_ipc_Send","uieCtlPrcApiNty","sysDisMngEnd"};
            refsOut.println("callee\tcallee_address\tfrom\tcaller\tcaller_entry");
            int extCount=0;int relevantCount=0;int referenceCount=0;
            FunctionIterator extern=fm.getExternalFunctions();
            while(extern.hasNext()){
                Function ef=extern.next(); extCount++;
                if(!relevant(ef.getName())) continue;
                relevantCount++;
                StringBuilder callers=new StringBuilder();
                Address target=ef.getEntryPoint();
                ReferenceIterator it=rm.getReferencesTo(target);
                int n=0;
                while(it.hasNext()){
                    Reference ref=it.next();
                    Function caller=fm.getFunctionContaining(ref.getFromAddress());
                    n++;referenceCount++;
                    if(n<=6)callers.append(" ").append(ref.getFromAddress()).append(":").append(caller==null?"?":caller.getName());
                    refsOut.println(ef.getName()+"\t"+target+"\t"+ref.getFromAddress()+"\t"+(caller==null?"":caller.getName())+"\t"+(caller==null?"":caller.getEntryPoint()));
                    if(caller!=null && !caller.isExternal() && selected.size()<120 && seen.add(caller.getEntryPoint().toString()))selected.add(caller);
                }
                log(w,"IMPORT "+ef.getName()+" AT "+target+" xrefs="+n+callers);
            }
            log(w,"TOTAL_EXTERNAL "+extCount+" RELEVANT "+relevantCount+" REFERENCES "+referenceCount+" CALLERS "+selected.size());
            for(String name:special) {
                SymbolIterator sit=currentProgram.getSymbolTable().getSymbols(name);
                int n=0;
                while(sit.hasNext() && n<5){
                    Symbol s=sit.next();n++;
                    log(w,"SYMBOL "+name+" AT "+s.getAddress()+" TYPE "+s.getSymbolType()+" EXTERNAL "+s.isExternal());
                    ReferenceIterator rit=rm.getReferencesTo(s.getAddress());
                    int nr=0;
                    while(rit.hasNext()){
                        Reference ref=rit.next();
                        Function caller=fm.getFunctionContaining(ref.getFromAddress());
                        nr++;
                        if(nr<=8)log(w,"  FROM "+ref.getFromAddress()+" "+(caller==null?"?":caller.getName()+" "+caller.getEntryPoint()));
                        if(caller!=null && !caller.isExternal() && selected.size()<130 && seen.add(caller.getEntryPoint().toString()))selected.add(caller);
                    }
                    log(w,"SYMBOL_REFS "+name+" "+nr);
                }
            }
            FunctionIterator all=fm.getFunctions(true);int names=0;
            while(all.hasNext()){Function f=all.next();String name=f.getName();if(!name.startsWith("FUN_") && !name.startsWith("thunk_")){
                if(names<110)log(w,"NAMED_FUNCTION "+f.getEntryPoint()+" "+name);
                names++;
                if(name.equals("main") && seen.add(f.getEntryPoint().toString()))selected.add(0,f);
            }}
            log(w,"NAMED_TOTAL "+names);
            log(w,"DECOMP_CANDIDATES "+selected.size());
        }
        DecompInterface iface=new DecompInterface();
        iface.toggleCCode(true);iface.toggleSyntaxTree(false);
        iface.openProgram(currentProgram);
        try(PrintWriter dec=new PrintWriter(new FileWriter(new File(outDir,"decompiled-selected.txt")))){
            int n=0;
            for(Function f:selected){
                if(n>=48 || monitor.isCancelled())break;
                if(f.isExternal())continue;
                DecompileResults result=iface.decompileFunction(f,70,monitor);
                dec.println("\n\n===== "+f.getName()+" @ "+f.getEntryPoint()+" size="+f.getBody().getNumAddresses()+" =====");
                dec.println("VALID "+result.decompileCompleted()+" MESSAGE "+clean(result.getErrorMessage()));
                if(result.decompileCompleted() && result.getDecompiledFunction()!=null){
                    String c=result.getDecompiledFunction().getC();
                    dec.println(c.length()>24000?c.substring(0,24000)+"\n/* truncated */":c);
                }
                n++; if(n%7==0)println("DECOMPILED "+n);
            }
            println("COMPLETE_DECOMP "+n);
        }
        iface.dispose();
        println("SURVEY_COMPLETE "+outDir);
    }
}
