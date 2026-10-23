// @category CA01
// Read-only Ghidra xref/decompile survey for CA01 PROC_REPRO eMMC/EXT3 strings.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import java.io.*;
import java.util.*;
public class CA01ReproPartitionSurvey extends GhidraScript {
    private PrintWriter out;
    private void log(String s){out.println(s);println(s);}
    public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=1) throw new IllegalArgumentException("Output folder required");
        File output=new File(args[0]);output.mkdirs();
        ReferenceManager refs=currentProgram.getReferenceManager();
        FunctionManager funcs=currentProgram.getFunctionManager();
        AddressSpace as=currentProgram.getAddressFactory().getDefaultAddressSpace();
        String[] paths={"/dev/mmcblk0p1","/dev/mmcblk0p2",
            "/dev/mmcblk0p3","mkfs.ext3","/opt/ftl/cddb",
            "fsck -a /dev/mmcblk0p3;mount /dev/mmcblk0p3 /opt/ftl/cddb"};
        HashMap<String,Function> selected=new LinkedHashMap<>();
        try(PrintWriter w=new PrintWriter(new FileWriter(new File(output,"partition-survey.txt")))) {
            out=w;
            log("ORIGINAL_BINARY "+currentProgram.getName());
            log("LANGUAGE "+currentProgram.getLanguage().getLanguageID());
            log("FUNCTIONS "+funcs.getFunctionCount());
            Memory memory=currentProgram.getMemory();
            for(String path:paths) {
                byte[] needle=path.getBytes("US-ASCII");
                Address addr=memory.findBytes(memory.getMinAddress(),needle,null,true,monitor);
                if(addr==null){log("NO_STRING "+path);continue;}
                log("STRING "+path+" ADDRESS "+addr);
                ReferenceIterator xrefs=refs.getReferencesTo(addr);
                int n=0;
                while(xrefs.hasNext()){
                    Reference r=xrefs.next();n++;
                    Function f=funcs.getFunctionContaining(r.getFromAddress());
                    log("  XREF from "+r.getFromAddress()+" fn="+(f==null?"none":f.getName()+" "+f.getEntryPoint())+" type="+r.getReferenceType());
                    if(f!=null&&!f.isExternal())selected.put(f.getEntryPoint().toString(),f);
                }
                log("STRING_REF_COUNT "+path+" "+n);
            }
            log("SELECTED_FUNCTIONS "+selected.size());
        }
        DecompInterface decomp=new DecompInterface();
        decomp.toggleCCode(true);decomp.toggleSyntaxTree(false);
        decomp.openProgram(currentProgram);
        try(PrintWriter w=new PrintWriter(new FileWriter(new File(output,"partition-callers.c.txt")))) {
            int count=0;
            for(Function f:selected.values()){
                if(monitor.isCancelled()||count>=20)break;
                DecompileResults result=decomp.decompileFunction(f,45,monitor);
                w.println("\n=== "+f.getName()+" @ "+f.getEntryPoint()+" size="+f.getBody().getNumAddresses()+"===");
                w.println("COMPLETED "+result.decompileCompleted()+" ERR "+result.getErrorMessage());
                if(result.decompileCompleted()&&result.getDecompiledFunction()!=null){
                    String code=result.getDecompiledFunction().getC();
                    w.println(code.length()<60000?code:code.substring(0,60000));
                }
                count++;
            }
            println("DECOMPILED "+count);
        }
        decomp.dispose();
        println("PARTITION_GHIDRA_SURVEY_COMPLETE");
    }
}
