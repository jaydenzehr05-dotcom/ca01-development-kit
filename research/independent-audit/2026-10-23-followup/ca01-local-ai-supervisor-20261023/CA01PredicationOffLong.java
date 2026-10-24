// @category CA01
// Static decompilation only. Writes generated research output outside the repository.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import com.google.gson.*;
import java.io.*;
import java.util.*;

// Targeted recovery only. Every address comes from SHA-bound failed original manifest.
// 120s per function (instead of 8s); output is separate, non-destructive.
public class CA01PredicationOffLong extends GhidraScript {
    public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=3)throw new IllegalArgumentException("new output directory, budget seconds, optional entry list required");
        File out=new File(args[0]);
        if(out.exists() || !out.mkdirs())throw new IOException("Output must be new: "+out);
        HashSet<String> selected=null;
        if(args.length==3){selected=new HashSet<>();try(BufferedReader r=new BufferedReader(new FileReader(args[2]))){String line;while((line=r.readLine())!=null)if(!line.isBlank())selected.add(toAddr(line.trim()).toString());}}
        long deadline=System.nanoTime()+Long.parseLong(args[1])*1000000000L;
        ArrayList<Function> functions=new ArrayList<>();
        FunctionIterator it=currentProgram.getFunctionManager().getFunctions(true);
        while(it.hasNext()){
            Function f=it.next();
            ghidra.program.model.mem.MemoryBlock b=currentProgram.getMemory().getBlock(f.getEntryPoint());
            ghidra.program.database.mem.AddressSourceInfo source=currentProgram.getMemory().getAddressSourceInfo(f.getEntryPoint());
            if((selected==null || selected.contains(f.getEntryPoint().toString())) && !f.isExternal() && b!=null && b.isExecute() && b.isInitialized() && !b.getName().equals("EXTERNAL") && source!=null && source.getFileOffset()>=0)functions.add(f);
        }
        // Startup/runtime exports and main first; retain remaining functions in address order.
        functions.sort((a,b)->{
            boolean x=priority(a.getName()),y=priority(b.getName());
            if(x!=y)return x?-1:1;
            return a.getEntryPoint().compareTo(b.getEntryPoint());
        });
        DecompInterface dec=new DecompInterface();
        dec.toggleCCode(true);dec.toggleSyntaxTree(false);DecompileOptions opts=new DecompileOptions();opts.setPredicate(false);dec.setOptions(opts);dec.openProgram(currentProgram);
        ArrayList<Map<String,Object>> rows=new ArrayList<>();int ok=0,failed=0,pending=0;
        try(PrintWriter code=new PrintWriter(new BufferedWriter(new FileWriter(new File(out,"decompiled.c"))));
            PrintWriter index=new PrintWriter(new FileWriter(new File(out,"functions.tsv")))){
            code.println("/* Ghidra C-like reconstruction, not original source or byte-exact recompilable C. */");
            code.println("/* Original executable SHA256: "+currentProgram.getExecutableSHA256()+" */");
            index.println("address\tname\tbytes\tstatus");
            for(Function f:functions){
                LinkedHashMap<String,Object> row=new LinkedHashMap<>();
                row.put("address",f.getEntryPoint().toString());row.put("name",f.getName());row.put("bytes",f.getBody().getNumAddresses());row.put("memory_block",currentProgram.getMemory().getBlock(f.getEntryPoint()).getName());
                ArrayList<String> calls=new ArrayList<>();
                for(Function target:f.getCalledFunctions(monitor)){
                    Function t=target.isThunk()?target.getThunkedFunction(true):target;
                    calls.add(target.getEntryPoint()+":"+target.getName()+(t!=null && t!=target?" -> "+t.getName():""));
                }
                Collections.sort(calls);row.put("calls",calls);
                String block=currentProgram.getMemory().getBlock(f.getEntryPoint()).getName();
                row.put("classification",block.equals(".plt")?"import_thunk":block.equals(".text")?"text_body":"other_executable");
                String status;
                if(System.nanoTime()>=deadline || monitor.isCancelled()){status="not_attempted_budget";pending++;}
                else {
                    DecompileResults r=dec.decompileFunction(f,360,monitor);
                    if(r.decompileCompleted() && r.getDecompiledFunction()!=null){
                        status="decompiled";ok++;
                        code.println("\n/* FUNCTION "+f.getEntryPoint()+" "+f.getName()+" bytes="+f.getBody().getNumAddresses()+" */");
                        code.println(r.getDecompiledFunction().getC());
                    } else {status="failed";failed++;row.put("error",r.getErrorMessage());}
                }
                row.put("status",status);rows.add(row);
                index.println(f.getEntryPoint()+"\t"+f.getName()+"\t"+f.getBody().getNumAddresses()+"\t"+status);
                if(rows.size()%250==0){code.flush();index.flush();println("CA01_PROGRESS "+currentProgram.getName()+" "+rows.size()+"/"+functions.size()+" ok="+ok+" failed="+failed+" pending="+pending);}
            }
        }finally{dec.dispose();}
        LinkedHashMap<String,Object> report=new LinkedHashMap<>();
        report.put("program",currentProgram.getName());report.put("sha256",currentProgram.getExecutableSHA256());
        report.put("language",currentProgram.getLanguageID().toString());report.put("image_base",currentProgram.getImageBase().toString());
        report.put("selection",args.length==3?"explicit entry list":"all discovered executable entries");report.put("functions_catalogued",functions.size());report.put("decompiled",ok);report.put("failed",failed);report.put("not_attempted",pending);
        report.put("limits","C-like static reconstruction; file-backed executable entries only, including real PLT thunks; automatic function discovery may be incomplete; decompiled does not mean semantically verified or original source.");
        TreeMap<String,TreeMap<String,Integer>> byKind=new TreeMap<>();
        for(Map<String,Object> row:rows)byKind.computeIfAbsent((String)row.get("classification"),k->new TreeMap<>()).merge((String)row.get("status"),1,Integer::sum);
        report.put("counts_by_kind",byKind);report.put("functions",rows);
        try(Writer w=new FileWriter(new File(out,"manifest.json"))){new GsonBuilder().setPrettyPrinting().create().toJson(report,w);}
        println("CA01_DECOMPILE_DONE "+currentProgram.getName()+" ok="+ok+" failed="+failed+" pending="+pending);
    }
    private boolean priority(String n){return n.equals("main") || n.equals("entry") || n.startsWith("rq_tsk_") || n.startsWith("fs_tsk_") || n.startsWith("rq_prc_") || n.startsWith("fc_sys_") || n.startsWith("fs_sys_") || n.startsWith("rq_sys_") || n.startsWith("SysPower") || n.startsWith("rq_msg_");}
}
