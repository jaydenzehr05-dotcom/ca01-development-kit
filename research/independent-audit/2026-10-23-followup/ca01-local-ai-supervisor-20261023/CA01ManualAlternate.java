// @category CA01
// Manual, independent static recovery; never modifies original firmware or repository.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import com.google.gson.*;
import java.io.*;
import java.util.*;

public class CA01ManualAlternate extends GhidraScript {
    public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=2)throw new IllegalArgumentException("New output directory and address-list file required");
        File output=new File(args[0]);
        if(output.exists() || !output.mkdirs())throw new IOException("Output must be new "+output);
        ArrayList<String> targets=new ArrayList<>();
        try(BufferedReader in=new BufferedReader(new FileReader(args[1]))) {
            String line;
            while((line=in.readLine())!=null)if(!line.isBlank())targets.add(toAddr(line.trim()).toString());
        }
        ArrayList<Map<String,Object>> rows=new ArrayList<>();
        int ok=0, failed=0;
        String[] styles={"decompile","normalize","firstpass","register"};
        DecompInterface di=new DecompInterface();
        di.toggleCCode(true);
        di.toggleSyntaxTree(true);
        if(!di.openProgram(currentProgram))throw new IllegalStateException("Ghidra cannot open program");
        try(PrintWriter code=new PrintWriter(new BufferedWriter(new FileWriter(new File(output,"decompiled.c"))));
            PrintWriter asm=new PrintWriter(new BufferedWriter(new FileWriter(new File(output,"assembly.txt"))));
            PrintWriter tsv=new PrintWriter(new FileWriter(new File(output,"functions.tsv")))) {
            code.println("/* C-like outputs from Ghidra alternate processing styles; not original factory source. */");
            code.println("/* Original executable SHA256: "+currentProgram.getExecutableSHA256()+" */");
            tsv.println("address\tname\tbytes\tstatus");
            for(String addrtext:targets) {
                Address addr=toAddr(addrtext);
                Function fn=currentProgram.getFunctionManager().getFunctionAt(addr);
                LinkedHashMap<String,Object> row=new LinkedHashMap<>();
                row.put("address",addr.toString());
                row.put("name",fn==null?"UNDISCOVERED_"+addrtext:fn.getName());
                row.put("bytes",fn==null?0:fn.getBody().getNumAddresses());
                MemoryBlock b=currentProgram.getMemory().getBlock(addr);
                String bn=b==null?"unknown":b.getName();
                row.put("memory_block",bn);
                row.put("classification",bn.equals(".text")?"text_body":bn.equals(".plt")?"import_thunk":"other_executable");
                row.put("calls",new ArrayList<String>());
                ArrayList<String> errors=new ArrayList<>();
                boolean success=false;
                if(fn!=null) {
                    asm.println("### "+addrtext+" "+fn.getName());
                    InstructionIterator ins=currentProgram.getListing().getInstructions(fn.getBody(),true);
                    int limit=0;
                    while(ins.hasNext() && limit++<20000) {
                        Instruction i=ins.next();
                        asm.println(i.getAddress()+" "+i.toString());
                    }
                    for(String style:styles) {
                        if(!di.setSimplificationStyle(style)) {
                            errors.add(style+": setting rejected");
                            continue;
                        }
                        try {
                            DecompileResults result=di.decompileFunction(fn,90,monitor);
                            if(result.decompileCompleted() && result.getDecompiledFunction()!=null) {
                                String c=result.getDecompiledFunction().getC();
                                if(c!=null && c.length()>20) {
                                    code.println("\n/* FUNCTION "+addr+" "+fn.getName()+" bytes="+fn.getBody().getNumAddresses()+" */");
                                    code.println("/* Ghidra simplification style: "+style+" */");
                                    code.println(c);
                                    row.put("decompile_style",style);
                                    success=true;
                                    break;
                                }
                            }
                            errors.add(style+": "+result.getErrorMessage());
                        } catch(Exception ex) {
                            errors.add(style+": "+ex.getClass().getSimpleName()+": "+ex.getMessage());
                        }
                        di.flushCache();
                    }
                } else {
                    errors.add("Ghidra did not discover this entrypoint in isolated import");
                }
                row.put("errors_by_style",errors);
                if(success) {
                    row.put("status","decompiled");
                    ok++;
                } else {
                    row.put("status","failed");
                    row.put("error",String.join(" | ",errors));
                    failed++;
                }
                rows.add(row);
                tsv.println(addr+"\t"+row.get("name")+"\t"+row.get("bytes")+"\t"+row.get("status"));
                println("CA01_ALT_PROGRESS "+addr+" "+row.get("status"));
            }
        } finally {
            di.dispose();
        }
        LinkedHashMap<String,Object> manifest=new LinkedHashMap<>();
        manifest.put("program",currentProgram.getName());
        manifest.put("sha256",currentProgram.getExecutableSHA256());
        manifest.put("selection","explicit failed entry addresses; Ghidra alternate decompiler styles");
        manifest.put("functions_catalogued",targets.size());
        manifest.put("decompiled",ok);
        manifest.put("failed",failed);
        manifest.put("not_attempted",0);
        manifest.put("functions",rows);
        manifest.put("limitations","Successful output is Ghidra pseudocode, not original source; fallback assembly is not a successful decompilation");
        try(Writer out=new FileWriter(new File(output,"manifest.json"))) {
            new GsonBuilder().setPrettyPrinting().create().toJson(manifest,out);
        }
        println("CA01_ALT_DONE ok="+ok+" failed="+failed);
    }
}
