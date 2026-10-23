// @category CA01
// Ghidra decompilation of recovered Fujitsu Ten system library; static analysis only.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.io.*;
import java.util.*;

public class CA01SystemStartup extends GhidraScript {
    public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=1)throw new IllegalArgumentException("Output directory required");
        File outDir=new File(args[0]);outDir.mkdirs();
        String[] names={"SysPowerOn","fs_sys_CnfEntry","fs_cnf_Load","fs_prc_Init","fs_sys_InitCom","fs_tsk_Init","fs_ipc_Init","fs_shm_Init","fs_psm_Init"};
        HashSet<String> wanted=new HashSet<>(Arrays.asList(names));
        DecompInterface dec=new DecompInterface();
        dec.toggleCCode(true);dec.toggleSyntaxTree(false);dec.openProgram(currentProgram);
        int count=0;
        try(PrintWriter w=new PrintWriter(new FileWriter(new File(outDir,"system-startup-decompiled.txt")))){
            w.println("CA01 System Library Startup Static Decompiled Analysis");
            w.println("program="+currentProgram.getName());
            w.println("functionCount="+currentProgram.getFunctionManager().getFunctionCount());
            FunctionIterator it=currentProgram.getFunctionManager().getFunctions(true);
            while(it.hasNext()){
                Function f=it.next();
                if(!wanted.contains(f.getName()) || f.isExternal())continue;
                w.println("\n==== "+f.getName()+" AT "+f.getEntryPoint()+" body="+f.getBody().getNumAddresses());
                Set<Function> calls=f.getCalledFunctions(monitor);
                int n=0;
                for(Function callee:calls){if(n<110)w.println("CALLS "+callee.getName()+" "+callee.getEntryPoint());n++;}
                w.println("CALL_COUNT "+n);
                DecompileResults result=dec.decompileFunction(f,55,monitor);
                w.println("DECOMP_OK "+result.decompileCompleted()+" ERROR "+result.getErrorMessage());
                if(result.decompileCompleted() && result.getDecompiledFunction()!=null){
                    String c=result.getDecompiledFunction().getC();
                    w.println(c.length()>36000?c.substring(0,36000)+"\n/* truncated */":c);
                }
                count++;
                println("SYSTEM_DECOMPILED "+f.getName()+" "+count);
            }
        }
        dec.dispose();
        println("SYSTEM_STARTUP_DONE "+count);
    }
}
