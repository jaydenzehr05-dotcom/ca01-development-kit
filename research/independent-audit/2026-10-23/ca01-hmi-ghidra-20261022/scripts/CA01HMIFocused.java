// @category CA01
// Focused Ghidra decompilation of recovered HMI startup/window/frame/message routines.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class CA01HMIFocused extends GhidraScript {
    private Address a(long v) {return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);}
    public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=1)throw new IllegalArgumentException("Output directory required");
        File outDir=new File(args[0]);outDir.mkdirs();
        long[] addresses={0x123eb8,0x2b66c,0x16094,0x2bb08,0x2b9fc,0x2b22c,0x2b054,
                          0x4054c,0x2a548,0x3d234,0x65df0,0xf694,0x15fb8,
                          0x2b70c,0x2b7e4,0x2bae8,0x2b944};
        DecompInterface dec=new DecompInterface();
        dec.toggleCCode(true);dec.toggleSyntaxTree(false);dec.openProgram(currentProgram);
        try(PrintWriter w=new PrintWriter(new FileWriter(new File(outDir,"focused-startup-window-message.txt")))){
            w.println("CA01 PROC_HMI focused Ghidra decompilation; import prototypes and global variable types incomplete");
            for(long address:addresses){
                Function f=currentProgram.getFunctionManager().getFunctionContaining(a(address));
                w.println("\n==== ADDR "+String.format("0x%08x",address)+" FUNCTION "+(f==null?"ABSENT":f.getName()+" entry="+f.getEntryPoint()));
                if(f==null || f.isExternal())continue;
                Set<Function> callees=f.getCalledFunctions(monitor);
                Set<Function> callers=f.getCallingFunctions(monitor);
                w.println("CALLED_FUNCTIONS "+callees.size()+" CALLERS "+callers.size());
                int n=0;for(Function x:callees){if(n++<75)w.println("CALLS "+x.getName()+" "+x.getEntryPoint());}
                n=0;for(Function x:callers){if(n++<35)w.println("CALLED_BY "+x.getName()+" "+x.getEntryPoint());}
                DecompileResults result=dec.decompileFunction(f,40,monitor);
                w.println("DECOMP_SUCCEEDED "+result.decompileCompleted()+" INFO "+result.getErrorMessage());
                if(result.decompileCompleted()&&result.getDecompiledFunction()!=null){
                    String s=result.getDecompiledFunction().getC();
                    w.println(s.length()>21000?s.substring(0,21000)+"\n/* truncated */":s);
                }
                println("FOCUSED_DECOMP "+f.getEntryPoint());
            }
            w.println("\n==== EGL CONFIG STATIC WORDS near 0x00296324");
            for(int i=0;i<16;i++){
                Address addr=a(0x296324+i*4);
                try{int val=currentProgram.getMemory().getInt(addr);
                    w.println(addr+" signed="+val+" hex=0x"+Integer.toHexString(val));}
                catch(Exception e){w.println(addr+" UNREADABLE "+e.getMessage());break;}
            }
        }
        dec.dispose();
        println("HMI_FOCUSED_COMPLETED");
    }
}
