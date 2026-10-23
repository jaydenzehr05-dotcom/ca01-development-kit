// @category CA01
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;
public class CA01MraFormat extends GhidraScript {
 public void run() throws Exception {
  DecompInterface d=new DecompInterface();d.openProgram(currentProgram);
  Set<Function> work=new LinkedHashSet<>();
  try(PrintWriter w=new PrintWriter(new FileWriter(getScriptArgs()[0]))){
   for(long a:new long[]{0x1264d4,0x639cc,0x5bdf4,0x62150,0x50838}){
    w.println("TARGET "+Long.toHexString(a));
    Function target=getFunctionAt(toAddr(a));if(target!=null)work.add(target);
    for(Reference ref:getReferencesTo(toAddr(a))){
     w.println("REF "+ref.getFromAddress()+" "+ref.getReferenceType());
     Function f=getFunctionContaining(ref.getFromAddress());
     if(f!=null)work.add(f);
     else for(Reference r:getReferencesTo(ref.getFromAddress())){
      Function f2=getFunctionContaining(r.getFromAddress());if(f2!=null)work.add(f2);
     }
    }
   }
   for(Function f:work){
    w.println("\nFUNCTION "+f.getEntryPoint()+" "+f.getName());
    for(Function c:f.getCalledFunctions(monitor))w.println("CALLEE "+c.getEntryPoint()+" "+c.getName());
    DecompileResults r=d.decompileFunction(f,40,monitor);if(r.decompileCompleted())w.println(r.getDecompiledFunction().getC());
   }
  }d.dispose();
 }
}
