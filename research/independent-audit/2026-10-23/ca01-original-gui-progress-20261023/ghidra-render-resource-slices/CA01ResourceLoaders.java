// @category CA01
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;
public class CA01ResourceLoaders extends GhidraScript {
 public void run() throws Exception {
  DecompInterface d=new DecompInterface();d.openProgram(currentProgram);
  Set<Function> work=new LinkedHashSet<>();
  try(PrintWriter w=new PrintWriter(new FileWriter(getScriptArgs()[0]))){
   for(long a:new long[]{0x3eaf0,0x3ec98,0x3e41c,0x3bf44,0x4aa50,0x125f34,0x125a14}){
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
