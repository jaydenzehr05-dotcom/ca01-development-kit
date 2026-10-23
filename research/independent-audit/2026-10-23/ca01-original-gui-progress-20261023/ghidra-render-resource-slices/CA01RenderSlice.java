// @category CA01
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;
import java.util.*;
public class CA01RenderSlice extends GhidraScript {
 public void run() throws Exception {
  DecompInterface d=new DecompInterface();d.openProgram(currentProgram);
  Set<Function> work=new LinkedHashSet<>();
  for(long a:new long[]{0x1e0640,0x1e092c,0x1de9c0,0x16094}){
   Function f=getFunctionAt(toAddr(a));if(f!=null){work.add(f);work.addAll(f.getCallingFunctions(monitor));}}
  try(PrintWriter w=new PrintWriter(new FileWriter(getScriptArgs()[0]))){
   for(Function f:work){
    w.println("\nFUNCTION "+f.getEntryPoint()+" "+f.getName());
    for(Function c:f.getCallingFunctions(monitor))w.println("CALLER "+c.getEntryPoint()+" "+c.getName());
    DecompileResults r=d.decompileFunction(f,40,monitor);
    if(r.decompileCompleted())w.println(r.getDecompiledFunction().getC());
   }
  }d.dispose();
 }
}
