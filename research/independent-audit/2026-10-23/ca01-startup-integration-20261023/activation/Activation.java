import ghidra.app.script.GhidraScript;import ghidra.app.decompiler.*;import ghidra.program.model.listing.*;import java.io.*;
public class Activation extends GhidraScript { public void run() throws Exception {
DecompInterface d=new DecompInterface();d.openProgram(currentProgram);PrintWriter o=new PrintWriter(new FileWriter(getScriptArgs()[0]));
FunctionIterator fs=currentProgram.getFunctionManager().getFunctions(true);while(fs.hasNext()){Function f=fs.next();if(!(f.getName().startsWith("fc_sys_")||f.getName().equals("fs_sys_SetSysMode"))||f.isExternal()||f.getBody().getNumAddresses()<20)continue;
o.println("FUNCTION "+f.getName()+" @ "+f.getEntryPoint());DecompileResults r=d.decompileFunction(f,50,monitor);if(r.decompileCompleted())o.println(r.getDecompiledFunction().getC());}
o.close();d.dispose();}}
