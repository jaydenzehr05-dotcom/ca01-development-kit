import ghidra.app.script.GhidraScript;import ghidra.app.decompiler.*;import ghidra.program.model.listing.*;import java.io.*;
public class ActivationDetail extends GhidraScript { public void run() throws Exception {
DecompInterface d=new DecompInterface();d.openProgram(currentProgram);PrintWriter o=new PrintWriter(new FileWriter(getScriptArgs()[0]));
FunctionIterator fs=currentProgram.getFunctionManager().getFunctions(true);while(fs.hasNext()){Function f=fs.next();if(!(f.getName().startsWith("rq_sys_")||f.getName().startsWith("rq_tsk_")||f.getName().equals("fc_sys_SysOnCtl")||f.getName().equals("fc_sys_AccOnStop"))||f.isExternal()||f.getBody().getNumAddresses()<8)continue;
o.println("FUNCTION "+f.getName()+" @ "+f.getEntryPoint());DecompileResults r=d.decompileFunction(f,50,monitor);if(r.decompileCompleted())o.println(r.getDecompiledFunction().getC()); InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);while(it.hasNext()){Instruction ins=it.next();o.println(ins.getAddress()+" "+ins);}}
o.close();d.dispose();}}
