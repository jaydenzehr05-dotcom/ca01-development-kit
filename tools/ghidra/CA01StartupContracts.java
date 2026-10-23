import ghidra.app.script.GhidraScript;import ghidra.app.decompiler.*;import ghidra.program.model.listing.*;import java.io.*;import java.util.*;
public class CA01StartupContracts extends GhidraScript { public void run() throws Exception {
Set<String> wanted=new HashSet<>(Arrays.asList("fc_sys_SysPreInit","fc_sys_SysSynInit","fc_sys_SysInit","fc_sys_SysCyclic","fc_sys_RcvTskCond","fc_sys_RcvInitWait","tsk_sys_System","fc_sys_RtcStart","fc_sys_TskCondNosAcc","fc_sys_TskCondActAcc","fc_cnf_ChkModeChange", "fc_sys_AccStart","fs_prc_Init","fc_cnf_Init","fc_cnf_Main","fc_cnf_LoadTypPrc","fc_cnf_ReadyTypPrc","fc_sys_InitComAdr","fs_tsk_Init","rq_tsk_Create","rq_tsk_Start","rq_msg_Create","fs_sys_ExInit","fs_sys_PrcCreate","rq_flg_Create","rq_tim_Create","fs_sys_CnfEntry"));
DecompInterface d=new DecompInterface();d.openProgram(currentProgram);PrintWriter o=new PrintWriter(new FileWriter(getScriptArgs()[0]));
FunctionIterator fs=currentProgram.getFunctionManager().getFunctions(true);while(fs.hasNext()){Function f=fs.next();if(!wanted.contains(f.getName())||f.isExternal()||f.getBody().getNumAddresses()<20)continue;
o.println("FUNCTION "+f.getName()+" @ "+f.getEntryPoint());DecompileResults r=d.decompileFunction(f,50,monitor);if(r.decompileCompleted())o.println(r.getDecompiledFunction().getC());
InstructionIterator ins=currentProgram.getListing().getInstructions(f.getBody(),true);while(ins.hasNext()){Instruction i=ins.next();o.println(i.getAddress()+" "+i);}}
o.close();d.dispose();}}
