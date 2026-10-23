// Ghidra headless survey of the CA01 1127 Boot component.
// Deliberately does NOT invent entry points, execute code or modify firmware.
// Run on a temporary, raw binary import with explicit ARM language.
//@category CA01
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class CA01BootSurvey extends GhidraScript {
    private void out(PrintWriter w, String text) { w.println(text); println(text); }
    private int find(byte[] bytes,byte[] needle) {
        for(int i=0;i<=bytes.length-needle.length;i++) {
            boolean match=true;
            for(int j=0;j<needle.length;j++)if(bytes[i+j]!=needle[j]){match=false;break;}
            if(match)return i;
        }
        return -1;
    }
    public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=1)throw new IllegalArgumentException("One output report path required");
        File report=new File(args[0]);
        File parent=report.getParentFile();
        if(parent!=null)parent.mkdirs();
        try(PrintWriter w=new PrintWriter(new FileWriter(report))) {
            out(w,"CA01 RAW BOOT SURVEY (not proof of execution or valid entry point)");
            out(w,"Program: "+currentProgram.getName());
            out(w,"Language: "+currentProgram.getLanguage().getLanguageID());
            out(w,"Image base: "+currentProgram.getImageBase());
            out(w,"Functions recognized by analysis: "+currentProgram.getFunctionManager().getFunctionCount());
            int instCount=0;
            InstructionIterator ins=currentProgram.getListing().getInstructions(true);
            while(ins.hasNext()){ins.next();instCount++;}
            out(w,"Disassembled instructions recognized: "+instCount);
            for(MemoryBlock block:currentProgram.getMemory().getBlocks()){
                out(w,"Memory block: "+block.getName()+" "+block.getStart()+" size="+block.getSize()+" initialized="+block.isInitialized());
                if(!block.isInitialized() || block.getSize()>16*1024*1024)continue;
                byte[] bytes=new byte[(int)block.getSize()];
                int loaded=currentProgram.getMemory().getBytes(block.getStart(),bytes);
                String[] markers={"U-Boot 2010.09","bootcmd=run sd_boot","root_emmc=root=",
                    "sd_lboot=run sl_set","rollback stat =","uImage_T_DAB_US_1M",
                    "system failed","boot_sh: SH IMAGE"};
                for(String marker:markers) {
                    int off=find(bytes,marker.getBytes(StandardCharsets.US_ASCII));
                    if(off>=0)out(w,"STRING marker="+marker+" first_offset=0x"+Integer.toHexString(off)+
                        " address="+block.getStart().add(off));
                    else out(w,"STRING marker="+marker+" NOT FOUND");
                }
                out(w,"Inspected bytes="+loaded);
            }
            FunctionIterator functions=currentProgram.getFunctionManager().getFunctions(true);
            int n=0;
            while(functions.hasNext() && n<25){
                Function f=functions.next();
                out(w,"FUNCTION "+f.getEntryPoint()+" "+f.getName()+" length="+f.getBody().getNumAddresses());
                n++;
            }
            out(w,"Reminder: the selected ARM language and raw base are hypotheses, not a known CA01 load mapping.");
        }
    }
}
