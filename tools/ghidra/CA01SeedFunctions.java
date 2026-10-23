// @category CA01
// Seed known ARM PLT slots and unwind-derived function candidates in a research project.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.io.*;
public class CA01SeedFunctions extends GhidraScript {
 public void run() throws Exception {
  String[] args=getScriptArgs();if(args.length!=1)throw new IllegalArgumentException("seed TSV required");
  int created=0,overlap=0;
  try(BufferedReader r=new BufferedReader(new FileReader(args[0]))){
   String line;
   while((line=r.readLine())!=null){
    if(line.isBlank())continue;
    String[] p=line.split("\\t");Address a=toAddr(p[0]);
    Function f=getFunctionAt(a);
    if(f==null){
     Function parent=getFunctionContaining(a);
     if(parent!=null){println("SEED_OVERLAP "+a+" parent="+parent.getEntryPoint());overlap++;continue;}
     disassemble(a);f=createFunction(a,null);
     if(f!=null)created++;
    }
    if(f!=null && p.length>1 && !p[1].equals("-"))f.setName(p[1],SourceType.ANALYSIS);
   }
  }
  println("SEED_DONE created="+created+" overlaps="+overlap);
 }
}
