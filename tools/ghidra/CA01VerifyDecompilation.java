// @category CA01
// Verify exported function entries against the actual original file bytes.
import ghidra.app.script.GhidraScript;
import ghidra.program.database.mem.AddressSourceInfo;
import ghidra.program.model.address.Address;
import com.google.gson.*;
import java.io.*;
import java.util.*;
public class CA01VerifyDecompilation extends GhidraScript {
 public void run() throws Exception {
  String[] args=getScriptArgs();
  if(args.length!=3)throw new IllegalArgumentException("manifest, original ELF, new verification output required");
  File output=new File(args[2]);if(output.exists())throw new IOException("Output must be new");
  JsonObject manifest;
  try(Reader r=new FileReader(args[0])){manifest=JsonParser.parseReader(r).getAsJsonObject();}
  if(!manifest.get("sha256").getAsString().equals(currentProgram.getExecutableSHA256()))throw new IOException("Project hash mismatch");
  java.security.MessageDigest digest=java.security.MessageDigest.getInstance("SHA-256");
  try(InputStream input=new FileInputStream(args[1])){byte[] buffer=new byte[65536];int n;while((n=input.read(buffer))!=-1)digest.update(buffer,0,n);}
  if(!java.util.HexFormat.of().formatHex(digest.digest()).equals(currentProgram.getExecutableSHA256()))throw new IOException("Original file SHA-256 mismatch");
  TreeMap<String,TreeMap<String,Integer>> counts=new TreeMap<>();
  JsonArray rows=new JsonArray();
  try(RandomAccessFile file=new RandomAccessFile(args[1],"r")){
   for(JsonElement item:manifest.getAsJsonArray("functions")){
    JsonObject row=item.getAsJsonObject();Address address=toAddr(row.get("address").getAsString());
    AddressSourceInfo source=currentProgram.getMemory().getAddressSourceInfo(address);
    if(source==null || source.getFileOffset()<0 || source.getFileOffset()>=file.length())throw new IOException("Entry is not file-backed: "+address);
    file.seek(source.getFileOffset());int original=file.readUnsignedByte();
    if((source.getOriginalValue()&255)!=original || (currentProgram.getMemory().getByte(address)&255)!=original)throw new IOException("Original entry byte mismatch: "+address);
    String block=currentProgram.getMemory().getBlock(address).getName();
    String kind=block.equals(".plt")?"import_thunk":block.equals(".text")?"text_body":"other_executable";
    counts.computeIfAbsent(kind,k->new TreeMap<>()).merge(row.get("status").getAsString(),1,Integer::sum);
    row.addProperty("classification",kind);row.addProperty("original_file_offset",source.getFileOffset());
    row.addProperty("entry_byte_verified",true);rows.add(row);
   }
  }
  JsonObject result=new JsonObject();result.addProperty("program",currentProgram.getName());
  result.addProperty("sha256",currentProgram.getExecutableSHA256());
  result.add("counts_by_kind",new Gson().toJsonTree(counts));result.add("functions",rows);
  result.addProperty("limits","Original file backing and entry byte verified per function, not complete-body byte checks or semantic correctness. Import thunks are separate from text bodies.");
  try(Writer w=new FileWriter(output)){new GsonBuilder().setPrettyPrinting().create().toJson(result,w);}
  println("CA01_VERIFIED_EXPORT "+currentProgram.getName()+" "+counts);
 }
}
