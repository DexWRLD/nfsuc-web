import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.nio.file.*;
import java.io.*;
public class ExportMetadata extends GhidraScript {
 public void run() throws Exception {
  Path out=Path.of(getScriptArgs()[0]);
  try(PrintWriter p=new PrintWriter(Files.newBufferedWriter(out.resolve("metadata.txt")))) {
   p.println("language\t"+currentProgram.getLanguageID());
   var entries=currentProgram.getSymbolTable().getExternalEntryPointIterator();
   while(entries.hasNext()) p.println("entry\t"+entries.next());
   var imports=currentProgram.getFunctionManager().getExternalFunctions();
   while(imports.hasNext()){ var f=imports.next(); p.println("import\t"+f.getEntryPoint()+"\t"+f.getName()+"\t"+f.getSignature()); }
   AddressSet covered=new AddressSet();
   var functions=currentProgram.getFunctionManager().getFunctions(true);
   while(functions.hasNext()) {
    var f=functions.next();
    AddressSet overlap=covered.intersect(f.getBody());
    if(!overlap.isEmpty()) p.println("overlap\t"+f.getEntryPoint()+"\t"+overlap);
    covered.add(f.getBody());
   }
   for(var b:currentProgram.getMemory().getBlocks()) {
    p.println("block\t"+b.getName()+"\t"+b.getStart()+"\t"+b.getEnd()+"\t"+b.isExecute());
    if(b.isExecute()) {
     AddressSet remaining=new AddressSet(b.getStart(),b.getEnd()).subtract(covered);
     var ranges=remaining.getAddressRanges();
     while(ranges.hasNext()) {var range=ranges.next();p.println("unassigned_exec\t"+range.getMinAddress()+"\t"+range.getMaxAddress()+"\t"+range.getLength());}
    }
   }
   var data=currentProgram.getListing().getDefinedData(true);
   while(data.hasNext()) {var d=data.next();p.println("data\t"+d.getAddress()+"\t"+d.getLength()+"\t"+d.getDataType().getName()+"\t"+d.getDefaultLabelPrefix(null));}
  }
 }
}
