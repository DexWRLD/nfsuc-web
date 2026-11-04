import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class ExportUndercover extends GhidraScript {
    String clean(String s) { return s.replace('\t',' ').replace('\n',' ').replace('\r',' '); }
    String addresses(Set<Function> fs) {
        TreeSet<String> result = new TreeSet<>();
        for (Function f : fs) result.add(f.getEntryPoint().toString());
        return String.join(",", result);
    }
    public void run() throws Exception {
        String sha = currentProgram.getExecutableSHA256();
        if (!"6b10551649fd70fa630bd7454fd953f51555fa2dd2112faae84ac8ca97844bcd".equalsIgnoreCase(sha))
            throw new IOException("Unexpected executable SHA " + sha);
        Path out = Path.of(getScriptArgs()[0]);
        DecompInterface dec = new DecompInterface();
        dec.toggleCCode(true);
        dec.toggleSyntaxTree(false);
        if (!dec.openProgram(currentProgram)) throw new IOException(dec.getLastMessage());
        try (PrintWriter c = new PrintWriter(Files.newBufferedWriter(out.resolve("nfs_undercover_full_decompile.c")));
             PrintWriter rows = new PrintWriter(Files.newBufferedWriter(out.resolve("functions.tsv")))) {
            c.println("/* Ghidra 12.2 saved analysis UndercoverResearch:/nfs.exe");
            c.println(" * SHA-256 " + sha.toLowerCase() + " | PE32 x86 | image base " + currentProgram.getImageBase());
            c.println(" * ExportUndercover.java | address order | recovered signatures, types and symbol references");
            c.println(" * Reference pseudocode. External definitions and unresolved state require separate recovery. */");
            var it = currentProgram.getFunctionManager().getFunctions(true);
            int n=0;
            while (it.hasNext()) {
                monitor.checkCancelled();
                Function f=it.next();
                String a=f.getEntryPoint().toString(), status="unavailable", reason="", body="";
                if (f.isThunk()) {
                    status="thunk"; Function target=f.getThunkedFunction(false);
                    reason=target == null ? "Unresolved thunk" : "Thunk to " + target.getEntryPoint() + " " + target.getName();
                } else {
                    try {
                        DecompileResults r=dec.decompileFunction(f,15,monitor);
                        if (r.decompileCompleted() && r.getDecompiledFunction()!=null) {
                            body=r.getDecompiledFunction().getC();
                            if (!body.isBlank()) status="decompiled"; else reason="Empty decompiler result";
                        } else reason=r.getErrorMessage();
                    } catch (Exception e) { reason=e.toString(); }
                }
                TreeSet<String> imports=new TreeSet<>(), indirect=new TreeSet<>();
                var ii=currentProgram.getListing().getInstructions(f.getBody(),true);
                while(ii.hasNext()) {
                    var inst=ii.next();
                    if(inst.getFlowType().isCall() && inst.getFlowType().isComputed()) indirect.add(inst.getAddress().toString());
                    if(inst.getFlowType().isCall()) for(var ref:inst.getReferencesFrom())
                        if(ref.isExternalReference()) imports.add(ref.getToAddress().toString());
                }
                String callers=addresses(f.getCallingFunctions(monitor)), callees=addresses(f.getCalledFunctions(monitor));
                rows.println(String.join("\t", a, clean(f.getName()), status, f.getBody().getMinAddress().toString(),
                    f.getBody().getMaxAddress().toString(), f.getCallingConventionName(), callers, callees,
                    clean(reason == null ? "" : reason), String.join(",",indirect),String.join(",",imports),
                    Long.toString(f.getBody().getNumAddresses())));
                c.println("\n/* UC_FUNCTION " + a + " " + f.getName() + " | " + status + " */");
                if(status.equals("decompiled")) c.println(body);
                else c.println("/* Body unavailable: " + clean(reason == null ? "" : reason).replace("*/","* /") + " */");
                if(++n % 1000 == 0) { c.flush(); rows.flush(); println("Exported " + n); }
            }
            println("Total " + n);
        } finally { dec.dispose(); }
    }
}
