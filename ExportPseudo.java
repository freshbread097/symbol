// Ghidra post-script used by server.py.
// Writes a simple, line-oriented function/pseudocode file that Python can parse.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.PrintWriter;

public class ExportPseudo extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException("Output path is required");
        PrintWriter out = new PrintWriter(args[0], "UTF-8");

        DecompInterface decomp = new DecompInterface();
        decomp.toggleCCode(true);
        decomp.openProgram(currentProgram);
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            try {
                DecompileResults r = decomp.decompileFunction(f, 60, monitor);
                if (!r.decompileCompleted() || r.getDecompiledFunction() == null) continue;
                String c = r.getDecompiledFunction().getC();
                if (c == null || c.trim().isEmpty()) continue;
                out.println("@@FUNC@@\t" + f.getEntryPoint() + "\t" + f.getName());
                out.println(c);
            } catch (Exception ignored) {
                // One problematic function should not prevent the rest of the binary from being exported.
            }
        }
        out.flush();
        out.close();
        decomp.dispose();
    }
}
