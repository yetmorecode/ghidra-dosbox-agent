package yetmorecode.ghidra.dosbox.mapping;

import java.util.Set;

import ghidra.app.plugin.core.debug.mapping.DefaultDebuggerMappingOffer;
import ghidra.dbg.target.TargetObject;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;

public class DosboxX86DebuggerMappingOffer extends DefaultDebuggerMappingOffer {
	public DosboxX86DebuggerMappingOffer(TargetObject target) {
		super(target, 100, "dosbox", new LanguageID("x86:LE:32:default"), new CompilerSpecID("gcc"), Set.of());
	}
}
