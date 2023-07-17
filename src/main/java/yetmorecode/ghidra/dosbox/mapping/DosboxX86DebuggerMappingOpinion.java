package yetmorecode.ghidra.dosbox.mapping;

import java.util.Set;

import ghidra.app.plugin.core.debug.mapping.DebuggerMappingOffer;
import ghidra.app.plugin.core.debug.mapping.DebuggerMappingOpinion;
import ghidra.dbg.target.TargetEnvironment;
import ghidra.dbg.target.TargetObject;
import yetmorecode.ghidra.dosbox.model.objects.DosboxEnvironment;

public class DosboxX86DebuggerMappingOpinion implements DebuggerMappingOpinion {
	@Override
	public Set<DebuggerMappingOffer> offersForEnv(TargetEnvironment env, TargetObject target,
			boolean includeOverrides) {
		if (env.getDebugger().equals(DosboxEnvironment.DEBUGGER) &&
			env.getArchitecture().equals(DosboxEnvironment.ARCH) && 
			env.getEndian().equals(DosboxEnvironment.ENDIAN) && 
			env.getOperatingSystem().equals(DosboxEnvironment.OS)
		) {
			return Set.of(new DosboxX86DebuggerMappingOffer(target));
		}
		return Set.of();
	}
}