package yetmorecode.ghidra.dosbox.mapping;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.plugin.core.debug.service.model.launch.AbstractDebuggerProgramLaunchOffer;
import ghidra.app.plugin.core.debug.service.model.launch.DebuggerProgramLaunchOffer;
import ghidra.app.plugin.core.debug.service.model.launch.DebuggerProgramLaunchOpinion;
import ghidra.app.services.DebuggerModelService;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public class DosboxDebuggerProgramLaunchOpinion implements DebuggerProgramLaunchOpinion {
	protected static class DosboxProgramLaunchOffer
	extends AbstractDebuggerProgramLaunchOffer {

		public DosboxProgramLaunchOffer(Program program, PluginTool tool, DebuggerModelFactory factory) {
			super(program, tool, factory);
		}

		@Override
		public String getConfigName() {
			return "dosbox";
		}

		@Override
		public String getMenuTitle() {
			return "in DOSBOX locally via TCP";
		}
	}
	
	
	@Override
	public Collection<DebuggerProgramLaunchOffer> getOffers(Program program, PluginTool tool,
			DebuggerModelService service) {
		String exe = program.getExecutablePath();
		if (exe == null || "".equals(exe.trim())) {
			return List.of();
		}
		List<DebuggerProgramLaunchOffer> offers = new ArrayList<>();
		for (DebuggerModelFactory factory : service.getModelFactories()) {
			if (!factory.isCompatible()) {
				continue;
			}
			String clsName = factory.getClass().getName();
			if (clsName.equals("yetmorecode.ghidra.dosbox.DosboxDebuggerModelFactory")) {
				offers.add(new DosboxProgramLaunchOffer(program, tool, factory));		
			}
		}
		
		return offers;
	}

}
