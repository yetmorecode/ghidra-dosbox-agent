package yetmorecode.ghidra.dosbox.model;

import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetBreakpointLocation;
import ghidra.dbg.target.TargetObject;

public class DosboxBreakpoint 
	extends DefaultTargetObject<TargetObject, DosboxBreakpoints> 
	implements TargetBreakpointLocation {

	public DosboxBreakpoint(AbstractDebuggerObjectModel model, DosboxBreakpoints parent, String key, String typeHint) {
		super(model, parent, key, typeHint);
		// TODO Auto-generated constructor stub
	}


}
