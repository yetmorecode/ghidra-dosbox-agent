package yetmorecode.ghidra.dosbox.model.objects;

import java.util.List;
import java.util.Map;

import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetEnvironment;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(name = DosboxEnvironment.NAME)
public class DosboxEnvironment extends DefaultTargetObject<TargetObject, TargetObject> implements TargetEnvironment {

	public static final String NAME = "Environment";
	public static final String ARCH = "x86";
	public static final String OS = "dos4gw";
	public static final String ENDIAN = "little";
	public static final String DEBUGGER = "dosbox";
	
	public DosboxEnvironment(AbstractDebuggerObjectModel model, TargetObject parent) {
		super(model, parent, NAME, NAME);
		changeAttributes(List.of(), Map.of(
			DEBUGGER_ATTRIBUTE_NAME, DEBUGGER,
			ARCH_ATTRIBUTE_NAME, ARCH,
			OS_ATTRIBUTE_NAME, OS,
			ENDIAN_ATTRIBUTE_NAME, ENDIAN,
			DISPLAY_ATTRIBUTE_NAME, "Environment: " + DEBUGGER + " " + OS + " " + ARCH
		), "Initialized Environment");
	}
}
