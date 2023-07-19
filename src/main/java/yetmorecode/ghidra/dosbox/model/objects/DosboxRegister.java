package yetmorecode.ghidra.dosbox.model.objects;

import java.util.List;
import java.util.Map;

import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetRegister;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(name = DosboxRegister.NAME)
public class DosboxRegister extends DefaultTargetObject<TargetObject, DosboxRegisterContainerAndBank> implements TargetRegister {

	public static final String NAME = "Register";
	
	public DosboxRegister(AbstractDebuggerObjectModel model, DosboxRegisterContainerAndBank parent, String name) {
		this(model, parent, name, Long.valueOf(0));
	}
	
	public DosboxRegister(AbstractDebuggerObjectModel model, DosboxRegisterContainerAndBank parent, String name, Long value) {
		super(model, parent, PathUtils.makeKey(name), NAME);
		
		changeAttributes(List.of(), List.of(), Map.of( //
			CONTAINER_ATTRIBUTE_NAME, parent, //
			BIT_LENGTH_ATTRIBUTE_NAME, Integer.valueOf(32), //
			DISPLAY_ATTRIBUTE_NAME, name + " : " + Long.toHexString(value),
			VALUE_ATTRIBUTE_NAME, Long.toHexString(value),
			MODIFIED_ATTRIBUTE_NAME, false
		), "Initialized " + name + " = 0x" + Long.toHexString(value));
	}

}
