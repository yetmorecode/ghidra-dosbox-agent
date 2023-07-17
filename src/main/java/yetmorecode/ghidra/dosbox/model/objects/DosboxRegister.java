package yetmorecode.ghidra.dosbox.model.objects;

import java.util.List;
import java.util.Map;

import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetRegister;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(name = "RegisterDescriptor", elements = {
		@TargetElementType(type = Void.class) }, attributes = {
			@TargetAttributeType(type = Void.class) })
public class DosboxRegister 
	extends DefaultTargetObject<TargetObject, DosboxRegisters>
	implements TargetRegister {

	public DosboxRegister(AbstractDebuggerObjectModel model, DosboxRegisters parent, String key) {
		super(model, parent, PathUtils.makeKey(key), "Register");
		// TODO Auto-generated constructor stub
		
		changeAttributes(List.of(), List.of(), Map.of( //
			CONTAINER_ATTRIBUTE_NAME, parent, //
			BIT_LENGTH_ATTRIBUTE_NAME, 32, //
			DISPLAY_ATTRIBUTE_NAME, key,
			VALUE_ATTRIBUTE_NAME, 0x12
		), "Initialized");
	}

}
