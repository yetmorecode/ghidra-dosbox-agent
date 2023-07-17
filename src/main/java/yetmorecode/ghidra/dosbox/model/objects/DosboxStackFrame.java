package yetmorecode.ghidra.dosbox.model.objects;

import java.util.List;
import java.util.Map;

import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetStackFrame;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
		name = "StackFrame",
		elements = {
			@TargetElementType(type = Void.class) },
		attributes = {
			@TargetAttributeType(
					name = "Registers",
					type = DosboxRegisters.class,
					required = true,
					fixed = false),
			@TargetAttributeType(type = Void.class) })
public class DosboxStackFrame extends DefaultTargetObject<TargetObject, TargetObject> implements TargetStackFrame {

	private DosboxRegisters registers;
	
	public DosboxStackFrame(AbstractDebuggerObjectModel model, TargetObject parent, String key, String typeHint) {
		super(model, parent, PathUtils.makeKey(key), typeHint);
		// TODO Auto-generated constructor stub
		
		setAttributes(Map.of(
			PC_ATTRIBUTE_NAME, model.getAddressFactory().getDefaultAddressSpace().getAddress(0x10010),
			VALUE_ATTRIBUTE_NAME, 0x10010
			
		), "Init");
		
		registers = new DosboxRegisters(model, this);
		
		changeAttributes(List.of(), Map.of(
			"Registers", registers
		), "Dynamic");
	}

}
