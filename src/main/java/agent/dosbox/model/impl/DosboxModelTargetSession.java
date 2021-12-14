package agent.dosbox.model.impl;

import ghidra.dbg.agent.DefaultTargetModelRoot;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
		name = "Dosbox",
		elements = {
			@TargetElementType(type = Void.class) },
		attributes = {
			@TargetAttributeType(type = Void.class) })
public class DosboxModelTargetSession extends DefaultTargetModelRoot {
	private DosboxModelImpl impl;
	
	public DosboxModelTargetSession(DosboxModelImpl impl, TargetObjectSchema schema) {
		super(impl, "Dosbox", schema);
		this.impl = impl;
	}

}
