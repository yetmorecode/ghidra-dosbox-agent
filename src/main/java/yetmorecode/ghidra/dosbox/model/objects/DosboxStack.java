package yetmorecode.ghidra.dosbox.model.objects;

import java.util.List;
import java.util.Map;

import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetStack;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
		name = "Stack",
		elements = {
			@TargetElementType(type = DosboxStackFrame.class) },
		attributes = {
			@TargetAttributeType(type = Void.class) },
		canonicalContainer = true)
public class DosboxStack extends DefaultTargetObject<TargetObject, DosboxModelRoot> implements TargetStack {

	
	
	public DosboxStack(AbstractDebuggerObjectModel model, DosboxModelRoot parent, String key, String typeHint) {
		super(model, parent, key, typeHint);
		// TODO Auto-generated constructor stub
		
		var f1 = new DosboxStackFrame(model, this, "10030", "frameA");
		
		setElements(List.of(f1), "Init");
	}
	
	

}
