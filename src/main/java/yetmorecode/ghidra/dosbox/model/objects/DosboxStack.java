package yetmorecode.ghidra.dosbox.model.objects;

import java.util.LinkedList;
import java.util.List;
import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetStack;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = DosboxStack.NAME,
	elements = { @TargetElementType(type = DosboxStackFrame.class) },
	canonicalContainer = true)
public class DosboxStack extends DefaultTargetObject<TargetObject, TargetObject> implements TargetStack {
	public static final String NAME = "Stack";
	
	public DosboxStack(AbstractDebuggerObjectModel model, TargetObject parent, String key, DosboxRegisterContainerAndBank regs) {
		super(model, parent, key, NAME);
		var frames = new LinkedList<DosboxStackFrame>();
		frames.push(new DosboxStackFrame(model, this, "0", Long.valueOf(0x10010)));
		changeElements(List.of(), frames, "Init");
	}
}
