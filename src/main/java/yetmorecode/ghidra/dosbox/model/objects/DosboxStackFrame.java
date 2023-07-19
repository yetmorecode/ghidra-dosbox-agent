package yetmorecode.ghidra.dosbox.model.objects;

import java.util.Map;

import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetStackFrame;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(name = DosboxStackFrame.NAME)
public class DosboxStackFrame extends DefaultTargetObject<TargetObject, DosboxStack> implements TargetStackFrame {

	public static final String NAME = "StackFrame";
	
	public DosboxStackFrame(AbstractDebuggerObjectModel model, DosboxStack parent, String key, Long pc) {
		super(model, parent, PathUtils.makeKey(key), NAME);
		setAttributes(Map.of(
			PC_ATTRIBUTE_NAME, model.getAddressFactory().getDefaultAddressSpace().getAddress(pc),
			VALUE_ATTRIBUTE_NAME, Long.toHexString(pc),
			DISPLAY_ATTRIBUTE_NAME, "frame @" + Long.toHexString(pc)
		), "Init");
	}

}
