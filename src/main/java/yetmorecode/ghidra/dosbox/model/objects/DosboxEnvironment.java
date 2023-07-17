package yetmorecode.ghidra.dosbox.model.objects;

import java.util.List;
import java.util.Map;

import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetEnvironment;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "Environment",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(type = Object.class)
	}
)
public class DosboxEnvironment 
	extends DefaultTargetObject<TargetObject, DosboxModelRoot>
	implements TargetEnvironment {

	public static final String ARCH = "x86";
	public static final String OS = "dos4gw";
	public static final String ENDIAN = "little";
	public static final String DEBUGGER = "dosbox";
	
	public DosboxEnvironment(AbstractDebuggerObjectModel model, DosboxModelRoot parent, String key, String typeHint) {
		super(model, parent, key, typeHint);
		changeAttributes(
			List.of(), 
			Map.of(
				DEBUGGER_ATTRIBUTE_NAME, DEBUGGER,
				ARCH_ATTRIBUTE_NAME, ARCH,
				OS_ATTRIBUTE_NAME, OS,
				ENDIAN_ATTRIBUTE_NAME, ENDIAN,
				"debugger", DEBUGGER,
				"arch", ARCH,
				"os", OS,
				"endian", ENDIAN
			),
			"Initialized"
		);
	}

}
