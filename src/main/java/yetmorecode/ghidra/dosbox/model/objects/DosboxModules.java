package yetmorecode.ghidra.dosbox.model.objects;

import java.util.List;

import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetModuleContainer;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;

@TargetObjectSchemaInfo(
		name = "ModuleContainer",
		elements = { //
			@TargetElementType(type = DosboxModule.class) //
		}, //
		elementResync = ResyncMode.ONCE, //
		attributes = { //
			@TargetAttributeType(type = Object.class) //
		},
		canonicalContainer = true)
public class DosboxModules
	extends DefaultTargetObject<DosboxModule, DosboxModelRoot> 
	implements TargetModuleContainer {

	private DosboxModule moduleA;
	
	public DosboxModules(AbstractDebuggerObjectModel model, DosboxModelRoot parent) {
		super(model, parent, "Modules", "ModuleContainer");
		
		moduleA = new DosboxModule(model, this, "bmh.exe", 0x10000, 0x6a94a);
		
		changeElements(List.of(), List.of(moduleA), "Added modules");
		
		
	}

}
