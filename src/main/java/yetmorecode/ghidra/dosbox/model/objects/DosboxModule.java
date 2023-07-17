package yetmorecode.ghidra.dosbox.model.objects;

import java.util.List;
import java.util.Map;

import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetModule;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRangeImpl;
import yetmorecode.ghidra.dosbox.model.DosboxModel;

@TargetObjectSchemaInfo(
		name = "Module",
		elements = {
			@TargetElementType(type = Void.class)
		},
		attributes = {
			@TargetAttributeType(type = Void.class)
		})
public class DosboxModule 
	extends DefaultTargetObject<TargetObject, DosboxModules>
	implements TargetModule {

	public DosboxModule(AbstractDebuggerObjectModel model, DosboxModules parent, String key, long base, long length) {
		super(model, parent, PathUtils.makeKey(key), "Module");
		
		
		try {
			changeAttributes(List.of(), Map.of( //
					MODULE_NAME_ATTRIBUTE_NAME, key, //
					SHORT_DISPLAY_ATTRIBUTE_NAME, key, //
					DISPLAY_ATTRIBUTE_NAME, key, //
					RANGE_ATTRIBUTE_NAME, new AddressRangeImpl(model.getAddressSpace(DosboxModel.DOSBOX_ADDRESS_SPACE).getAddress(base), length)
				), "Initialized");
			
			
		} catch (AddressOverflowException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (AddressOutOfBoundsException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//listeners.fire.event(getProxy(), null, TargetEventType.MODULE_LOADED, "Library loaded", List.of(this));
	}

}
