package yetmorecode.ghidra.dosbox.model.objects;

import java.util.List;
import java.util.Map;

import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetMemoryRegion;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRangeImpl;
import yetmorecode.ghidra.dosbox.model.DosboxModel;

@TargetObjectSchemaInfo(
		name = "MemoryRegion",
		elements = {
			@TargetElementType(type = Void.class) },
		attributes = {
			@TargetAttributeType(type = Void.class) })
public class DosboxMemoryRegion 
	extends DefaultTargetObject<TargetObject, DosboxMemory> 
	implements TargetMemoryRegion {

	public DosboxMemoryRegion(AbstractDebuggerObjectModel model, DosboxMemory parent, String key, long base, long length) {
		super(model, parent, PathUtils.makeKey(key), "MemoryRegion");
		
		
		try {
			var r = new AddressRangeImpl(model.getAddressSpace(DosboxModel.DOSBOX_ADDRESS_SPACE).getAddress(base), length);
			changeAttributes(List.of(), Map.of( //
				MEMORY_ATTRIBUTE_NAME, parent, //
				RANGE_ATTRIBUTE_NAME, r, //
				READABLE_ATTRIBUTE_NAME, true, //
				WRITABLE_ATTRIBUTE_NAME, true, //
				EXECUTABLE_ATTRIBUTE_NAME, true, //
				DISPLAY_ATTRIBUTE_NAME, r.toString() //
			), "Initialized");
		} catch (AddressOverflowException | AddressOutOfBoundsException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
}

}
