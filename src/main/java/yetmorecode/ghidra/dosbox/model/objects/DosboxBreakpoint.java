package yetmorecode.ghidra.dosbox.model.objects;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetBreakpointLocation;
import ghidra.dbg.target.TargetBreakpointSpec;
import ghidra.dbg.target.TargetDeletable;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.util.Msg;
import yetmorecode.ghidra.dosbox.model.DosboxModel;

@TargetObjectSchemaInfo(name = DosboxBreakpoint.NAME)
public class DosboxBreakpoint extends DefaultTargetObject<TargetObject, DosboxBreakpoints> 
	implements TargetBreakpointLocation, TargetBreakpointSpec, TargetDeletable {

	public static final String NAME = "Breakpoint";
	
	public DosboxBreakpoint(AbstractDebuggerObjectModel model, DosboxBreakpoints parent, String key, long address) {
		super(model, parent, PathUtils.makeKey(key), NAME);
		try {
			changeAttributes(List.of(), Map.of(
				DISPLAY_ATTRIBUTE_NAME, key + " - " + Long.toHexString(address),
				CONTAINER_ATTRIBUTE_NAME, parent,
				KIND_ATTRIBUTE_NAME, TargetBreakpointKind.SW_EXECUTE,
				ENABLED_ATTRIBUTE_NAME, true,
				EXPRESSION_ATTRIBUTE_NAME, "",
				SPEC_ATTRIBUTE_NAME, this,
				RANGE_ATTRIBUTE_NAME, new AddressRangeImpl(model.getAddressSpace(DosboxModel.DOSBOX_ADDRESS_SPACE).getAddress(address), 1)
				), "Init");
		} catch (AddressOverflowException | AddressOutOfBoundsException e) {
			Msg.error(this, "Invalid breakpoint address: " + Long.toHexString(address));
		}
	}

	@Override
	public CompletableFuture<Void> disable() {
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<Void> enable() {
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<Void> delete() {
		return AsyncUtils.NIL;
	}
	
	@Override
	public void addAction(TargetBreakpointAction action) {
		Msg.info(this, "add action");
		
	}

	@Override
	public void removeAction(TargetBreakpointAction action) {
		Msg.info(this, "remove action");
	}
}
