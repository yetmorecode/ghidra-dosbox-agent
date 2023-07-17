package yetmorecode.ghidra.dosbox.model.objects;

import java.util.Set;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetBreakpointLocationContainer;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.target.TargetBreakpointSpecContainer;
import ghidra.program.model.address.AddressRange;
import ghidra.util.Msg;

@TargetObjectSchemaInfo(
		name = "BreakpointsContainer",
		elements = { //
			@TargetElementType(type = DosboxBreakpoint.class) //
		}, //
		elementResync = ResyncMode.ALWAYS, //
		attributes = { //
			@TargetAttributeType(type = Object.class) //
		},
		canonicalContainer = true)
public class DosboxBreakpoints 
	extends DefaultTargetObject<DosboxBreakpoint, DosboxModelRoot> 
	implements TargetBreakpointLocationContainer, TargetBreakpointSpecContainer {

	public DosboxBreakpoints(AbstractDebuggerObjectModel model, DosboxModelRoot parent, String key, String typeHint) {
		super(model, parent, key, typeHint);
		// TODO Auto-generated constructor stub
	}

	@Override
	public CompletableFuture<Void> placeBreakpoint(String expression, Set<TargetBreakpointKind> kinds) {
		Msg.info(this, "placing breakpoint by expression: " + expression);
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<Void> placeBreakpoint(AddressRange range, Set<TargetBreakpointKind> kinds) {
		Msg.info(this, "placing breakpoint by range: " + range.getMinAddress().toString());
		return AsyncUtils.NIL;
	}



}
