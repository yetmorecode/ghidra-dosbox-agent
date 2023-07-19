package yetmorecode.ghidra.dosbox.model.objects;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetBreakpointLocationContainer;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpecContainer;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.program.model.address.AddressRange;
import ghidra.util.Msg;

@TargetObjectSchemaInfo(
	name = DosboxBreakpoints.NAME,
	elements = { @TargetElementType(type = DosboxBreakpoint.class) },
	elementResync = ResyncMode.ALWAYS,
	canonicalContainer = true
)
public class DosboxBreakpoints extends DefaultTargetObject<DosboxBreakpoint, DosboxModelRoot> 
	implements TargetBreakpointLocationContainer, TargetBreakpointSpecContainer {

	public static final String NAME = "Breakpoints";
	
	public DosboxBreakpoints(AbstractDebuggerObjectModel model, DosboxModelRoot parent) {
		super(model, parent, NAME, NAME);
		var breakpoints = new LinkedList<DosboxBreakpoint>();
		breakpoints.push(new DosboxBreakpoint(model, this, "0", 0x10010));
		breakpoints.push(new DosboxBreakpoint(model, this, "1", 0x20000));
		breakpoints.push(new DosboxBreakpoint(model, this, "2", 0x20010));
		changeElements(List.of(), breakpoints, "Changed breakpoints");
		changeAttributes(List.of(), Map.of(
			SUPPORTED_BREAK_KINDS_ATTRIBUTE_NAME, TargetBreakpointKindSet.of(TargetBreakpointKind.SW_EXECUTE)
		), "Init");
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
