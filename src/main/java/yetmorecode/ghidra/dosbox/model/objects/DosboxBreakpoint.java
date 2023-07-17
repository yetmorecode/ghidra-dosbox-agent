package yetmorecode.ghidra.dosbox.model.objects;

import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetBreakpointLocation;
import ghidra.dbg.target.TargetBreakpointSpec;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.util.Msg;

@TargetObjectSchemaInfo(
		name = "Breakpoint",
		elements = {
			@TargetElementType(type = Void.class)
		},
		attributes = {
			@TargetAttributeType(type = Void.class)
		})
public class DosboxBreakpoint 
	extends DefaultTargetObject<TargetObject, DosboxBreakpoints> 
	implements TargetBreakpointLocation, TargetBreakpointSpec {

	public DosboxBreakpoint(AbstractDebuggerObjectModel model, DosboxBreakpoints parent, String key, String typeHint) {
		super(model, parent, key, typeHint);
		// TODO Auto-generated constructor stub
	}

	@Override
	public CompletableFuture<Void> disable() {
		Msg.info(this, "disable");
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<Void> enable() {
		Msg.info(this, "enable");
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
