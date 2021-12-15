package yetmorecode.ghidra.dosbox.model.target;

import java.util.concurrent.CompletableFuture;

import agent.gdb.manager.GdbInferior;
import agent.gdb.model.impl.GdbModelTargetInferiorContainer;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetDeletable;
import ghidra.dbg.target.TargetDetachable;
import ghidra.dbg.target.TargetExecutionStateful;
import ghidra.dbg.target.TargetKillable;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.target.TargetResumable;
import ghidra.dbg.target.TargetSteppable;
import ghidra.dbg.target.TargetAttacher.TargetAttachKind;
import ghidra.dbg.target.TargetAttacher.TargetAttachKindSet;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.util.Msg;
import yetmorecode.ghidra.dosbox.model.SelectableObject;

@TargetObjectSchemaInfo(
		name = "Inferior",
		elements = {
			@TargetElementType(type = Void.class) },
		attributes = {
			@TargetAttributeType(type = Void.class) })
public class InferiorModel extends DefaultTargetObject<TargetObject, InferiorContainerModel>
implements SelectableObject, TargetProcess, TargetExecutionStateful, TargetDeletable, TargetDetachable, TargetKillable, TargetResumable,
TargetSteppable {

	public InferiorModel(InferiorContainerModel inferiors, InferiorModel inferior) {
		super(inferiors.impl, inferiors, keyInferior(inferior), "Inferior");
		
	}
	
	protected static String indexInferior(int inferiorId) {
		return PathUtils.makeIndex(inferiorId);
	}

	protected static String indexInferior(InferiorModel inferior) {
		return indexInferior(0);
	}

	protected static String keyInferior(InferiorModel inferior) {
		return PathUtils.makeKey(indexInferior(inferior));
	}

	@Override
	public CompletableFuture<Void> setActive() {
		Msg.debug(this, "selected inferior..");
		return CompletableFuture.completedFuture(null);
	}
	
	public static final ParameterDescription<Boolean> PARAMETER_FOO =
			ParameterDescription.create(Boolean.class, "foolean", false, false,
				"true or no?",
				"a second line aha!");
	
	public static final TargetParameterMap PARAMETERS =
		TargetMethod.makeParameters(TargetCmdLineLauncher.PARAMETER_CMDLINE_ARGS, PARAMETER_FOO);

	protected static final TargetAttachKindSet SUPPORTED_KINDS = TargetAttachKindSet.of( //
		TargetAttachKind.BY_OBJECT_REF, TargetAttachKind.BY_ID);

	@Override
	public CompletableFuture<Void> step(TargetStepKind kind) {
		Msg.info(this, "step");
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<Void> resume() {
		Msg.info(this, "resume");
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<Void> kill() {
		Msg.info(this, "kill");
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<Void> detach() {
		Msg.info(this, "detach");
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<Void> delete() {
		Msg.info(this, "delete");
		return AsyncUtils.NIL;
	}

}
