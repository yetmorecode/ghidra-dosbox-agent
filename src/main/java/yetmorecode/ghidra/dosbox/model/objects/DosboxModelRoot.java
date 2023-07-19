package yetmorecode.ghidra.dosbox.model.objects;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetModelRoot;
import ghidra.dbg.target.TargetAccessConditioned;
import ghidra.dbg.target.TargetActiveScope;
import ghidra.dbg.target.TargetAggregate;
import ghidra.dbg.target.TargetAttachable;
import ghidra.dbg.target.TargetAttacher;
import ghidra.dbg.target.TargetEventScope;
import ghidra.dbg.target.TargetExecutionStateful;
import ghidra.dbg.target.TargetFocusScope;
import ghidra.dbg.target.TargetInterruptible;
import ghidra.dbg.target.TargetLauncher;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.target.TargetResumable;
import ghidra.dbg.target.TargetSteppable;
import ghidra.dbg.target.TargetThread;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.util.Msg;
import yetmorecode.ghidra.dosbox.model.DosboxModel;

@TargetObjectSchemaInfo(name = "Dosbox", attributes = {
	@TargetAttributeType(name = DosboxEnvironment.NAME, type = DosboxEnvironment.class, required = true, fixed = true),
	@TargetAttributeType(name = "Breakpoints", type = DosboxBreakpoints.class, required = true, fixed = false),
	@TargetAttributeType(name = "Memory", type = DosboxMemory.class, required = true, fixed = false),
	@TargetAttributeType(name = "Modules", type = DosboxModules.class, required = true, fixed = true),
	@TargetAttributeType(name = "Stack", type = DosboxStack.class, required = true, fixed = false),
	@TargetAttributeType(name = "Registers", type = DosboxRegisterContainerAndBank.class, required = true, fixed = false) 
})
public class DosboxModelRoot extends DefaultTargetModelRoot 
	implements TargetAccessConditioned, TargetInterruptible, TargetResumable, TargetExecutionStateful,
	TargetActiveScope, TargetFocusScope, TargetLauncher, TargetAttacher, TargetProcess, 
	TargetThread, TargetEventScope, TargetAggregate, TargetSteppable {

	public DosboxBreakpoints breakpoints;
	public DosboxModules modules;
	
	public DosboxEnvironment env;
	public DosboxMemory memory;
	
	public DosboxRegisterContainerAndBank registers;
	public DosboxStack stack;
	
	public DosboxModelRoot(DosboxModel model, TargetObjectSchema schema) {
		super(model, "Dosbox", schema);
		
		breakpoints = new DosboxBreakpoints(model, this);
		modules = new DosboxModules(model, this);
		env = new DosboxEnvironment(model, this);
		memory = new DosboxMemory(model, this);
		registers = new DosboxRegisterContainerAndBank(model, this);
		stack = new DosboxStack(model, this, "Stack", registers);
		
		changeAttributes(List.of(), Map.of(
			PID_ATTRIBUTE_NAME, Long.valueOf(1),
			STATE_ATTRIBUTE_NAME, TargetExecutionState.STOPPED,
			ACCESSIBLE_ATTRIBUTE_NAME, true,
			SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME, TargetAttachKindSet.of(
					TargetAttachKind.BY_ID),
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME, TargetParameterMap.of(),
			SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME, TargetStepKindSet.of(
					TargetStepKind.ADVANCE,
					TargetStepKind.FINISH,
					TargetStepKind.LINE,
					TargetStepKind.OVER,
					TargetStepKind.OVER_LINE,
					TargetStepKind.RETURN,
					TargetStepKind.UNTIL,
					TargetStepKind.EXTENDED),
			FOCUS_ATTRIBUTE_NAME, this
		), "Initialized");
		changeAttributes(List.of(), Map.of(
			DosboxEnvironment.NAME, env,
			DosboxBreakpoints.NAME, breakpoints,
			"Modules", modules,
			"Memory", memory,
			DosboxStack.NAME, stack,
			"Registers", registers,
			TID_ATTRIBUTE_NAME, Integer.valueOf(3),
			EVENT_OBJECT_ATTRIBUTE_NAME, this,
			DISPLAY_ATTRIBUTE_NAME, "dosbox main thread",
			SHORT_DISPLAY_ATTRIBUTE_NAME, "dosbox main"
		), "Dynamic");
	}

	@Override
	public CompletableFuture<Void> interrupt() {
		setRunning(false);
		
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<Void> resume() {
		setRunning(true);
		
		listeners.fire.event(this, this, TargetEventType.RUNNING, "Running", List.of(this));
		
		
		return AsyncUtils.NIL;
	}
	
	public void setAccessible(boolean accessible) {
		changeAttributes(List.of(), Map.of(
			ACCESSIBLE_ATTRIBUTE_NAME, accessible
		), "Accessibility changed");
	}
	
	public void setRunning(boolean isRunning) {
		changeAttributes(List.of(), Map.of( //
			STATE_ATTRIBUTE_NAME, isRunning ? TargetExecutionState.RUNNING : TargetExecutionState.STOPPED,
			ACCESSIBLE_ATTRIBUTE_NAME, !isRunning
		), isRunning ? "State changed to running" : "State changed to stopped");
	}

	@Override
	public CompletableFuture<Void> launch(Map<String, ?> args) {
		listeners.fire.created(this);
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<Void> attach(TargetAttachable attachable) {
		Msg.info(this, "attach");
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<Void> attach(long pid) {
		Msg.info(this, "attach by pid");
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<Void> step(TargetStepKind kind) {
		Msg.info(this, "step");
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<Void> requestFocus(TargetObject obj) {
		return AsyncUtils.NIL;	
	}

	@Override
	public CompletableFuture<Void> requestActivation(TargetObject obj) {
		return AsyncUtils.NIL;
	}
}
