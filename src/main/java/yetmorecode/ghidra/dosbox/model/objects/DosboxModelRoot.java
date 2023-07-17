package yetmorecode.ghidra.dosbox.model.objects;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.gdb.model.impl.GdbModelTargetInferior;
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
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.target.TargetResumable;
import ghidra.dbg.target.TargetStack;
import ghidra.dbg.target.TargetThread;
import ghidra.dbg.target.TargetAttacher.TargetAttachKind;
import ghidra.dbg.target.TargetAttacher.TargetAttachKindSet;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.util.Msg;
import yetmorecode.ghidra.dosbox.model.DosboxModel;

@TargetObjectSchemaInfo(
		name = "Dosbox",
		elements = {
			@TargetElementType(type = Void.class) },
		attributes = {
			@TargetAttributeType(
					name = "Environment",
					type = DosboxEnvironment.class,
					required = true,
					fixed = true),
			@TargetAttributeType(
					name = "Breakpoints",
					type = DosboxBreakpoints.class,
					required = true,
					fixed = false),
			@TargetAttributeType(
					name = "Memory",
					type = DosboxMemory.class,
					required = true,
					fixed = false),
			@TargetAttributeType(
					name = "Modules",
					type = DosboxModules.class,
					required = true,
					fixed = true),
			@TargetAttributeType(
					name = "Stack",
					type = DosboxStack.class,
					required = true,
					fixed = false),
			@TargetAttributeType(type = Void.class) })
public class DosboxModelRoot 
	extends DefaultTargetModelRoot 
	implements TargetAccessConditioned, TargetInterruptible, TargetResumable, TargetExecutionStateful,
	TargetActiveScope, TargetEventScope, TargetFocusScope, TargetLauncher, TargetAttacher, TargetProcess, TargetAggregate, TargetThread {

	private DosboxBreakpoints breakpoints;
	private DosboxModules modules;
	
	private DosboxEnvironment env;
	public DosboxMemory memory;
	public DosboxStack stack;
	
	public DosboxModelRoot(DosboxModel model, TargetObjectSchema schema) {
		super(model, "Dosbox", schema);
		
		breakpoints = new DosboxBreakpoints(model, this, "Breakpoints", "Breakpoints");
		modules = new DosboxModules(model, this);
		env = new DosboxEnvironment(model, this, "Environment", "Environment");
		memory = new DosboxMemory(model, this);
		stack = new DosboxStack(model, this, "Stack", "Stack");
		
		changeAttributes(List.of(), Map.of(
			STATE_ATTRIBUTE_NAME, TargetExecutionState.STOPPED,
			ACCESSIBLE_ATTRIBUTE_NAME, true,
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME, TargetMethod.makeParameters(TargetCmdLineLauncher.PARAMETER_CMDLINE_ARGS), //
			SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME, TargetAttachKindSet.of(TargetAttachKind.BY_ID), //
			FOCUS_ATTRIBUTE_NAME, this // Satisfy schema. Will be set to first inferior.
		), "Initialized");
		changeAttributes(List.of(), Map.of(
			"Environment", env,
			"Breakpoints", breakpoints,
			"Modules", modules,
			"Memory", memory,
			"Stack", stack	
		), "Dynamic");
		
		listeners.fire.event(getProxy(), this, TargetEventType.THREAD_CREATED, "Thread started", List.of(this));
	}

	
	@Override
	public CompletableFuture<Void> interrupt() {
		Msg.info(this, "interrupt");
		setRunning(false);
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<Void> resume() {
		Msg.info(this, "resume");
		setRunning(true);
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
	public CompletableFuture<Void> requestActivation(TargetObject obj) {
		Msg.info(this, "request activation");
		return AsyncUtils.NIL;
	}


	@Override
	public CompletableFuture<Void> requestFocus(TargetObject obj) {
		Msg.info(this, "request focus");
		return AsyncUtils.NIL;
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
}
