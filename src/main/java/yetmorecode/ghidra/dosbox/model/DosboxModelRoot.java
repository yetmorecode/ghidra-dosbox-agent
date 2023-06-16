package yetmorecode.ghidra.dosbox.model;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetModelRoot;
import ghidra.dbg.target.TargetAccessConditioned;
import ghidra.dbg.target.TargetExecutionStateful;
import ghidra.dbg.target.TargetInterruptible;
import ghidra.dbg.target.TargetResumable;

public class DosboxModelRoot 
	extends DefaultTargetModelRoot 
	implements TargetAccessConditioned, TargetInterruptible, TargetResumable, TargetExecutionStateful {

	public DosboxModelRoot(DosboxModel model) {
		super(model, "Dosbox");
		changeAttributes(List.of(), Map.of(
			STATE_ATTRIBUTE_NAME, TargetExecutionState.RUNNING,
			ACCESSIBLE_ATTRIBUTE_NAME, true,
			DISPLAY_ATTRIBUTE_NAME, "dosbox display"
		), "Initialized");
	}

	@Override
	public CompletableFuture<Void> interrupt() {
		setRunning(false);
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<Void> resume() {
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
			DISPLAY_ATTRIBUTE_NAME, "dosbox new"
		), isRunning ? "State changed to running" : "State changed to stopped");
	}
}
