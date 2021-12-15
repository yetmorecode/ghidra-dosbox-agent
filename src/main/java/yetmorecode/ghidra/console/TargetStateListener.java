package yetmorecode.ghidra.console;

import ghidra.util.TriConsumer;

public interface TargetStateListener extends TriConsumer<TargetState, TargetState, Cause> {
	/**
	 * The state has changed because of the given cause
	 * 
	 * @param state the new state
	 * @param cause the reason for the change
	 */
	void stateChanged(TargetState state, Cause cause);

	@Override
	default void accept(TargetState oldSt, TargetState newSt, Cause u) {
		stateChanged(newSt, u);
	}
}