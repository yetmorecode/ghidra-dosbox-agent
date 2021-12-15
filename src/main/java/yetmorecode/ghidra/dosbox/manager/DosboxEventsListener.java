package yetmorecode.ghidra.dosbox.manager;

import yetmorecode.ghidra.console.Cause;
import yetmorecode.ghidra.console.TargetEventsListener;

public interface DosboxEventsListener extends TargetEventsListener {
	/**
	 * A breakpoint has been created in the session
	 * 
	 * @param info information about the new breakpoint
	 * @param cause the cause of this event
	 */
	default void breakpointCreated(BreakpointInfo info, Cause cause) {
		
	}

	/**
	 * A breakpoint in the session has been modified
	 * 
	 * @param newInfo new information about the modified breakpoint
	 * @param oldInfo old information about the modified breakpoint
	 * @param cause the cause of this event
	 */
	default void breakpointModified(BreakpointInfo newInfo, BreakpointInfo oldInfo, Cause cause) {
		
	}

	/**
	 * A breakpoint has been deleted from the session
	 * 
	 * @param info information about the now-deleted breakpoint
	 * @param cause the cause of this event
	 */
	default void breakpointDeleted(BreakpointInfo info, Cause cause) {
		
	}
}
