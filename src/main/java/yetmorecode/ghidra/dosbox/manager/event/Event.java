package yetmorecode.ghidra.dosbox.manager.event;

import agent.gdb.manager.GdbState;
import yetmorecode.ghidra.dosbox.manager.Cause;
import yetmorecode.ghidra.dosbox.manager.PendingCommand;
import yetmorecode.ghidra.dosbox.manager.Cause.Causes;
import yetmorecode.ghidra.dosbox.manager.DosboxState;

public abstract class Event<T> implements Cause {
	private final T info;
	protected Cause cause = Causes.UNCLAIMED;
	protected boolean stolen = false;

	protected Event(T info) {
		this.info = info;
	}
	/**
	 * Get the information detailing the event
	 * 
	 * @return the information
	 */
	public T getInfo() {
		return info;
	}
	
	public Cause getCause() {
		return cause;
	}

	public void claim(PendingCommand<?> cmd) {
		if (cause != Causes.UNCLAIMED) {
			throw new IllegalStateException("Event is already claimed by " + cause);
		}
		cause = cmd;
	}

	public void steal() {
		stolen = true;
	}

	public boolean isStolen() {
		return stolen;
	}
	
	/**
	 * If this event implies a new GDB state, get that state
	 * 
	 * @return the new state, or null for no change
	 */
	public DosboxState newState() {
		return null;
	}
	
	@Override
	public String toString() {
		return getClass().getSimpleName();
	}
}
