package yetmorecode.ghidra.dosbox.manager.command;

import yetmorecode.ghidra.dosbox.manager.Cause;
import yetmorecode.ghidra.dosbox.manager.event.CommandCompletedEvent;
import yetmorecode.ghidra.dosbox.manager.event.CommandRunningEvent;
import yetmorecode.ghidra.dosbox.manager.event.Event;

public abstract class Command<T> implements Cause {

	public boolean handle(Event<?> evt, PendingCommand<?> pending) {
		if (evt instanceof CommandRunningEvent) {
			return false;
		}
		if (evt instanceof CommandCompletedEvent) {
			pending.claim(evt);
			return true;
		}
		return false;
	}
	
	/**
	 * Called when the manager believes this command is finished executing
	 * 
	 * <p>
	 * This is presumed when the manager receives the prompt after issuing the encoded command
	 * 
	 * @param pending a copy of the now-finished-executing command instance
	 * @return the object "returned" by the command
	 */
	public abstract T complete(PendingCommand<?> pending);
}
