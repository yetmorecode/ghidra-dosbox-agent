package yetmorecode.ghidra.console.command;

import ghidra.util.Msg;
import yetmorecode.ghidra.console.Cause;
import yetmorecode.ghidra.console.ConsoleManager;
import yetmorecode.ghidra.console.event.CommandCompletedEvent;
import yetmorecode.ghidra.console.event.CommandRunningEvent;
import yetmorecode.ghidra.console.event.Event;

public abstract class Command<T> implements Cause {
	protected ConsoleManager manager;
	
	public Command(ConsoleManager m) {
		manager = m;
	}
	
	public boolean handle(Event<?> evt, PendingCommand<?> pending) {
		Msg.info(this, pending + ": " + evt);
		if (evt instanceof CommandRunningEvent) {
			return false;
		}
		if (evt instanceof CommandCompletedEvent) {
			Msg.info(this, "claimed");
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
	
	/**
	 * Encode the command
	 * 
	 * @return the encoded command
	 */
	public abstract String encode();
	
	@Override
	public String toString() {
		return this.getClass().getSimpleName();
	}
}
