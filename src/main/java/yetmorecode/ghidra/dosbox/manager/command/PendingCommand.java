package yetmorecode.ghidra.dosbox.manager.command;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import ghidra.util.Msg;
import yetmorecode.ghidra.dosbox.manager.Cause;
import yetmorecode.ghidra.dosbox.manager.event.Event;

public class PendingCommand<T> extends CompletableFuture<T> implements Cause {
	private final Command<? extends T> command;
	private final Set<Event<?>> evts = new LinkedHashSet<>();
	
	public PendingCommand(Command<? extends T> cmd) {
		command = cmd;
	}
	
	public Command<? extends T> getCommand() {
		return command;
	}
	
	/**
	 * Finish the execution of this command
	 */
	public void finish() {
		Msg.debug(this, "Finishing " + command);
		try {
			T result = command.complete(this);
			complete(result);
		}
		catch (Throwable e) {
			completeExceptionally(e);
		}
	}
	
	/**
	 * Handle an event
	 * 
	 * <p>
	 * This gives the command implementation the first chance to claim or steal an event
	 * 
	 * @param evt the event
	 * @return true if the command is ready to be completed
	 */
	public boolean handle(Event<?> evt) {
		return command.handle(evt, this);
	}
	
	/**
	 * Claim an event
	 * 
	 * This stores the event for later retrieval and processing.
	 * 
	 * @param evt the event
	 */
	public void claim(Event<?> evt) {
		evt.claim(this);
		evts.add(evt);
	}

	/**
	 * Steal an event
	 * 
	 * This stores the event for later retrieval and processing.
	 * 
	 * @param evt the event
	 */
	public void steal(Event<?> evt) {
		claim(evt);
		evt.steal();
	}
}
