package yetmorecode.ghidra.console.command;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import yetmorecode.ghidra.console.Cause;
import yetmorecode.ghidra.console.event.CommandCompletedEvent;
import yetmorecode.ghidra.console.event.Event;

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
		try {
			T result = command.complete(this);
			complete(result);
		}
		catch (Throwable e) {
			e.printStackTrace();
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
	
	/**
	 * Assume a single event was claimed/stolen, and get that event as the given type
	 * 
	 * @param cls the type of the event
	 * @return the event cast to the type
	 * @throws IllegalStateException if more than one event was claimed/stolen
	 * @throws ClassCastException if the event cannot be cast to the given type
	 */
	public <E extends Event<?>> E castSingleEvent(Class<E> cls) {
		if (evts.size() != 1) {
			throw new IllegalStateException("Command did not claim exactly one event");
		}
		return cls.cast(evts.iterator().next());
	}

	/**
	 * Get the first claimed/stolen event of a given type
	 * 
	 * @param <E> the type of the event
	 * @param cls the class of the event
	 * @return the event cast to the type, or null
	 */
	public <E extends Event<?>> E getFirstOf(Class<E> cls) {
		for (Event<?> evt : evts) {
			if (cls.isAssignableFrom(evt.getClass())) {
				return cls.cast(evt);
			}
		}
		return null;
	}

	/**
	 * Find the first claimed/stolen event of a given type
	 * 
	 * @param <E> the type of the event
	 * @param cls the class of the event
	 * @return the event cast to the type
	 * @throws IllegalStateException if no event of the given type was claimed/stolen
	 */
	public <E extends Event<?>> E findFirstOf(Class<E> cls) {
		E first = getFirstOf(cls);
		if (first != null) {
			return first;
		}
		throw new IllegalStateException("Command did not claim any " + cls);
	}

	/**
	 * Check if any event of a given type has been claimed
	 * 
	 * @param cls the class of the event
	 * @return true if at least one is claimed, false otherwise
	 */
	public boolean hasAny(Class<? extends Event<?>> cls) {
		return getFirstOf(cls) != null;
	}

	/**
	 * Find all events claimed/stolen of a given type
	 * 
	 * @param cls the type of the events
	 * @return the list of events cast to the type
	 */
	public <E extends Event<?>> List<E> findAllOf(Class<E> cls) {
		List<E> found = new ArrayList<>();
		for (Event<?> evt : evts) {
			if (cls.isAssignableFrom(evt.getClass())) {
				found.add(cls.cast(evt));
			}
		}
		return found;
	}

	/**
	 * Assume exactly one event of the given type was claimed/stolen, and get that event
	 * 
	 * @param cls the type of the event
	 * @return the event cast to the type
	 * @throws IllegalStateException if more than one event matches
	 */
	public <E extends Event<?>> E findSingleOf(Class<E> cls) {
		List<E> found = findAllOf(cls);
		if (found.size() != 1) {
			throw new IllegalStateException(
				"Command did not claim exactly one " + cls + ". Have " + evts);
		}
		return found.get(0);
	}

	/**
	 * Check that the command completed with one of the given results
	 * 
	 * {@link GdbCommandErrorEvent} need not be listed. This method will handle it as a special case
	 * already. To avoid the special treatment, list it explicitly.
	 * 
	 * @param classes the completion type to accept
	 * @return the completion event, cast to the greatest common subclass
	 */
	@SafeVarargs
	public final <E extends CommandCompletedEvent> E checkCompletion(
			Class<E>... classes) {
		CommandCompletedEvent completion =
			findSingleOf(CommandCompletedEvent.class);
		// Allow query for exact class to override error interpretation
		for (Class<E> cls : classes) {
			if (cls == completion.getClass()) {
				return cls.cast(completion);
			}
		}
		/*
		if (completion instanceof GdbCommandErrorEvent) {
			throw new GdbCommandError(completion.getInfo(), cmd);
		}
		*/
		for (Class<E> cls : classes) {
			if (cls.isAssignableFrom(completion.getClass())) {
				return cls.cast(completion);
			}
		}
		throw new IllegalStateException(
			"Command completed with " + completion + ", not any of " + Arrays.asList(classes));
	}
	
	@Override
	public String toString() {
		return command.toString() + '*';
	}
}
