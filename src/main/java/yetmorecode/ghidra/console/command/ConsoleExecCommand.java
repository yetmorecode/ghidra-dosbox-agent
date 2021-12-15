package yetmorecode.ghidra.console.command;

import yetmorecode.ghidra.console.ConsoleManager;
import yetmorecode.ghidra.console.event.ConsoleOutputEvent;
import yetmorecode.ghidra.console.event.Event;

public class ConsoleExecCommand extends Command<String> {

	private final String command;
	
	public ConsoleExecCommand(ConsoleManager manager, String command) {
		super(manager);
		this.command = command;
	}
	
	@Override
	public boolean handle(Event<?> evt, PendingCommand<?> pending) {
		if (evt instanceof ConsoleOutputEvent) {
			pending.claim(evt);
			return true;
		}
		return false;
	}

	@Override
	public String complete(PendingCommand<?> pending) {
		StringBuilder builder = new StringBuilder();
		for (var out : pending.findAllOf(ConsoleOutputEvent.class)) {
			builder.append(out.getOutput());
		}
		return builder.toString();
	}

	@Override
	public String encode() {
		return command;
	}
	
	@Override
	public String toString() {
		return "execute command: " + command;
	}

}
