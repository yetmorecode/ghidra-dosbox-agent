package yetmorecode.ghidra.console.event;

public class CommandCompletedEvent extends Event<String> {
	public CommandCompletedEvent(String info) {
		super(info);
	}
}
