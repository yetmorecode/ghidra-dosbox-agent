package yetmorecode.ghidra.console.event;

public class CommandRunningEvent<T> extends Event<T> {
	public CommandRunningEvent(T info) {
		super(info);
	}
}
