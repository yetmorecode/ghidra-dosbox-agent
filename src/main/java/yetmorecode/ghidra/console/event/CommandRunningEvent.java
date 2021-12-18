package yetmorecode.ghidra.console.event;

public class CommandRunningEvent extends CommandCompletedEvent {
	public CommandRunningEvent(String info) {
		super(info);
	}
}
