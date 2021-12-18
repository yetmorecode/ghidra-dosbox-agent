package yetmorecode.ghidra.console.event;

import yetmorecode.ghidra.dosbox.manager.command.DosboxEvent;

public class CommandCompletedEvent extends DosboxEvent {
	public CommandCompletedEvent(String info) {
		super(info);
	}
	
	public String assumeMsg() {
		return getInfo();
	}
}
