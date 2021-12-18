package yetmorecode.ghidra.dosbox.manager.command;

import yetmorecode.ghidra.console.event.Event;

public abstract class DosboxEvent extends Event<String> {
	protected DosboxEvent(String info) {
		super(info);
	}
}
