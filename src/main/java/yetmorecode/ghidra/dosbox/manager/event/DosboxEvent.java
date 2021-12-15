package yetmorecode.ghidra.dosbox.manager.event;

import yetmorecode.ghidra.console.event.Event;

public abstract class DosboxEvent<T> extends Event<T> {
	protected DosboxEvent(T info) {
		super(info);
	}
}
