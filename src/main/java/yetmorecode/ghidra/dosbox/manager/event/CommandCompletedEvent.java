package yetmorecode.ghidra.dosbox.manager.event;

public class CommandCompletedEvent<T> extends Event<T> {

	protected CommandCompletedEvent(T info) {
		super(info);
	}

}
