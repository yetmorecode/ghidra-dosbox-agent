package yetmorecode.ghidra.console.event;

public class ConsoleOutputEvent extends Event<String> {
	public ConsoleOutputEvent(String info) {
		super(info);
	}

	public String getOutput() {
		return getInfo();
	}
	
	@Override
	public String toString() {
		return "console output: " + getOutput();
	}
}
