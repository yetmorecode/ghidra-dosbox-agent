package yetmorecode.ghidra.console;

public interface ConsoleOutputListener {
	/**
	 * Debugger outputted some text
	 * 
	 * @param out the output
	 */
	void output(String out);
}
