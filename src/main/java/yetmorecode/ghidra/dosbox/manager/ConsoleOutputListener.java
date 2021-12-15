package yetmorecode.ghidra.dosbox.manager;

public interface ConsoleOutputListener {
	/**
	 * Debugger outputted some text
	 * 
	 * @param out the output
	 */
	void output(String out);
}
