package yetmorecode.ghidra.console;

public interface TargetOutputListener {
	/**
	 * The target outputted some text
	 * 
	 * @param out the output
	 */
	void output(String out);
}
