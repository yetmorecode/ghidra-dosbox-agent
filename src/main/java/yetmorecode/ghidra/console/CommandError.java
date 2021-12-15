package yetmorecode.ghidra.console;

@SuppressWarnings("serial")
public class CommandError extends RuntimeException {
	
	String info;
	
	public CommandError(String info) {
		this.info = info;
	}
	
	/**
	 * Get the details, if present
	 * 
	 * @return the details, or null
	 */
	public String getInfo() {
		return info;
	}

}
