package yetmorecode.ghidra.dosbox.manager.command;

import yetmorecode.ghidra.console.command.Command;
import yetmorecode.ghidra.dosbox.manager.DosboxManager;

public abstract class DosboxCommand<T> extends Command<T> {
	protected DosboxManager manager;
	
	public DosboxCommand(DosboxManager m) {
		super(m.getConsoleManager());
		manager = m;
	}
}
