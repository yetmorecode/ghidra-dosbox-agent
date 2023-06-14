package yetmorecode.ghidra.dosbox;

import agent.gdb.model.impl.GdbModelImpl;
import agent.gdb.pty.PtyFactory;

public class DosboxModel extends GdbModelImpl {
	public DosboxModel(PtyFactory ptyFactory) {
		super(ptyFactory);
	}
	
	@Override
	public String getBrief() {
		return "DOSBox-X @ " + gdb.getPtyDescription();
	}
}
