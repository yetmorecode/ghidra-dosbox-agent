package yetmorecode.ghidra.dosbox.model;

import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerModelClosedReason;
import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;


public class DosboxModel extends AbstractDebuggerObjectModel {
	protected final AddressFactory addressFactory = new DefaultAddressFactory(
			new AddressSpace[] { new GenericAddressSpace("dosbox", 32, AddressSpace.TYPE_RAM, 0) });
	protected String hostname = "localhost";
	protected int port = 2999;
	
	protected DosboxModelRoot rootNode;
	
	public DosboxModel(String hostname, int port) {
		super();
		this.hostname = hostname;
		this.port = port;
		addModelRoot(new DosboxModelRoot(this));
	}
	
	@Override
	public AddressFactory getAddressFactory() {
		return addressFactory;
	}
	
	@Override
	public String getBrief() {
		return String.format("DOSBox-X (%s:%d)", hostname, port);
	}
	
	
	public CompletableFuture<Void> start() {
		return AsyncUtils.NIL;
	}
	
	@Override
	public CompletableFuture<Void> close() {
		listeners.fire.modelClosed(DebuggerModelClosedReason.NORMAL);
		getModelRoot().invalidateSubtree(getModelRoot(), "Dosbox is terminating");
		return super.close();
	}
}
