package yetmorecode.ghidra.dosbox.model;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebuggerModelClosedReason;
import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.error.DebuggerModelTerminatingException;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.util.Msg;

public class DosboxModel extends AbstractDebuggerObjectModel {

	protected final AddressSpace space = new GenericAddressSpace("dosbox", 32, AddressSpace.TYPE_RAM, 0);
	protected final AddressFactory addressFactory = new DefaultAddressFactory(new AddressSpace[] { space });
	protected String hostname = "localhost";
	protected int port = 3000;
	
	public DosboxModel(String hostname, int port) {
		super();
		this.hostname = hostname;
		this.port = port;
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
		Msg.info(this, "dosbox model: starting ");
		return CompletableFuture.runAsync(() -> {
			throw new DebuggerModelTerminatingException("Cannot connect to dosbox");
		});
	}
	
	@Override
	public CompletableFuture<Void> close() {
		Msg.info(this, "dosbox model: terminating");
		try {
			listeners.fire.modelClosed(DebuggerModelClosedReason.NORMAL);
			return super.close();
		}
		catch (Throwable t) {
			return CompletableFuture.failedFuture(t);
		}
	}
}
