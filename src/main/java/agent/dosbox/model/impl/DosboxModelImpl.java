package agent.dosbox.model.impl;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;

import agent.gdb.model.impl.GdbModelTargetSession;
import ghidra.dbg.DebuggerModelClosedReason;
import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.AnnotatedSchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;

public class DosboxModelImpl extends AbstractDebuggerObjectModel {
	
	protected static final String SPACE_NAME = "ram";
	
	protected static final AnnotatedSchemaContext SCHEMA_CTX = new AnnotatedSchemaContext();
	protected static final TargetObjectSchema ROOT_SCHEMA =
		SCHEMA_CTX.getSchemaForClass(DosboxModelTargetSession.class);
	
	protected final AddressSpace space =
		new GenericAddressSpace(SPACE_NAME, 64, AddressSpace.TYPE_RAM, 0);
	protected final AddressFactory addressFactory =
		new DefaultAddressFactory(new AddressSpace[] { space });
	

	private DosboxModelTargetSession session;
	protected final CompletableFuture<DosboxModelTargetSession> completedSession;
	
	public DosboxModelImpl() {
		super();
		this.session = new DosboxModelTargetSession(this, ROOT_SCHEMA);
		
		this.completedSession = CompletableFuture.completedFuture(session);
	}
	
	@Override
	public AddressFactory getAddressFactory() {
		return addressFactory;
	}

	public void terminate() throws IOException {
		listeners.fire.modelClosed(DebuggerModelClosedReason.NORMAL);
		session.invalidateSubtree(session, "GDB is terminating");
		//gdb.terminate();
	}

	@Override
	public CompletableFuture<? extends TargetObject> fetchModelRoot() {
		return completedSession;
	}

	@Override
	public boolean isAlive() {
		//return gdb.getState().isAlive();
		return true;
	}

	@Override
	public CompletableFuture<Void> close() {
		try {
			terminate();
			return super.close();
		}
		catch (Throwable t) {
			return CompletableFuture.failedFuture(t);
		}
	}
	
	@Override
	public TargetObjectSchema getRootSchema() {
		return ROOT_SCHEMA;
	}

}
