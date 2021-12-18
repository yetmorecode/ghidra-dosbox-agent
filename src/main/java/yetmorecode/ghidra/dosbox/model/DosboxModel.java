package yetmorecode.ghidra.dosbox.model;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.apache.commons.lang3.exception.ExceptionUtils;

import agent.gdb.manager.impl.cmd.GdbCommandError;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerModelClosedReason;
import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.error.DebuggerModelTerminatingException;
import ghidra.dbg.error.DebuggerUserException;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.AnnotatedSchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.util.Msg;
import yetmorecode.ghidra.console.CommandError;
import yetmorecode.ghidra.dosbox.manager.DosboxManager;
import yetmorecode.ghidra.dosbox.model.target.SessionModel;

public class DosboxModel extends AbstractDebuggerObjectModel {
	
	protected static final String SPACE_NAME = "ram";
	
	protected static final AnnotatedSchemaContext SCHEMA_CTX = new AnnotatedSchemaContext();
	protected static final TargetObjectSchema ROOT_SCHEMA =
		SCHEMA_CTX.getSchemaForClass(SessionModel.class);
	
	protected final AddressSpace space =
		new GenericAddressSpace(SPACE_NAME, 64, AddressSpace.TYPE_RAM, 0);
	protected final AddressFactory addressFactory =
		new DefaultAddressFactory(new AddressSpace[] { space });
	
	public DosboxManager dosboxManager;
	private SessionModel session;
	protected final CompletableFuture<SessionModel> completedSession;
	protected String hostname = "localhost";
	protected int port = 3000;
	protected Map<Object, TargetObject> objectMap = new HashMap<>();
	
	public DosboxModel(String hostname, int port) {
		super();
		this.hostname = hostname;
		this.port = port;
		dosboxManager = new DosboxManager(hostname, port);
		session = new SessionModel(this, ROOT_SCHEMA);
		completedSession = CompletableFuture.completedFuture(session);
	}
	
	public CompletableFuture<Void> start() {
		return CompletableFuture.runAsync(() -> {
			try {
				// connect to dosbox
				dosboxManager.start();
			}
			catch (IOException e) {
				throw new DebuggerModelTerminatingException("Cannot connect to DOSBox-X: " + e.getMessage(), e);
			}
		}).thenCompose(__ -> {
			return dosboxManager.runRC();
		});
	}
	
	@Override
	public AddressFactory getAddressFactory() {
		return addressFactory;
	}

	public void terminate() throws IOException {
		Msg.info(this, "terminate model");
		listeners.fire.modelClosed(DebuggerModelClosedReason.NORMAL);
		session.invalidateSubtree(session, "dosbox is terminating");
		dosboxManager.terminate();
	}

	@Override
	public String getBrief() {
		return String.format("DOSBox-X (%s:%d)", hostname, port);
	}
	
	@Override
	public CompletableFuture<? extends TargetObject> fetchModelRoot() {
		return completedSession;
	}

	@Override
	public boolean isAlive() {
		return dosboxManager.getState().isAlive();
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
	
	public static <T> T translateEx(Throwable ex) {
		Throwable t = AsyncUtils.unwrapThrowable(ex);
		if (t instanceof CommandError) {
			CommandError err = (CommandError) t;
			throw new DebuggerUserException(err.getInfo());
		}
		return ExceptionUtils.rethrow(ex);
	}

	public void addModelObject(Object object, TargetObject targetObject) {
		objectMap.put(object, targetObject);
	}

	public TargetObject getModelObject(Object object) {
		return objectMap.get(object);
	}

	public void deleteModelObject(Object object) {
		objectMap.remove(object);
	}
}
