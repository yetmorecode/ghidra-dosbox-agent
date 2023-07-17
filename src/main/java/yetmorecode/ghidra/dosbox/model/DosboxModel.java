package yetmorecode.ghidra.dosbox.model;

import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerModelClosedReason;
import ghidra.dbg.DebuggerObjectModelWithMemory;
import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.target.TargetMemory;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.AnnotatedSchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import yetmorecode.ghidra.dosbox.model.objects.DosboxModelRoot;


public class DosboxModel extends AbstractDebuggerObjectModel implements DebuggerObjectModelWithMemory {
	public static final String DOSBOX_ADDRESS_SPACE = "ram";
	
	protected static final AnnotatedSchemaContext SCHEMA_CTX = new AnnotatedSchemaContext();
	protected static final TargetObjectSchema ROOT_SCHEMA =
		SCHEMA_CTX.getSchemaForClass(DosboxModelRoot.class);
	
	
	protected final AddressFactory addressFactory = new DefaultAddressFactory(
			new AddressSpace[] { new GenericAddressSpace(DOSBOX_ADDRESS_SPACE, 32, AddressSpace.TYPE_RAM, 0) });
	protected String hostname = "localhost";
	protected int port = 2999;
	
	protected DosboxModelRoot rootNode;
	
	public DosboxModel(String hostname, int port) {
		super();
		this.hostname = hostname;
		this.port = port;
		rootNode = new DosboxModelRoot(this, ROOT_SCHEMA);
		addModelRoot(rootNode);
	}
	
	@Override
	public AddressFactory getAddressFactory() {
		return addressFactory;
	}
	
	@Override
	public String getBrief() {
		return String.format("DOSBox-X (%s:%d)", hostname, port);
	}
	
	@Override
	public TargetObjectSchema getRootSchema() {
		return ROOT_SCHEMA;
	}
	
	
	public CompletableFuture<Void> start() {
		listeners.fire.modelOpened();
		
		return AsyncUtils.NIL;
	}
	
	@Override
	public CompletableFuture<Void> close() {
		listeners.fire.modelClosed(DebuggerModelClosedReason.NORMAL);
		getModelRoot().invalidateSubtree(getModelRoot(), "Dosbox is terminating");
		return super.close();
	}

	@Override
	public TargetMemory getMemory(TargetObject target, Address address, int length) {
		return rootNode.memory;
	}
}
