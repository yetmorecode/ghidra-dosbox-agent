package yetmorecode.ghidra.dosbox.model.objects;

import java.util.Set;
import java.util.concurrent.CompletableFuture;

import org.bouncycastle.util.Arrays;

import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetMemory;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;

@TargetObjectSchemaInfo(
		name = "Memory",
		elementResync = ResyncMode.ALWAYS,
		elements = {
			@TargetElementType(type = DosboxMemoryRegion.class)
		},
		attributes = {
			@TargetAttributeType(type = Void.class) },
		canonicalContainer = true)
public class DosboxMemory
	extends DefaultTargetObject<TargetObject, DosboxModelRoot> 
	implements TargetMemory {

	DosboxMemoryRegion r1;

	public DosboxMemory(AbstractDebuggerObjectModel model, DosboxModelRoot parent) {
		super(model, parent, "Memory", "Memory");
		
		r1 = new DosboxMemoryRegion(model, this, "bmh.exe", 0x10000, 0x6a94a);
		setElements(Set.of(r1), "Regions Initialized");
		
	}

	@Override
	public CompletableFuture<byte[]> readMemory(Address address, int length) {
		//Msg.info(this, "reading memory at " + address.toString() + ", length = " + length);
		var mem = new byte[length];
		Arrays.fill(mem, (byte) (address.getOffset() % 0xff));
		listeners.fire.memoryUpdated(this, address, mem);
		return CompletableFuture.completedFuture(mem);
	}

	@Override
	public CompletableFuture<Void> writeMemory(Address address, byte[] data) {
		Msg.info(this, "writing memory");
		return null;
	}

}
