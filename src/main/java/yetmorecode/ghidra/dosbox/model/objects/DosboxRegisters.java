package yetmorecode.ghidra.dosbox.model.objects;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.dbg.target.TargetRegisterContainer;
import ghidra.dbg.target.TargetStack;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.util.Msg;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;

@TargetObjectSchemaInfo(
		name = "Registers",
		elements = {
			@TargetElementType(type = DosboxRegister.class) },
		elementResync = ResyncMode.ALWAYS, //
		attributes = {
			@TargetAttributeType(
				name = TargetRegisterBank.DESCRIPTIONS_ATTRIBUTE_NAME,
				type = DosboxRegisters.class),
			@TargetAttributeType(type = Void.class) },
		canonicalContainer = true)
public class DosboxRegisters
	extends DefaultTargetObject<TargetObject, DosboxStackFrame> 
	implements TargetRegisterBank, TargetRegisterContainer, TargetStack {

	private Map<String, byte[]> m = new HashMap<>();
	
	public DosboxRegisters(AbstractDebuggerObjectModel model, DosboxStackFrame parent) {
		super(model, parent, "Registers", "Registers");
		
		
		DosboxRegister eax = new DosboxRegister(model, this, "eax");
		DosboxRegister ebx = new DosboxRegister(model, this, "ebx");
		
		m.put("eax", new byte[] { 0x12, 0x23, 0x45, 0x66 });
		m.put("ebx", new byte[] { 0x12, 0x23, 0x34, 0x56 });
		
		setElements(List.of(eax, ebx), "Added registers");
		setAttributes(Map.of( //
			DESCRIPTIONS_ATTRIBUTE_NAME, this //
		), "Initialized");
		
		getListeners().fire.registersUpdated(getProxy(), m);
	}

	@Override
	public CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(Collection<String> names) {
		Msg.info(this, "read regs");
		for (var name : names) {
			Msg.info(this, name);
		}
		return CompletableFuture.completedFuture(m);
	}

	@Override
	public CompletableFuture<Void> writeRegistersNamed(Map<String, byte[]> values) {
		// TODO Auto-generated method stub
		Msg.info(this, "write regs");
		return null;
	}

}
