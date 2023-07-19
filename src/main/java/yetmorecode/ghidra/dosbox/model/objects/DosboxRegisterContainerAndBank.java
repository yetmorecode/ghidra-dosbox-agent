package yetmorecode.ghidra.dosbox.model.objects;

import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncUtils;
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
			@TargetAttributeType(type = Void.class) },
		canonicalContainer = true)
public class DosboxRegisterContainerAndBank
	extends DefaultTargetObject<TargetObject, TargetObject> 
	implements TargetRegisterContainer, TargetRegisterBank {

	public Map<String, byte[]> bankValues = new LinkedHashMap<>();
	
	public DosboxRegisterContainerAndBank(AbstractDebuggerObjectModel model, TargetObject parent) {
		super(model, parent, "Registers", "Registers");
		
		var registerElements = new LinkedList<DosboxRegister>();
		registerElements.push(new DosboxRegister(model, this, "eax", Long.valueOf(0x12345678)));
		registerElements.push(new DosboxRegister(model, this, "ebx", Long.valueOf(0x1001c)));
		registerElements.push(new DosboxRegister(model, this, "ecx"));
		registerElements.push(new DosboxRegister(model, this, "edx"));
		registerElements.push(new DosboxRegister(model, this, "esp"));
		registerElements.push(new DosboxRegister(model, this, "ebp"));
		registerElements.push(new DosboxRegister(model, this, "eip", Long.valueOf(0x1001a)));
		registerElements.push(new DosboxRegister(model, this, "esi"));
		registerElements.push(new DosboxRegister(model, this, "edi"));
		changeElements(List.of(), registerElements, "Added registers");
		
		changeAttributes(List.of(), Map.of(DESCRIPTIONS_ATTRIBUTE_NAME, this), "Init");
		
		bankValues.put("eax", new byte[] { (byte) 0xaa, 0x34, 0x56, 0x78 });
		bankValues.put("ebx", new byte[] { 0x12, 0x34, 0x56, 0x78 });
		bankValues.put("ecx", new byte[] { 0x12, 0x34, 0x56, 0x78 });
		
		getListeners().fire.invalidateCacheRequested(this);
		getListeners().fire.registersUpdated(this, bankValues);
	}
	
	@Override
	public CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(Collection<String> names) {
		Msg.info(this, "read regs");
		
		for (var name : names) {
			Msg.info(this, name);
		}
		
		return CompletableFuture.completedFuture(bankValues);
	}

	@Override
	public CompletableFuture<Void> writeRegistersNamed(Map<String, byte[]> values) {
		Msg.info(this, "write regs");
		return AsyncUtils.NIL;
	}
}
