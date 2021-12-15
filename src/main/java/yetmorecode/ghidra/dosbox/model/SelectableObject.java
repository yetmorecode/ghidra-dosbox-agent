package yetmorecode.ghidra.dosbox.model;

import java.util.concurrent.CompletableFuture;

import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

/**
 * Interface for selectable model object that may become active in the future
 * 
 * @author https://github.com/yetmorecode
 */
@TargetObjectSchemaInfo(name = "Selectable", attributes = { @TargetAttributeType(type = Void.class) })
public interface SelectableObject extends TargetObject {
	CompletableFuture<Void> setActive();
}
