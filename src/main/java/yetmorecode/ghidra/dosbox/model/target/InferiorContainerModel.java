package yetmorecode.ghidra.dosbox.model.target;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetConfigurable;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.util.Msg;
import yetmorecode.ghidra.dosbox.model.DosboxModel;

@TargetObjectSchemaInfo(
		name = "InferiorContainer",
		attributes = {
			@TargetAttributeType(name = TargetConfigurable.BASE_ATTRIBUTE_NAME, type = Integer.class), //
			@TargetAttributeType(type = Void.class) //
		},
		canonicalContainer = true)
public class InferiorContainerModel extends DefaultTargetObject<InferiorModel, SessionModel>
implements TargetConfigurable {
	
	protected final DosboxModel impl;

	public InferiorContainerModel(SessionModel session) {
		super(session.model, session, NAME, "InferiorContainer");
		impl = session.model;
		changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, 10), "Initialized");

		//model.gdb.addEventsListener(this);
	}

	public static final String NAME = "Inferiors";

	@Override
	public CompletableFuture<Void> writeConfigurationOption(String key, Object value) {
		Msg.debug(this, "writing config");
		return CompletableFuture.completedFuture(null);
	}
	
	public synchronized InferiorModel getTargetInferior(InferiorModel inferior) {
		/*
		TargetObject modelObject = impl.getModelObject(inferior);
		if (modelObject != null) {
			return (Inferior) modelObject;
		}
		return new Inferior(this, inferior);
		*/
		return null;
	}

}
