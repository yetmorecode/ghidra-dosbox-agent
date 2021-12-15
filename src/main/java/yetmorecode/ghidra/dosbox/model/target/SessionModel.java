package yetmorecode.ghidra.dosbox.model.target;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.gdb.manager.GdbCause;
import agent.gdb.manager.GdbManager;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetModelRoot;
import ghidra.dbg.target.TargetAccessConditioned;
import ghidra.dbg.target.TargetActiveScope;
import ghidra.dbg.target.TargetAttachable;
import ghidra.dbg.target.TargetAttacher;
import ghidra.dbg.target.TargetConsole;
import ghidra.dbg.target.TargetEventScope;
import ghidra.dbg.target.TargetFocusScope;
import ghidra.dbg.target.TargetInterpreter;
import ghidra.dbg.target.TargetInterruptible;
import ghidra.dbg.target.TargetLauncher;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.util.Msg;
import yetmorecode.ghidra.console.Cause;
import yetmorecode.ghidra.console.ConsoleOutputListener;
import yetmorecode.ghidra.dosbox.manager.BreakpointInfo;
import yetmorecode.ghidra.dosbox.manager.DosboxEventsListener;
import yetmorecode.ghidra.dosbox.model.DosboxModel;
import yetmorecode.ghidra.dosbox.model.SelectableObject;

@TargetObjectSchemaInfo(
	name = "Dosbox",
	elements = { @TargetElementType(type = Void.class) },
	attributes = { @TargetAttributeType(type = Void.class) }
)
public class SessionModel extends DefaultTargetModelRoot implements 
	TargetAccessConditioned, TargetAttacher, TargetInterpreter, TargetInterruptible,
	TargetLauncher, TargetActiveScope, TargetEventScope, TargetFocusScope, DosboxEventsListener, ConsoleOutputListener {
	public DosboxModel model;
	protected String display = "DOSBox-X";
	private boolean accessible = true;
	protected SelectableObject focus;
	
	private InferiorContainerModel inferiors;
	protected String debugger = "dosbox"; // Used by GdbModelTargetEnvironment
	
	public SessionModel(DosboxModel m, TargetObjectSchema schema) {
		super(m, "Dosbox", schema);
		model = m;
		inferiors = new InferiorContainerModel(this);
		
		changeAttributes(List.of(), Map.of( //
			inferiors.getName(), inferiors, //
			//available.getName(), available, //
			//breakpoints.getName(), breakpoints, //
			ACCESSIBLE_ATTRIBUTE_NAME, accessible, //
			PROMPT_ATTRIBUTE_NAME, "session> ", //
			DISPLAY_ATTRIBUTE_NAME, display, //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME, InferiorModel.PARAMETERS, //
			SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME, InferiorModel.SUPPORTED_KINDS, //
			FOCUS_ATTRIBUTE_NAME, this // Satisfy schema. Will be set to first inferior.
		), "Initialized");
		
		model.dosboxManager.addEventsListener(this);
		model.dosboxManager.addConsoleOutputListener(this);

		getVersion();
		
	}
	
	@TargetAttributeType(name = InferiorContainerModel.NAME, required = true, fixed = true)
	public InferiorContainerModel getInferiors() {
		return inferiors;
	}
	
	protected void getVersion() {
		Msg.info(this, "session model: get version");
		model.dosboxManager.waitForPrompt().thenCompose(__ -> {
			return model.dosboxManager.consoleCapture("i");
		}).thenAccept(out -> {
			debugger = out;
			changeAttributes(List.of(),
				Map.of(DISPLAY_ATTRIBUTE_NAME, display = out.split(":")[1].strip() //
			), "Version refreshed");
		}).exceptionally(e -> {
			model.reportError(this, "Could not get GDB version", e);
			debugger = "dosbox";
			return null;
		});
	}

	public String getDisplay() {
		return display;
	}

	public void output(GdbManager.Channel gdbChannel, String out) {
		TargetConsole.Channel dbgChannel;
		switch (gdbChannel) {
			case STDOUT:
				dbgChannel = TargetConsole.Channel.STDOUT;
				break;
			case STDERR:
				dbgChannel = TargetConsole.Channel.STDERR;
				break;
			default:
				throw new AssertionError();
		}
		listeners.fire.consoleOutput(this, dbgChannel, out);
	}

	public void inferiorSelected(InferiorModel inferior, GdbCause cause) {
		InferiorModel inf = inferiors.getTargetInferior(inferior);
		setFocus(inf);
	}
	
	protected void setFocus(SelectableObject focus) {
		changeAttributes(List.of(), Map.of( //
			FOCUS_ATTRIBUTE_NAME, this.focus = focus //
		), "Focus changed");
	}

	public CompletableFuture<Void> launch(Map<String, ?> args) {
		/*
		List<String> cmdLineArgs =
			CmdLineParser.tokenize(TargetCmdLineLauncher.PARAMETER_CMDLINE_ARGS.get(args));
		Boolean useStarti = GdbModelTargetInferior.PARAMETER_STARTI.get(args);
		return impl.gateFuture(impl.gdb.availableInferior().thenCompose(inf -> {
			return GdbModelImplUtils.launch(inf, cmdLineArgs, useStarti, () -> {
				return inferiors.getTargetInferior(inf).environment.refreshInternal();
			});
		}).thenApply(__ -> null));
		*/
		Msg.debug(this,  "Launching new inferior huhu");
		return CompletableFuture.completedFuture(null);
	}

	public CompletableFuture<Void> attach(TargetAttachable attachable) {
		Msg.debug(this, "attach");
		return CompletableFuture.completedFuture(null);
	}

	public CompletableFuture<Void> attach(long pid) {
		/*
		return impl.gateFuture(impl.gdb.availableInferior().thenCompose(inf -> {
			return inf.attach(pid).thenApply(__ -> null);
		}));
		*/
		Msg.debug(this, "attach");
		return CompletableFuture.completedFuture(null);
	}

	public CompletableFuture<Void> interrupt() {
		// int
		return AsyncUtils.NIL;
	}

	public CompletableFuture<Void> execute(String cmd) {
		return model.gateFuture(model.dosboxManager.console(cmd).exceptionally(DosboxModel::translateEx));
	}

	@Override
	public CompletableFuture<Void> requestFocus(TargetObject obj) {
		Msg.debug(this, "request focus");
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<String> executeCapture(String cmd) {
		Msg.info(this, "execute capture");
		return CompletableFuture.completedFuture("output");
	}

	public CompletableFuture<Void> writeConfigurationOption(String key, Object value) {
		Msg.debug(this,  "write config");
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<Void> requestActivation(TargetObject obj) {
		Msg.debug(this,  "request activation");
		return AsyncUtils.NIL;
	}

	@Override
	public void output(String out) {
		Msg.info(this, "output() " + out);
	}

	public void breakpointDeleted(BreakpointInfo info, Cause cause) {
		Msg.info(this,  "breakpoint deleted");
	}

}
