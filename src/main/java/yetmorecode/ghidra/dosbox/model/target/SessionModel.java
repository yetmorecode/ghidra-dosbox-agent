package yetmorecode.ghidra.dosbox.model.target;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncFence;
import ghidra.async.AsyncLazyValue;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetModelRoot;
import ghidra.dbg.target.TargetAccessConditioned;
import ghidra.dbg.target.TargetActiveScope;
import ghidra.dbg.target.TargetAttachable;
import ghidra.dbg.target.TargetAttacher;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.TargetEventScope;
import ghidra.dbg.target.TargetFocusScope;
import ghidra.dbg.target.TargetInterpreter;
import ghidra.dbg.target.TargetInterruptible;
import ghidra.dbg.target.TargetLauncher;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetAttacher.TargetAttachKind;
import ghidra.dbg.target.TargetAttacher.TargetAttachKindSet;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.util.Msg;
import yetmorecode.ghidra.console.Cause;
import yetmorecode.ghidra.console.ConsoleOutputListener;
import yetmorecode.ghidra.dosbox.manager.DosboxEventsListener;
import yetmorecode.ghidra.dosbox.manager.command.DosboxCommand;
import yetmorecode.ghidra.dosbox.manager.command.breakpoint.Breakpoint;
import yetmorecode.ghidra.dosbox.manager.command.register.ListRegisterNamesCommand;
import yetmorecode.ghidra.dosbox.manager.command.register.Register;
import yetmorecode.ghidra.dosbox.manager.command.register.RegisterSet;
import yetmorecode.ghidra.dosbox.model.DosboxModel;
import yetmorecode.ghidra.dosbox.model.SelectableObject;

@TargetObjectSchemaInfo(
	name = "Dosbox",
	elements = { @TargetElementType(type = Void.class) },
	attributes = { @TargetAttributeType(type = Void.class) }
)
public class SessionModel extends DefaultTargetModelRoot implements 
	TargetAccessConditioned, TargetInterpreter, TargetInterruptible,
	TargetActiveScope, TargetEventScope, TargetFocusScope, DosboxEventsListener, ConsoleOutputListener {
	public DosboxModel model;
	protected String display = "DOSBox-X";
	private boolean accessible = true;
	protected SelectableObject focus;
	
	private final RegisterContainerModel registersContainer;
	//private final EnvironmentModel environment;
	//private final SegmentContainerModel segmentContainer;
	//private final InterruptContainerModel interruptContainer;

	protected String debugger = "dosbox"; // Used by GdbModelTargetEnvironment
	
	private final AsyncLazyValue<RegisterSet> registers =
			new AsyncLazyValue<>(this::doListRegisters);
	
	protected static final TargetAttachKindSet SUPPORTED_KINDS = TargetAttachKindSet.of( //
			TargetAttachKind.BY_OBJECT_REF, TargetAttachKind.BY_ID);
	
	public static final TargetParameterMap PARAMETERS =
			TargetMethod.makeParameters();
	
	public SessionModel(DosboxModel m, TargetObjectSchema schema) {
		super(m, "Dosbox", schema);
		model = m;
		registersContainer = new RegisterContainerModel(this);
		//environment = new EnvironmentModel(this);
		//segmentContainer = new SegmentContainerModel(this);
		//interruptContainer = new InterruptContainerModel(this);
		
		changeAttributes(List.of(), Map.of( //
			registersContainer.getName(), registersContainer, //
			//environment.getName(), environment,
			//segmentContainer.getName(), segmentContainer,
			//interruptContainer.getName(), interruptContainer,
			//available.getName(), available, //
			//breakpoints.getName(), breakpoints, //
			ACCESSIBLE_ATTRIBUTE_NAME, accessible, //
			PROMPT_ATTRIBUTE_NAME, "dosbox> ", //
			DISPLAY_ATTRIBUTE_NAME, display, //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME, PARAMETERS, //
			FOCUS_ATTRIBUTE_NAME, this // Satisfy schema. Will be set to first inferior.
		), "Initialized");
		
		model.dosboxManager.addEventsListener(this);
		model.dosboxManager.addConsoleOutputListener(this);

		getVersion();
		
	}
	
	@TargetAttributeType(name = "Registers", required = true, fixed = true)
	public RegisterContainerModel getRegisters() {
		return registersContainer;
	}
	
	
	public CompletableFuture<RegisterSet> listRegisters() {
		return registers.request();
	}
	
	private CompletableFuture<RegisterSet> doListRegisters() {
		Map<Integer, String> namesByNumber = new TreeMap<>();
		return execute(new ListRegisterNamesCommand(model.dosboxManager)).thenCompose(response -> {
			
			Msg.info(this, "list regs: " + response);
			
			/*
			for (int i = 0; i < names.size(); i++) {
				String n = names.get(i);
				if ("".equals(n)) {
					continue;
				}
				namesByNumber.put(i, n);
			}
			*/
			return doEvaluateSizesInParts(namesByNumber.values());
		}).thenApply(values -> {
			List<Register> regs = new ArrayList<>();
			List<Integer> sizes = new ArrayList<>();
			/*
			for (String v : values) {
				try {
					sizes.addAll(GdbCValueParser.parseArray(v).expectInts());
				}
				catch (GdbParseError e) {
					throw new AssertionError("GDB did not give an integer array!");
				}
			}
			*/
			if (sizes.size() != namesByNumber.size()) {
				throw new AssertionError("GDB did not give all the sizes!");
			}
			Iterator<Integer> sit = sizes.iterator();
			Iterator<Map.Entry<Integer, String>> eit = namesByNumber.entrySet().iterator();
			while (sit.hasNext()) {
				int size = sit.next();
				Map.Entry<Integer, String> ent = eit.next();
				regs.add(new Register(ent.getValue(), ent.getKey(), size));
			}
			return new RegisterSet(regs);
		});
	}
	
	private CompletableFuture<List<String>> doEvaluateSizesInParts(Collection<String> names) {
		List<String> parts = generateEvaluateSizesParts(names);
		if (parts.isEmpty()) {
			// I guess names was empty
			return CompletableFuture.completedFuture(List.of());
		}
		if (parts.size() == 1) {
			return evaluate(parts.get(0)).thenApply(List::of);
		}
		AsyncFence fence = new AsyncFence();
		String[] result = new String[parts.size()];
		for (int i = 0; i < result.length; i++) {
			String p = parts.get(i);
			final int j = i;
			fence.include(evaluate(p).thenAccept(r -> {
				result[j] = r;
			}));
		}
		return fence.ready().thenApply(__ -> Arrays.asList(result));
	}
	
	public CompletableFuture<String> evaluate(String expression) {
		return CompletableFuture.completedFuture(expression);
	}

	
	private List<String> generateEvaluateSizesParts(Collection<String> names) {
		List<String> result = new ArrayList<>();
		/*
		StringBuffer buf = new StringBuffer("{");
		for (String n : names) {
			String toAdd = "sizeof($" + n + "),";
			if (buf.length() + toAdd.length() > GdbEvaluateCommand.MAX_EXPR_LEN) {
				assert buf.length() > 0;
				// Remove trailing comma
				result.add(buf.substring(0, buf.length() - 1) + "}");
				buf.delete(1, buf.length()); // Leave leading brace
			}
			buf.append(toAdd);
		}
		if (buf.length() > 0) {
			result.add(buf.substring(0, buf.length() - 1) + "}");
		}
		*/
		return result;
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

	protected CompletableFuture<String> execute(DosboxCommand<? extends String> cmd) {
		return model.dosboxManager.execute(cmd);
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
		listeners.fire.consoleOutput(this, Channel.STDOUT, out + "\n\n");
	}

	public void breakpointDeleted(Breakpoint info, Cause cause) {
		Msg.info(this,  "breakpoint deleted");
	}

}
