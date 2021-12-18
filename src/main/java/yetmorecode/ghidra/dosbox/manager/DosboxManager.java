package yetmorecode.ghidra.dosbox.manager;

import java.io.IOException;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;

import agent.gdb.manager.evt.GdbCommandConnectedEvent;
import agent.gdb.manager.evt.GdbCommandDoneEvent;
import agent.gdb.manager.evt.GdbCommandEchoEvent;
import agent.gdb.manager.evt.GdbCommandErrorEvent;
import agent.gdb.manager.evt.GdbCommandExitEvent;
import agent.gdb.manager.evt.GdbCommandRunningEvent;
import agent.gdb.manager.evt.GdbConsoleOutputEvent;
import agent.gdb.manager.evt.GdbDebugOutputEvent;
import agent.gdb.manager.evt.GdbRunningEvent;
import agent.gdb.manager.evt.GdbStoppedEvent;
import agent.gdb.manager.evt.GdbTargetOutputEvent;
import ghidra.async.AsyncReference;
import ghidra.dbg.util.HandlerMap;
import ghidra.dbg.util.PrefixMap;
import ghidra.util.Msg;
import yetmorecode.ghidra.console.ConsoleManager;
import yetmorecode.ghidra.console.ConsoleOutputListener;
import yetmorecode.ghidra.console.ParseError;
import yetmorecode.ghidra.console.TCPConsoleManager;
import yetmorecode.ghidra.console.TargetEventsListener;
import yetmorecode.ghidra.console.TargetOutputListener;
import yetmorecode.ghidra.console.TargetState;
import yetmorecode.ghidra.console.Cause.Causes;
import yetmorecode.ghidra.console.TargetStateListener;
import yetmorecode.ghidra.console.command.Command;
import yetmorecode.ghidra.console.command.ConsoleExecCommand;
import yetmorecode.ghidra.console.event.CommandCompletedEvent;
import yetmorecode.ghidra.console.event.Event;
import yetmorecode.ghidra.dosbox.manager.command.DosboxEvent;
import yetmorecode.ghidra.dosbox.manager.command.run.RunningEvent;
import yetmorecode.ghidra.dosbox.manager.command.stop.StoppedEvent;


public class DosboxManager implements ConsoleManager {
	//private final AsyncTimer timer = AsyncTimer.DEFAULT_TIMER;
	private final AtomicBoolean exited = new AtomicBoolean(false);
	private final AsyncReference<Boolean, Void> prompt = new AsyncReference<>(false);	
	protected String hostname = "localhost";
	protected int port = 3000;
	private boolean terminated = false;
	
	private ConsoleManager consoleManager;
	
	public static void main(String[] args)
			throws InterruptedException, ExecutionException {
		DosboxManager mgr = new DosboxManager("localhost", 3000);
		Msg.info(mgr, "Starting standalone DosboxManager");
		try {
			mgr.start();
			mgr.runRC().get();
			Msg.info(mgr, "Waiting for commands..");
			mgr.consoleLoop();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		Msg.info(mgr, "Done.");
	}
	
	public DosboxManager(String hostname, int port) {
		this.hostname = hostname;
		this.port = port;
		consoleManager = new TCPConsoleManager(hostname, port);
		
		var handlerMap = getHandlerMap();
		handlerMap.putVoid(RunningEvent.class, this::processRunning);
		handlerMap.putVoid(StoppedEvent.class, this::processStopped);
		handlerMap.putVoid(CommandCompletedEvent.class, this::processCommandDone);
		
		var prefixMap = getPrefixMap();
		// version
		prefixMap.put("v", CommandCompletedEvent::new);
		// state
		prefixMap.put("s", CommandCompletedEvent::new);
		// regs
		prefixMap.put("r", CommandCompletedEvent::new);
		// error
		prefixMap.put("e", CommandCompletedEvent::new);
		// out
		prefixMap.put("o", CommandCompletedEvent::new);
		prefixMap.put("bp", CommandCompletedEvent::new);
		prefixMap.put("-", GdbCommandEchoEvent::new);
		prefixMap.put("~", GdbConsoleOutputEvent::fromMi2);
		prefixMap.put("@", GdbTargetOutputEvent::new);
		prefixMap.put("&", GdbDebugOutputEvent::new);

		prefixMap.put("^done", GdbCommandDoneEvent::new);
		prefixMap.put("^running", GdbCommandRunningEvent::new);
		prefixMap.put("^connected", GdbCommandConnectedEvent::new);
		prefixMap.put("^exit", GdbCommandExitEvent::new);
		prefixMap.put("^error", GdbCommandErrorEvent::fromMi2);

		prefixMap.put("*running", GdbRunningEvent::new);
		prefixMap.put("*stopped", GdbStoppedEvent::new);

	}
	
	/**
	 * Handler for "^done"
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processCommandDone(CommandCompletedEvent evt, Void v) {
		checkClaimed(evt);
	}
	
	protected void checkClaimed(DosboxEvent evt) {
		if (evt.getCause() == Causes.UNCLAIMED) {
			if (evt instanceof CommandCompletedEvent) {
				CommandCompletedEvent completed = (CommandCompletedEvent) evt;
				String msg = completed.assumeMsg();
				if (msg != null) {
					/*
					if (evt instanceof GdbCommandErrorEvent) {
						Msg.error(this, msg);
					}
					*/
					
					Msg.info(this, msg);
					throw new AssertionError("Command completion left unclaimed!");
				}
			}
		}
	}
	
	/**
	 * Handler for "*running"
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processRunning(RunningEvent evt, Void v) {
		Msg.info(this,  "process running");
		/*
		String threadId = evt.assumeThreadId();
		if (threadId == null) {
			threadId = "all";
		}
		if ("all".equals(threadId)) {
			GdbInferiorImpl cur = curInferior;
			event(() -> {
				listenersEvent.fire.inferiorStateChanged(cur, cur.getKnownThreads().values(),
					evt.newState(), null, evt.getCause(), evt.getReason());
			}, "inferiorState-running");
			for (GdbThreadImpl thread : curInferior.getKnownThreadsImpl().values()) {
				thread.setState(evt.newState(), evt.getCause(), evt.getReason());
			}
		}
		else {
			int id = Integer.parseUnsignedInt(threadId);
			GdbThreadImpl thread = threads.get(id);
			event(() -> {
				listenersEvent.fire.inferiorStateChanged(thread.getInferior(),
					List.of(thread), evt.newState(), null, evt.getCause(), evt.getReason());
			}, "inferiorState-running");
			thread.setState(evt.newState(), evt.getCause(), evt.getReason());
		}
		*/
	}
	
	/**
	 * Handler for "*stopped"
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processStopped(StoppedEvent evt, Void v) {
		/*
		String stoppedThreadsStr = evt.assumeStoppedThreads();
		Collection<GdbThreadImpl> stoppedThreads;
		if (null == stoppedThreadsStr || "all".equals(stoppedThreadsStr)) {
			stoppedThreads = threads.values();
		}
		else {
			stoppedThreads = new LinkedHashSet<>();
			for (String stopped : stoppedThreadsStr.split(",")) {
				stoppedThreads.add(threads.get(Integer.parseInt(stopped)));
			}
		}

		Integer tid = evt.getThreadId();
		GdbThreadImpl evtThread = tid == null ? null : threads.get(tid);
		Map<GdbInferior, Set<GdbThread>> byInf = new LinkedHashMap<>();
		for (GdbThreadImpl thread : stoppedThreads) {
			thread.setState(evt.newState(), evt.getCause(), evt.getReason());
			byInf.computeIfAbsent(thread.getInferior(), i -> new LinkedHashSet<>()).add(thread);
		}
		for (Map.Entry<GdbInferior, Set<GdbThread>> ent : byInf.entrySet()) {
			event(() -> {
				listenersEvent.fire.inferiorStateChanged(ent.getKey(), ent.getValue(),
					evt.newState(), evtThread, evt.getCause(), evt.getReason());
			}, "inferiorState-stopped");
		}
		if (evtThread != null) {
			GdbStackFrameImpl frame = evt.getFrame(evtThread);
			event(() -> listenersEvent.fire.threadSelected(evtThread, frame, evt),
				"inferiorState-stopped");
		}
		*/
	}
	
	public ConsoleManager getConsoleManager() {
		return consoleManager;
	}
	
	public void addConsoleOutputListener(ConsoleOutputListener listener) {
		consoleManager.addConsoleOutputListener(listener);
	}

	public void removeConsoleOutputListener(ConsoleOutputListener listener) {
		consoleManager.removeConsoleOutputListener(listener);
	}
	
	public void start(String... args) throws IOException {
		consoleManager.start(args);
	}
	
	public synchronized TargetState getState() {
		return consoleManager.getState();
	}
	
	public boolean isAlive() {
		return consoleManager.isAlive();
	}
	
	public <T> CompletableFuture<T> execute(Command<? extends T> cmd) {
		return consoleManager.execute(cmd);
	}
	
	public void consoleLoop() throws IOException {
		consoleManager.consoleLoop();
	}
	
	public CompletableFuture<Void> runRC() {
		return consoleManager.runRC();
	}

	/**
	 * Execute commands upon GDB startup
	 * 
	 * @return a future which completes when the rc commands are complete
	 */
	public CompletableFuture<Void> initialize() {
		return consoleManager.initialize();
	}
	
	public synchronized void terminate() {
		if (terminated) {
			return;
		}
		exited.set(true);
		consoleManager.terminate();
		terminated = true;
	}
	
	public void submit(Runnable runnable) {
		consoleManager.submit(runnable);
	}
	
	public synchronized void processLine(String line) {
		consoleManager.processLine(line);
	}
	
	public void addTargetOutputListener(TargetOutputListener listener) {
		consoleManager.addTargetOutputListener(listener);
	}

	public void removeTargetOutputListener(TargetOutputListener listener) {
		consoleManager.removeTargetOutputListener(listener);
	}
	
	public void addStateListener(TargetStateListener listener) {
		consoleManager.addStateListener(listener);
	}

	public void removeStateListener(TargetStateListener listener) {
		consoleManager.removeStateListener(listener);
	}

	public CompletableFuture<Void> waitForPrompt() {
		return prompt.waitValue(true);
	}
	
	public CompletableFuture<Void> console(String command) {
		Msg.info(this, "command: " + command);
		return execute(new ConsoleExecCommand(this.getConsoleManager(), command)).thenApply(e -> null);
	}

	public CompletableFuture<String> consoleCapture(String command) {
		return execute(new ConsoleExecCommand(this.getConsoleManager(), command));
	}

	@Override
	public void addEventsListener(TargetEventsListener listener) {
		consoleManager.addEventsListener(listener);
	}

	@Override
	public void removeEventsListener(TargetEventsListener listener) {
		consoleManager.removeEventsListener(listener);
	}

	@Override
	public void synthesizeConsoleOut(String line) {
		consoleManager.synthesizeConsoleOut(line);
	}

	@Override
	public HandlerMap<Event<?>, Void, Void> getHandlerMap() {
		return consoleManager.getHandlerMap();
	}

	@Override
	public PrefixMap<DosboxEvent, ParseError> getPrefixMap() {
		return consoleManager.getPrefixMap();
	}
}
