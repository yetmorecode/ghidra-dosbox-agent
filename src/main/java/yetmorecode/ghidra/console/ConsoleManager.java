package yetmorecode.ghidra.console;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.exception.ExceptionUtils;

import ghidra.async.AsyncLock;
import ghidra.async.AsyncReference;
import ghidra.async.AsyncUtils;
import ghidra.async.AsyncLock.Hold;
import ghidra.dbg.error.DebuggerModelTerminatingException;
import ghidra.dbg.util.HandlerMap;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListenerSet;
import sun.misc.Signal;
import sun.misc.SignalHandler;
import yetmorecode.ghidra.console.Cause.Causes;
import yetmorecode.ghidra.console.command.Command;
import yetmorecode.ghidra.console.command.ConsoleExecCommand;
import yetmorecode.ghidra.console.command.PendingCommand;
import yetmorecode.ghidra.console.event.ConsoleOutputEvent;
import yetmorecode.ghidra.console.event.Event;
import yetmorecode.ghidra.console.io.InputOutputThread;
import yetmorecode.ghidra.dosbox.manager.DosboxEventsListener;


public class ConsoleManager {
	/**
	 * An interface for taking lines of input
	 */
	public interface LineReader {
		String readLine(String prompt) throws IOException;
	}
	
	
	public static class BufferedReaderLineReader implements LineReader {
		private BufferedReader reader;

		BufferedReaderLineReader() {
			this.reader = new BufferedReader(new InputStreamReader(System.in));
		}

		@Override
		public String readLine(String prompt) throws IOException {
			System.out.print(prompt);
			return reader.readLine();
		}
	}
	
	private final AsyncReference<TargetState, Cause> state =
			new AsyncReference<>(TargetState.NOT_STARTED);
	private final AsyncReference<TargetState, Cause> asyncState = new AsyncReference<>(state.get());

	private final AsyncLock cmdLock = new AsyncLock();
	private final AtomicReference<AsyncLock.Hold> cmdLockHold = new AtomicReference<>(null);
	private ExecutorService executor;
	//private final AsyncTimer timer = AsyncTimer.DEFAULT_TIMER;

	private PendingCommand<?> curCmd = null;
	private final HandlerMap<Event<?>, Void, Void> handlerMap = new HandlerMap<>();
	
	protected final ExecutorService eventThread = Executors.newSingleThreadExecutor();
	private InputOutputThread ioThread;
	private InputOutputThread iniThread;
	private Thread gdbWaiter;
	private final AtomicBoolean exited = new AtomicBoolean(false);
	
	protected final ListenerSet<TargetEventsListener> listenersEvent =
		new ListenerSet<>(TargetEventsListener.class);
	protected final ListenerSet<TargetOutputListener> listenersTargetOutput =
		new ListenerSet<>(TargetOutputListener.class);
	protected final ListenerSet<ConsoleOutputListener> listenersConsoleOutput =
		new ListenerSet<>(ConsoleOutputListener.class);
	
	private final AsyncReference<Boolean, Void> prompt = new AsyncReference<>(false);
	
	protected String hostname = "localhost";
	protected int port = 3000;
	
	private boolean terminated = false;
	
	public ConsoleManager(String hostname, int port) {
		this.hostname = hostname;
		this.port = port;
		
		state.filter(this::stateFilter);
		state.addChangeListener((os, ns, c) -> event(() -> asyncState.set(ns, c), "managerState"));
		
		defaultHandlers();
	}
	
	public static void main(String[] args)
			throws InterruptedException, ExecutionException {
		var mgr = new ConsoleManager("localhost", 3000);
		try {
			mgr.start();
			mgr.runRC().get();
			mgr.consoleLoop();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void addConsoleOutputListener(ConsoleOutputListener listener) {
		listenersConsoleOutput.add(listener);
	}

	public void removeConsoleOutputListener(ConsoleOutputListener listener) {
		listenersConsoleOutput.remove(listener);
	}
	
	public void addTargetOutputListener(TargetOutputListener listener) {
		listenersTargetOutput.add(listener);
	}

	public void removeTargetOutputListener(TargetOutputListener listener) {
		listenersTargetOutput.remove(listener);
	}
	
	public void addStateListener(TargetStateListener listener) {
		asyncState.addChangeListener(listener);
	}

	public void removeStateListener(TargetStateListener listener) {
		asyncState.removeChangeListener(listener);
	}

	public void addEventsListener(DosboxEventsListener listener) {
		listenersEvent.add(listener);
	}

	public void removeEventsListener(DosboxEventsListener listener) {
		listenersEvent.remove(listener);
	}
	

	public CompletableFuture<Void> console(String command) {
		return execute(new ConsoleExecCommand(this, command)).thenApply(e -> null);
	}

	public CompletableFuture<String> consoleCapture(String command) {
		return execute(new ConsoleExecCommand(this, command));
	}
	
	public void consoleLoop() throws IOException {
		//checkStarted();
		Signal sigInterrupt = new Signal("INT");
		SignalHandler oldHandler = Signal.handle(sigInterrupt, (sig) -> {
		});
		try {
			/*
			 * prompt.addChangeListener((p, v) -> { if (p) { System.out.print(PROMPT_GDB + " "); }
			 * });
			 */
			LineReader reader = new BufferedReaderLineReader();
			//LineReader reader = new GnuReadlineLineReader();
			// System.out.print(PROMPT_GDB + " ");
			while (isAlive()) {
				String cmd = reader.readLine("waiting for user input..\n");
				Msg.info(this, "received input..");
				if (cmd == null) {
					System.out.println("quit");
					return;
				}
				
				console(cmd).exceptionally((e) -> {
					Throwable realExc = AsyncUtils.unwrapThrowable(e);
					if (realExc instanceof CommandError) {
						return null; // Gdb will have already printed it
					}
					e.printStackTrace();
					//System.out.print(PROMPT_GDB + " ");
					return null;
				});
			}
		}
		finally {
			Signal.handle(sigInterrupt, oldHandler);
		}
	}
	
	public synchronized TargetState getState() {
		return state.get();
	}
	
	public synchronized void processLine(String line) {
		processEvent(new ConsoleOutputEvent(line));
	}
	
	public CompletableFuture<Void> runRC() {
		return CompletableFuture.runAsync(() -> {
			Msg.info(this, "runRC()");
		}).thenCompose(__ -> initialize());
	}
	
	public void submit(Runnable runnable) {
		//checkStartedNotExit();
		executor.submit(() -> {
			try {
				runnable.run();
			}
			catch (Throwable e) {
				e.printStackTrace();
			}
		});
	}
	
	public void start(String... args) throws IOException {
		state.set(TargetState.RUNNING, Causes.UNCLAIMED);
		executor = Executors.newSingleThreadExecutor();
		iniThread = new InputOutputThread(this, hostname, port);
		
		/*
		gdbWaiter = new Thread(this::waitExit, "DOSBox-X WaitExit");
		gdbWaiter.start();
		*/

		iniThread.start();
		try {
			CompletableFuture.anyOf(iniThread.hasWriter, state.waitValue(TargetState.EXIT))
					.get(10, TimeUnit.SECONDS);
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			throw new IOException("Could not detect interpreter");
		}
		
		if (state.get() == TargetState.EXIT) {
			//Msg.info(this, "terminated before first prompt");
			return;
		}

		ioThread = iniThread;
		ioThread.setName("Read CLI");
		// Looks terrible, but we're already in this world
		//ioThread.writer.print("start_1" + System.lineSeparator());
		//ioThread.writer.flush();
	}
	
	
	
	public boolean isAlive() {
		return state.get().isAlive();
	}

	public synchronized void terminate() {
		executor.shutdownNow();
		
		ioThread.interrupt();
		try {
			ioThread.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		DebuggerModelTerminatingException reason =
			new DebuggerModelTerminatingException("disconnecting from target");
		cmdLock.dispose(reason);
		state.dispose(reason);
		
		PendingCommand<?> cc = this.curCmd; // read volatile
		if (cc != null && !cc.isDone()) {
			cc.completeExceptionally(reason);
		}
		
		terminated = true;
	}
	
	protected void defaultHandlers() {
		handlerMap.putVoid(ConsoleOutputEvent.class, this::processStdOut);
	}
	
	/**
	 * Schedule a command for execution
	 * 
	 * @param cmd the command to execute
	 * @return the pending command, which acts as a future for later completion
	 */
	protected <T> PendingCommand<T> doExecute(Command<? extends T> cmd) {
		assert cmd != null;
		//checkStartedNotExit();
		PendingCommand<T> pcmd = new PendingCommand<>(cmd);

		Msg.info(this, "WAITING cmdLock: " + pcmd);
		cmdLock.acquire(null).thenAccept(hold -> {
			cmdLockHold.set(hold);
			Msg.info(this, "ACQUIRED cmdLock: " + pcmd);
			synchronized (this) {
				if (curCmd != null) {
					throw new AssertionError("Cannot execute more than one command at a time");
				}
				
				/*
				if (gdb != null && !cmd.validInState(state.get())) {
					throw new GdbCommandError(
						"Command " + cmd + " is not valid while " + state.get());
				}
				*/
				//cmd.preCheck(pcmd);
				if (pcmd.isDone()) {
					cmdLockHold.getAndSet(null).release();
					return;
				}
				curCmd = pcmd;
				Msg.info(this, "CURCMD = " + curCmd);
				
				PrintWriter wr = ioThread.writer;				
				String text = cmd.encode();
				if (text != null)  {
					// send it to dosbox
					wr.print(text + System.lineSeparator());
					wr.flush();
					// pending now..					
				}
			}
		}).exceptionally((exc) -> {
			pcmd.completeExceptionally(exc);
			Msg.debug(this, "ON_EXCEPTION: CURCMD = " + curCmd);
			synchronized (this) {
				curCmd = null;
			}
			Msg.debug(this, "SET CURCMD = null");
			Msg.debug(this, "RELEASING cmdLock");
			Hold hold = cmdLockHold.getAndSet(null);
			if (hold != null) {
				hold.release();
			}
			return null;
		});
		return pcmd;
	}

	public <T> CompletableFuture<T> execute(Command<? extends T> cmd) {
		// NB. curCmd::finish is passed to eventThread already 
		return doExecute(cmd);//.thenApplyAsync(t -> t, eventThread);
	}
	
	/**
	 * Execute commands upon GDB startup
	 * 
	 * @return a future which completes when the rc commands are complete
	 */
	protected CompletableFuture<Void> initialize() {
		return AsyncUtils.NIL;
	}
	
	protected synchronized void processEvent(Event<?> evt) {
		/**
		 * NOTE: I've forgotten why, but the the state update needs to happen between handle and
		 * finish.
		 */
		boolean cmdFinished = false;
		if (curCmd != null) {
			cmdFinished = curCmd.handle(evt);
			if (cmdFinished) {
				//checkImpliedFocusChange();
			}
		}

		TargetState newState = evt.newState();
		//Msg.debug(this, "received event: " + evt);
		state.set(newState, evt.getCause());

		// NOTE: Do not check if claimed here.
		// Downstream processing should check for cause
		handlerMap.handle(evt, null);

		if (cmdFinished) {
			// running finish async
			event(curCmd::finish, evt.toString());
			curCmd = null;
			cmdLockHold.getAndSet(null).release();
		}
	}
	
	protected void processStdOut(ConsoleOutputEvent evt, Void v) {
		String out = evt.getOutput();
		if (!evt.isStolen()) {
			listenersConsoleOutput.fire.output(out);
		}
	}
	
	
	
	protected CompletableFuture<Void> event(Runnable r, String text) {
		return CompletableFuture.runAsync(r, eventThread).exceptionally(ex -> {
			return ExceptionUtils.rethrow(ex);
		});
	}
	
	protected TargetState stateFilter(TargetState cur, TargetState set, Cause cause) {
		if (set == null) {
			return cur;
		}
		return set;
	}
}