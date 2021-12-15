package yetmorecode.ghidra.dosbox.manager;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.StringReader;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.exception.ExceptionUtils;

import agent.gdb.manager.GdbCause;
import agent.gdb.manager.GdbConsoleOutputListener;
import agent.gdb.manager.GdbState;
import agent.gdb.manager.GdbManager.Channel;
import agent.gdb.manager.evt.GdbConsoleOutputEvent;
import agent.gdb.manager.impl.GdbPendingCommand;
import agent.gdb.manager.impl.GdbManagerImpl.Interpreter;
import ghidra.async.AsyncLock;
import ghidra.async.AsyncReference;
import ghidra.async.AsyncUtils;
import ghidra.async.AsyncLock.Hold;
import ghidra.dbg.util.HandlerMap;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListenerSet;
import sun.misc.Signal;
import sun.misc.SignalHandler;
import yetmorecode.ghidra.dosbox.manager.Cause.Causes;
import yetmorecode.ghidra.dosbox.manager.command.Command;
import yetmorecode.ghidra.dosbox.manager.command.ConsoleExecCommand;
import yetmorecode.ghidra.dosbox.manager.event.ConsoleOutputEvent;
import yetmorecode.ghidra.dosbox.manager.event.Event;

public class DosboxManager {

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
	
	
	
	private final AsyncReference<DosboxState, Cause> state =
			new AsyncReference<>(DosboxState.NOT_STARTED);
	private final AsyncReference<DosboxState, Cause> asyncState = new AsyncReference<>(state.get());

	private final AsyncLock cmdLock = new AsyncLock();
	private final AtomicReference<AsyncLock.Hold> cmdLockHold = new AtomicReference<>(null);
	private ExecutorService executor;
	//private final AsyncTimer timer = AsyncTimer.DEFAULT_TIMER;

	private PendingCommand<?> curCmd = null;
	private final HandlerMap<Event<?>, Void, Void> handlerMap = new HandlerMap<>();
	
	protected final ExecutorService eventThread = Executors.newSingleThreadExecutor();
	private DosboxInputOutputThread ioThread;
	private DosboxInputOutputThread iniThread;
	private Thread gdbWaiter;
	private final AtomicBoolean exited = new AtomicBoolean(false);
	
	protected final ListenerSet<ConsoleOutputListener> listenersConsoleOutput =
			new ListenerSet<>(ConsoleOutputListener.class);
	
	public static void main(String[] args)
			throws InterruptedException, ExecutionException {
		DosboxManager mgr = new DosboxManager();
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
	
	public DosboxManager() {
		state.filter(this::stateFilter);
		state.addChangeListener((os, ns, c) -> event(() -> asyncState.set(ns, c), "managerState"));
		
		defaultHandlers();
	}
	
	private void defaultHandlers() {
		handlerMap.putVoid(ConsoleOutputEvent.class, this::processStdOut);
	}
	
	
	protected void processStdOut(ConsoleOutputEvent evt, Void v) {
		String out = evt.getOutput();
		if (!evt.isStolen()) {
			listenersConsoleOutput.fire.output(out);
		}
	}
	
	public void addConsoleOutputListener(ConsoleOutputListener listener) {
		listenersConsoleOutput.add(listener);
	}

	public void removeConsoleOutputListener(ConsoleOutputListener listener) {
		listenersConsoleOutput.remove(listener);
	}

	private DosboxState stateFilter(DosboxState cur, DosboxState set, Cause cause) {
		if (set == null) {
			return cur;
		}
		return set;
	}
	
	public void start(String... args) throws IOException {
		state.set(DosboxState.RUNNING, Causes.UNCLAIMED);
		Msg.info(this, "state = starting " + state.get());
		
		executor = Executors.newSingleThreadExecutor();

		
		
		iniThread = new DosboxInputOutputThread(this);
		
		/*
		gdbWaiter = new Thread(this::waitExit, "DOSBox-X WaitExit");
		gdbWaiter.start();
		*/

		iniThread.start();
		try {
			CompletableFuture.anyOf(iniThread.hasWriter, state.waitValue(DosboxState.EXIT))
					.get(10, TimeUnit.SECONDS);
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			throw new IOException("Could not detect GDB's interpreter mode");
		}
		
		if (state.get() == DosboxState.EXIT) {
			Msg.info(this, "terminated before first prompt");
			return;
		}

		ioThread = iniThread;
		ioThread.setName("Read CLI");
		// Looks terrible, but we're already in this world
		//ioThread.writer.print("start_1" + System.lineSeparator());
		//ioThread.writer.flush();
	}
	
	private void waitExit() {
		//int exitcode = gdb.waitExited();
		state.set(DosboxState.EXIT, Causes.UNCLAIMED);
		exited.set(true);
		if (!executor.isShutdown()) {
			Msg.info(this, "executor.isShutdown() " + executor.isShutdown());
			terminate();
		}
	}
	
	public boolean isAlive() {
		return state.get().isAlive();
	}
	
	public CompletableFuture<Void> console(String command) {
		return execute(new ConsoleExecCommand(this, command)).thenApply(e -> null);
	}
	
	protected <T> CompletableFuture<T> execute(Command<? extends T> cmd) {
		// NB. curCmd::finish is passed to eventThread already 
		return doExecute(cmd);//.thenApplyAsync(t -> t, eventThread);
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

		Msg.debug(this, "WAITING cmdLock: " + pcmd);
		cmdLock.acquire(null).thenAccept(hold -> {
			cmdLockHold.set(hold);
			Msg.debug(this, "ACQUIRED cmdLock: " + pcmd);
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
	
	public CompletableFuture<Void> runRC() {
		return CompletableFuture.runAsync(() -> {
			Msg.debug(this, "runRC()");
		}).thenCompose(__ -> initialize());
	}

	/**
	 * Execute commands upon GDB startup
	 * 
	 * @return a future which completes when the rc commands are complete
	 */
	protected CompletableFuture<Void> initialize() {
		Msg.debug(this, "doing rc()");
		return AsyncUtils.NIL;
	}
	
	public synchronized void terminate() {
		Msg.debug(this, "manager terminate");
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

		DosboxState newState = evt.newState();
		//Msg.debug(this, "received event: " + evt);
		state.set(newState, evt.getCause());

		// NOTE: Do not check if claimed here.
		// Downstream processing should check for cause
		handlerMap.handle(evt, null);

		if (cmdFinished) {
			event(curCmd::finish, evt.toString());
			curCmd = null;
			cmdLockHold.getAndSet(null).release();
		}
	}
	
	CompletableFuture<Void> event(Runnable r, String text) {
		//Msg.debug(this, "queueing event: " + text);
		return CompletableFuture.runAsync(r, eventThread).exceptionally(ex -> {
			Msg.error(this, "Error in event callback:", ex);
			return ExceptionUtils.rethrow(ex);
		});
	}
	
	public synchronized void processLine(String line) {
		processEvent(new ConsoleOutputEvent(line));
	}
}
