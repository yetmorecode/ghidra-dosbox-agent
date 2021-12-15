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
import yetmorecode.ghidra.console.ConsoleManager;
import yetmorecode.ghidra.console.ConsoleOutputListener;
import yetmorecode.ghidra.console.TargetOutputListener;
import yetmorecode.ghidra.console.TargetState;
import yetmorecode.ghidra.console.TargetStateListener;
import yetmorecode.ghidra.console.command.Command;
import yetmorecode.ghidra.console.command.ConsoleExecCommand;
import yetmorecode.ghidra.console.command.PendingCommand;
import yetmorecode.ghidra.console.event.ConsoleOutputEvent;

import yetmorecode.ghidra.dosbox.manager.event.DosboxEvent;

public class DosboxManager {

	
	
	

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
		consoleManager = new ConsoleManager(hostname, port);
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
	
	protected <T> CompletableFuture<T> execute(Command<? extends T> cmd) {
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
	protected CompletableFuture<Void> initialize() {
		Msg.info(this, "doing rc()");
		return AsyncUtils.NIL;
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

	public void addEventsListener(DosboxEventsListener listener) {
		consoleManager.addEventsListener(listener);
	}

	public void removeEventsListener(DosboxEventsListener listener) {
		consoleManager.removeEventsListener(listener);
	}
	
	public CompletableFuture<Void> waitForPrompt() {
		return prompt.waitValue(true);
	}
	
	public CompletableFuture<Void> console(String command) {
		return execute(new ConsoleExecCommand(this.getConsoleManager(), command)).thenApply(e -> null);
	}

	public CompletableFuture<String> consoleCapture(String command) {
		return execute(new ConsoleExecCommand(this.getConsoleManager(), command));
	}
}
