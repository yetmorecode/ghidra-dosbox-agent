package yetmorecode.ghidra.dosbox.manager;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import ghidra.async.AsyncReference;
import ghidra.util.Msg;
import yetmorecode.ghidra.console.ConsoleManager;
import yetmorecode.ghidra.console.ConsoleOutputListener;
import yetmorecode.ghidra.console.TCPConsoleManager;
import yetmorecode.ghidra.console.TargetEventsListener;
import yetmorecode.ghidra.console.TargetOutputListener;
import yetmorecode.ghidra.console.TargetState;
import yetmorecode.ghidra.console.TargetStateListener;
import yetmorecode.ghidra.console.command.Command;
import yetmorecode.ghidra.console.command.ConsoleExecCommand;

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
}
