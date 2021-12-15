package yetmorecode.ghidra.console;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;

import agent.gdb.manager.GdbManager.Channel;
import yetmorecode.ghidra.console.command.Command;

public interface ConsoleManager {
	/**
	 * An interface for taking lines of input
	 */
	public interface LineReader {
		String readLine(String prompt) throws IOException;
	}
	
	public void addConsoleOutputListener(ConsoleOutputListener listener);

	public void removeConsoleOutputListener(ConsoleOutputListener listener);
	
	public void addTargetOutputListener(TargetOutputListener listener);

	public void removeTargetOutputListener(TargetOutputListener listener);
	
	public void addStateListener(TargetStateListener listener);

	public void removeStateListener(TargetStateListener listener);

	public void addEventsListener(TargetEventsListener listener);

	public void removeEventsListener(TargetEventsListener listener);
	

	public CompletableFuture<Void> console(String command);

	public CompletableFuture<String> consoleCapture(String command);
	
	public void consoleLoop() throws IOException;
	
	public TargetState getState();
	
	public void processLine(String line);
	
	public CompletableFuture<Void> runRC();
	
	public void submit(Runnable runnable);
	
	public void start(String... args) throws IOException;	
	
	
	public boolean isAlive();
	
	public void terminate();
	
	public <T> CompletableFuture<T> execute(Command<? extends T> cmd);
	
	public CompletableFuture<Void> initialize();
	
	public void synthesizeConsoleOut(String line);
}
