package yetmorecode.ghidra.dosbox.manager;

import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncUtils;
import ghidra.util.Msg;

public class DosboxManager {

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
		Msg.debug(this, "Terminating " + this);
	}
}
