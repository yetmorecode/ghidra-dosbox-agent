package yetmorecode.ghidra.dosbox;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import agent.gdb.manager.GdbCause;
import agent.gdb.manager.GdbState;
import agent.gdb.manager.impl.GdbManagerImpl;
import agent.gdb.manager.impl.cmd.GdbCommandError;
import ghidra.async.AsyncReference;
import ghidra.async.AsyncUtils;
import ghidra.util.Msg;
import sun.misc.Signal;
import sun.misc.SignalHandler;
import yetmorecode.ghidra.dosbox.pty.TCPPtyFactory;

public class DosboxManager extends GdbManagerImpl {

	private static final String PROMPT_GDB = "(dosbox)";
	private final String hostname;
	private final int port;
	
	protected AsyncReference<GdbState, GdbCause> state =
			new AsyncReference<>(GdbState.NOT_STARTED);
	
	public static void main(String[] args)
			throws InterruptedException, ExecutionException {
		DosboxManager m = new DosboxManager();
		Msg.info(m, "Starting stand-alone DosboxManager console");
		try {
			m.start();
			m.runRC().get();
			m.consoleLoop();
		} catch (IOException e) {
			System.out.println("Error: " + e.getMessage());
		}
	}

	public DosboxManager() {
		this("localhost", 2999);
	}
	
	public DosboxManager(String hostname) {
		this(hostname, 2999);
	}
	
	public DosboxManager(String hostname, int port) {
		super(new TCPPtyFactory(hostname, port));
		this.hostname = hostname;
		this.port = port;
	}
	
	@Override
	public void consoleLoop() throws IOException {
		if (getState() == GdbState.NOT_STARTED) {
			throw new IllegalStateException(
				"DOSBox-X has not been started or has not finished starting");
		}
		Signal sigInterrupt = new Signal("INT");
		SignalHandler oldHandler = Signal.handle(sigInterrupt, (sig) -> {
			try {
				sendInterruptNow();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		});
		try {
			BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
			while (isAlive()) {
				System.out.print(PROMPT_GDB + " ");
				String cmd = reader.readLine();
				if (cmd == null || cmd.startsWith("exit") || cmd.startsWith("quit")) {
					System.out.println("Exiting..");
					return;
				}
				console(cmd).exceptionally((e) -> {
					Throwable realExc = AsyncUtils.unwrapThrowable(e);
					if (realExc instanceof GdbCommandError) {
						return null; // Gdb will have already printed it
					}
					e.printStackTrace();
					return null;
				});
			}
		}
		finally {
			Signal.handle(sigInterrupt, oldHandler);
		}
	}
	
	@Override
	public void start() throws IOException {
		super.start(null);
	}
	
	@Override
	protected CompletableFuture<Void> rc() {
		return AsyncUtils.NIL;
	}
	
	public String toString() {
		return getClass().getSimpleName() + "(" + hostname + ":" + port + ")";
	}
}
