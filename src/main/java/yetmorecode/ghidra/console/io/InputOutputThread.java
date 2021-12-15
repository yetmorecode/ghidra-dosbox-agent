package yetmorecode.ghidra.console.io;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.concurrent.CompletableFuture;

import ghidra.util.Msg;
import yetmorecode.ghidra.console.ConsoleManager;

public class InputOutputThread extends Thread {
	public BufferedReader reader;
	
	public PrintWriter writer;
	public CompletableFuture<Void> hasWriter;
	final ConsoleManager manager;

	Socket clientSocket;
	
	public InputOutputThread(ConsoleManager manager, String hostname, int port) throws UnknownHostException, IOException {
		this.manager = manager;
		Msg.info(this, "connecting to socket: " + hostname + ":" + port);
		clientSocket = new Socket(hostname, port);
		try {
			reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		hasWriter = new CompletableFuture<>();
		if (writer == null) {
			// output stream to dosbox
			writer = new PrintWriter(clientSocket.getOutputStream());
			hasWriter.complete(null);
		}
	}

	@Override
	public void run() {
		try {
			String line;
			// input from dosbox
			while (isAlive() && null != (line = reader.readLine())) {
				String l = line;
				if (l.length() == 0) {
					continue;
				}				
				manager.submit(() -> {
					manager.processLine(l);
				});
			}
			Msg.info(this, "io: done reading: alive = " + isAlive());
		} catch (Throwable e) {
			Msg.debug(this, "Connection error: " + e.getMessage());
			manager.terminate();
		}
	}
	
	public void close() throws IOException {
		clientSocket.close();
	}
}
