package yetmorecode.ghidra.dosbox.manager;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.util.concurrent.CompletableFuture;

import ghidra.util.Msg;

class DosboxInputOutputThread extends Thread {
	public BufferedReader reader;
	
	public PrintWriter writer;
	CompletableFuture<Void> hasWriter;
	final DosboxManager manager;
	
	public PipedOutputStream sendToDosbox;

	DosboxInputOutputThread(DosboxManager manager) {
		this.manager = manager;
		
		sendToDosbox = new PipedOutputStream();
		
		
		try {
			PipedInputStream in = new PipedInputStream(sendToDosbox);
			this.reader = new BufferedReader(new InputStreamReader(in));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//InputStream = new StringReader("s:running\nv:1.0\ntitle:foo\n")
		
		
		PrintWriter os = new PrintWriter(sendToDosbox);
		os.println("s:running\n");
		os.println("v:1.0");
		os.println("ti:foobar");
		os.flush();
		
		hasWriter = new CompletableFuture<>();
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
				
				if (writer == null) {
					// output stream to dosbox
					writer = new PrintWriter(sendToDosbox);
					//writer = new PrintWriter(pty.getParent().getOutputStream());
					hasWriter.complete(null);
				}
				manager.submit(() -> {
					// simulate 1.5 second wait
					try {
						sleep(1500);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					//Msg.info(this, "io: responding " + l);
					manager.processLine(l);
				});
			}
			Msg.info(this, "io: done reading: alive = " + isAlive());
		} catch (Throwable e) {
			manager.terminate();
			Msg.debug(this, "reader exiting");
			e.printStackTrace();
		}
	}
}
