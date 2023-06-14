/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package yetmorecode.ghidra.dosbox.pty;

import java.io.*;
import java.net.Socket;
import java.util.Map;
import javax.help.UnsupportedOperationException;

import agent.gdb.pty.PtyChild;
import agent.gdb.pty.PtySession;

public class TCPPtyChild extends TCPPtyEndpoint implements PtyChild {
	// address? port?
	private final Socket client;
	
	public TCPPtyChild(Socket client, OutputStream outputStream, InputStream inputStream) {
		super(outputStream, inputStream);
		this.client = client;
	}

	@Override
	public InputStream getInputStream() {
		throw new UnsupportedOperationException("The child is not local");
	}

	@Override
	public OutputStream getOutputStream() {
		throw new UnsupportedOperationException("The child is not local");
	}

	@Override
	public PtySession session(String[] args, Map<String, String> env) throws IOException {
		return new TcpPtySession(this.client);
		
	}

	@Override
	public String nullSession() throws IOException {
		return "dosbox pty";
	}
}
