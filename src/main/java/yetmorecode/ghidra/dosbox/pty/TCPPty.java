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

import agent.gdb.pty.*;

public class TCPPty implements Pty {
	private final OutputStream out;
	private final InputStream in;
	private final Socket client;
	
	public TCPPty(Socket client) throws IOException {
		out = client.getOutputStream();
		in = client.getInputStream();
		this.client = client;
	}

	@Override
	public PtyParent getParent() {
		return new TCPPtyParent(out, in);
	}

	@Override
	public PtyChild getChild() {
		return new TCPPtyChild(client, out, in);
	}

	@Override
	public void close() throws IOException {
		in.close();
		out.close();
	}
}
