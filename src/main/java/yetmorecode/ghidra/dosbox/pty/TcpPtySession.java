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

import java.io.IOException;
import java.net.Socket;

import agent.gdb.pty.PtySession;

public class TcpPtySession implements PtySession {
	private final Socket client;

	public TcpPtySession(Socket client) {
		this.client = client;
	}

	@Override
	public int waitExited() throws InterruptedException {
		// Doesn't look like there's a clever way to wait. So do the spin sleep :(
		while (!client.isConnected()) {
			Thread.sleep(1000);
		}
		return 0;
	}

	@Override
	public void destroyForcibly() {
		try {
			client.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
