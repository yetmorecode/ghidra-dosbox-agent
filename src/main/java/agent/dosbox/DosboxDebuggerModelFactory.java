package agent.dosbox;

import java.util.concurrent.CompletableFuture;

import agent.dosbox.model.impl.DosboxModelImpl;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.util.ConfigurableFactory.FactoryDescription;

@FactoryDescription( //
	brief = "Dosbox debugger via TCP", //
	htmlDetails = "Connects to a Dosbox debugger via TCP" //
)
public class DosboxDebuggerModelFactory implements DebuggerModelFactory {

	private String hostname = "localhost";
	@FactoryOption("hostname")
	public final Property<String> hostnameOption =
		Property.fromAccessors(String.class, this::getHostname, this::setHostname);

	private int port = 1234;
	@FactoryOption("TCP port")
	public final Property<Integer> portOption =
		Property.fromAccessors(Integer.class, this::getPort, this::setPort);
	
	@Override
	public CompletableFuture<? extends DebuggerObjectModel> build() {
		return CompletableFuture.supplyAsync(() -> {			
			return new DosboxModelImpl();
		});
	}
	
	public String getHostname() {
		return hostname;
	}

	public void setHostname(String hostname) {
		this.hostname = hostname;
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}

}
