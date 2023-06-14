package yetmorecode.ghidra.dosbox;

import java.util.concurrent.CompletableFuture;
import ghidra.dbg.util.ConfigurableFactory.FactoryDescription;
import yetmorecode.ghidra.dosbox.model.DosboxModel;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;

@FactoryDescription(
	brief = "DOSBox-X debugger via TCP",
	htmlDetails = "Connects to DOSBox-X via TCP"
)
public class DosboxDebuggerModelFactory implements DebuggerModelFactory {

	/**
	 * host name to connect to
	 */
	private String hostname = "localhost";
	
	/**
	 * TCP port to connect to
	 */
	private int port = 2999;
	
	
	@FactoryOption("hostname")
	public final Property<String> ho = Property.fromAccessors(String.class, this::getHostname, this::setHostname);
	
	@FactoryOption("TCP port")
	public final Property<Integer> po = Property.fromAccessors(Integer.class, this::getPort, this::setPort);
	
	
	@Override
	public CompletableFuture<? extends DebuggerObjectModel> build() {	
		return CompletableFuture.supplyAsync(() -> {
			var model = new DosboxModel(getHostname(), getPort());
			model.start();
			return model;
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
