package yetmorecode.ghidra.dosbox;

import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.util.ConfigurableFactory.FactoryDescription;
import yetmorecode.ghidra.dosbox.model.DosboxModel;

/**
 * Provides DOSBox-X support as debugger agent
 * 
 * Creates a new dosbox debugger model and provides agent options
 * 
 * @author https://github.com/yetmorecode
 */
@FactoryDescription(
	brief = "DOSBox-X debugger via TCP",
	htmlDetails = "Connects to DOSBox-X via TCP"
)
public class DosboxDebuggerModelFactory implements DebuggerModelFactory {

	/**
	 * Hostname to connect to
	 */
	private String hostname = "localhost";
	
	/**
	 * TCP port to connect to
	 */
	private int port = 1234;
	
	/**
	 * Provides hostname option to UI
	 */
	@FactoryOption("hostname")
	public final Property<String> hostnameOption =
		Property.fromAccessors(String.class, this::getHostname, this::setHostname);

	/**
	 * Provides port option to UI
	 */
	@FactoryOption("TCP port")
	public final Property<Integer> portOption =
		Property.fromAccessors(Integer.class, this::getPort, this::setPort);
	
	@Override
	public CompletableFuture<? extends DebuggerObjectModel> build() {
		return CompletableFuture.supplyAsync(() -> {
			// Create a new model
			return new DosboxModel();
		});
	}
	
	/**
	 * Get remote agent host name
	 * @return
	 */
	public String getHostname() {
		return hostname;
	}

	/**
	 * Set remote agent host name
	 * @param hostname
	 */
	public void setHostname(String hostname) {
		this.hostname = hostname;
	}

	/**
	 * Get remote agent port
	 * @return
	 */
	public int getPort() {
		return port;
	}

	/**
	 * Set remote agent port
	 * @param port
	 */
	public void setPort(int port) {
		this.port = port;
	}
}
