package yetmorecode.ghidra.console;

public enum TargetState {
	/**
	 * not alive, because it has not be started
	 */
	NOT_STARTED {
		@Override
		public boolean isAlive() {
			return false;
		}
	},
	/**
	 * alive, but has not ready for commands yet
	 */
	STARTING {
		@Override
		public boolean isAlive() {
			return true;
		}
	},
	/**
	 * target is stopped
	 */
	STOPPED {
		@Override
		public boolean isAlive() {
			return true;
		}
	},
	/**
	 * target is running
	 */
	RUNNING {
		@Override
		public boolean isAlive() {
			return true;
		}
	},
	/**
	 * target has exited
	 */
	EXIT {
		@Override
		public boolean isAlive() {
			return false;
		}
	};

	public abstract boolean isAlive();
}