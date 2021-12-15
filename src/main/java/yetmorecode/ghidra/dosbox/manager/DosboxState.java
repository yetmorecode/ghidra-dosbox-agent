package yetmorecode.ghidra.dosbox.manager;

public enum DosboxState {
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
	 * alive, but has not issued its first prompt, yet
	 */
	STARTING {
		@Override
		public boolean isAlive() {
			return true;
		}
	},
	/**
	 * dosbox is stopped
	 */
	STOPPED {
		@Override
		public boolean isAlive() {
			return true;
		}
	},
	/**
	 * dosbox is running
	 */
	RUNNING {
		@Override
		public boolean isAlive() {
			return true;
		}
	},
	/**
	 * dosbox has exited
	 */
	EXIT {
		@Override
		public boolean isAlive() {
			return false;
		}
	};

	public abstract boolean isAlive();
}