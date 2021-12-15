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
package yetmorecode.ghidra.async;

import java.lang.ref.Cleaner;
import java.util.concurrent.*;

/**
 * A wrapper for Java's {@link CompletableFuture}
 */
public interface AsyncUtils<T> {
	Cleaner CLEANER = Cleaner.create();
	
	CompletableFuture<Void> NIL = CompletableFuture.completedFuture(null);

	@SuppressWarnings({ "unchecked", "rawtypes" })
	public static <T> CompletableFuture<T> nil() {
		return (CompletableFuture) NIL;
	}
	
	/**
	 * Unwrap {@link CompletionException}s and {@link ExecutionException}s to get the real cause
	 * 
	 * @param e the (usually wrapped) exception
	 * @return the nearest cause in the chain that is not a {@link CompletionException}
	 */
	public static Throwable unwrapThrowable(Throwable e) {
		Throwable exc = e;
		while (exc instanceof CompletionException || exc instanceof ExecutionException) {
			exc = exc.getCause();
		}
		return exc;
	}
}
