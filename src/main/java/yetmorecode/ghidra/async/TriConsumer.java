package yetmorecode.ghidra.async;

import java.util.function.BiConsumer;

/**
 * Patterned after {@link BiConsumer}.
 * 
 * @param <T>
 * @param <U>
 * @param <V>
 */
@FunctionalInterface
public interface TriConsumer<T, U, V> {
	/**
	 * Performs this operation on the given arguments.
	 *
	 * @param t the first input argument
	 * @param u the second input argument
	 * @param v the third input argument
	 */
	void accept(T t, U u, V v);
}