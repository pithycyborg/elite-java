# Elite Java

**Low-memory JVM experiments. Graal Native. HotSpot intrinsics.**

High-performance Java that defies the "enterprise bloat" stereotype. These experiments maximize throughput and minimize footprint via off-heap memory, SIMD, and native compilation.

## Featured Experiments

| Module | RSS (Native) | Key Technique |
| :--- | :--- | :--- |
| **No-GC Parser** | 4.2 MB | Off-heap `MemorySegment` → AST |
| **Native CLI** | 8.0 MB | Reflection-free GraalVM Native Image |
| **SIMD Math** | 6.1 MB | `VectorAPI` + intrinsic inlining |
| **Zero-Alloc Streams** | 5.8 MB | Primitive-specialized `Spliterators` |

## Technical Constraints

* **Zero Reflection:** Reflection-free architectures for maximum GraalVM compatibility.
* **Memory Bound:** Static heap targets of ≤ 32MB.
* **Modern Core:** Java 21+ Virtual Threads (Loom) and Structured Concurrency.
* **No Bloat:** Zero dependencies. No Spring, no Hibernate, no Jakarta.

## Performance Profile

| Task | Input | Java (Native) | Rust | Python |
| :--- | :--- | :--- | :--- | :--- |
| JSON Parse | 1MB | 3.2ms | 2.1ms | 187ms |
| CLI Startup | - | 12ms | 89μs | 245ms |
| SIMD Vector | 10^6 | 1.1ms | 0.9ms | 412ms |

## Philosophy

Java is often misused. We treat the JVM as a systems-level tool to achieve:
1.  **Mechanical Sympathy:** Aligning data structures with L1/L2 cache lines.
2.  **Deterministic Latency:** Eliminating GC pauses via stack-allocation and off-heap storage.
3.  **Instant Warmup:** Leveraging AOT (Ahead-of-Time) compilation.

## Usage

```bash
# Standard JVM (HotSpot)
./gradlew run

# Native Image (AOT)
./gradlew nativeCompile
./build/native/nativeCompile/experiment-name
