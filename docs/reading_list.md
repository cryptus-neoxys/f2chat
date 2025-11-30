# f2chat Prerequisite Reading List

This document outlines the essential knowledge required to understand and contribute to `f2chat`. It is structured for a Computer Science undergraduate with a strong interest in cryptography and algebraic topology.

## 1. Cryptography Foundations

Before diving into FHE, you need a solid grasp of modern cryptography and ring theory.

- **Modular Arithmetic & Ring Theory**:

  - **Concept**: Understanding $\mathbb{Z}_q$ and polynomial rings $\mathbb{Z}_q[x]/(x^n+1)$.
  - **Resource**: **A Book of Abstract Algebra (Charles C. Pinter)**
    - **Chapter 10**: Cyclic Groups (Understanding $\mathbb{Z}_n$).
    - **Chapter 17-19**: Rings, Ideals, and Quotient Rings (Crucial for modular arithmetic).
    - **Chapter 24**: Rings of Polynomials (The structure of our ciphertexts).
    - **Chapter 25**: Factoring Polynomials (Irreducibility and $x^n+1$).
  - **Why**: FHE ciphertexts are polynomials in a specific ring structure.

- **Lattice-Based Cryptography**:

  - **Concept**: Learning with Errors (LWE) and Ring-LWE problems.
  - **Resource**: [A Decade of Lattice Cryptography (Peikert)](https://eprint.iacr.org/2015/939.pdf) - _Read sections 1 & 2 for high-level intuition._
  - **Why**: The security of BGV (the scheme we use) relies on the hardness of these problems.

- **Fully Homomorphic Encryption (FHE)**:
  - **Concept**: Computing on encrypted data without decryption.
  - **Resource**: [FHE for the rest of us (Microsoft Research)](https://www.microsoft.com/en-us/research/blog/fully-homomorphic-encryption-for-the-rest-of-us/)
  - **Deep Dive**: [The BGV Scheme (Brakerski-Gentry-Vaikuntanathan)](https://eprint.iacr.org/2011/277.pdf) - _Focus on the "Leveled FHE" concept._

## 2. The OpenFHE Library

We use OpenFHE as our cryptographic backend.

- **Getting Started**:

  - **Resource**: [OpenFHE Getting Started Guide](https://openfhe-development.readthedocs.io/en/latest/intro/installation.html)
  - **Key Sections**: Installation, "Your First OpenFHE Program".

- **BGV in OpenFHE**:
  - **Resource**: [OpenFHE BGV Example](https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/simple-integers-bgvrns.cpp)
  - **Why**: This example mirrors how we initialize our `FHEContext` and perform basic operations.

## 3. Mathematical Framework (Sheaf & Wreath)

This is the unique theoretical core of `f2chat`.

- **Sheaf Theory**:

  - **Concept**: Local data consistency (patches) leading to global solutions.
  - **Resource**: [Sheaf Theory for Undergraduates (Gallier)](https://www.cis.upenn.edu/~jean/sheaves-cohomology.pdf) - _Read the introduction and first chapter._
  - **Intuition**: Think of a "sheaf" as a way to glue local routing rules together to form a valid global route.

- **Wreath Products**:
  - **Concept**: A group construction that captures "position-dependent" symmetry (like a rubik's cube or a network with local structure).
  - **Resource**: [Wreath Product (Wikipedia)](https://en.wikipedia.org/wiki/Wreath_product) - _Focus on the "Group Action" definition._
  - **Why**: Our routing attention mechanism is a "Wreath-Sheaf" attention, meaning it respects these specific symmetries.

## 4. Engineering & Tooling

Practical skills needed to build and test the system.

- **Bazel Build System**:

  - **Resource**: [Bazel Tutorial: C++](https://bazel.build/tutorials/cpp)
  - **Why**: We use Bazel for hermetic builds and dependency management.

- **Modern C++ (C++17/20)**:

  - **Resource**: [A Tour of C++ (Stroustrup)](https://www.stroustrup.com/tour.html)
  - **Key Concepts**: `std::shared_ptr`, `std::vector`, Templates, `absl::StatusOr` (from Abseil).

- **Google Test (GTest)**:
  - **Resource**: [GoogleTest Primer](https://google.github.io/googletest/primer.html)
  - **Why**: All our verification is done via unit and integration tests.
