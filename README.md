![Build Status](https://img.shields.io/badge/build-passing-brightgreen)

# Chronos ⏳

**Chronos** is a time-locked encryption vault built in Go.

Unlike traditional encryption where knowing the password allows instant decryption, a Chronos vault **mathematically guarantees** that decryption will take a specific amount of CPU time. Even if the recipient has the vault file and the public parameters, they absolutely *must* spend time computing the solution.

## How it works

This implements a time-lock puzzle based on the **Rivest-Shamir-Wagner (1996)** construction.
1. The locker generates an RSA modulus $N = p \cdot q$.
2. They pick a random base $x$.
3. The puzzle requires computing $y = x^{2^T} \pmod N$, which takes exactly $T$ sequential squarings. Because you cannot parallelize modular exponentiation without knowing $\phi(N)$, you cannot speed this up simply by adding more cores.
4. The locker (knowing $\phi(N) = (p-1)(q-1)$) can compute $e = 2^T \pmod{\phi(N)}$ and instantly find $y = x^e \pmod N$.
5. The payload is encrypted using AES-256-GCM, where the key is derived from the SHA-256 hash of $y$.
6. The prime factors $p$ and $q$ are destroyed, leaving only $N$, $x$, and $T$.
7. To unlock, the recipient *must* run the sequential squarings to recover $y$.

## Usage

```bash
# Build the tool
go build

# Create a secret file
echo "Top secret message" > secret.txt

# Lock the file. 
# T is the number of squarings. 5,000,000 takes a few seconds on modern CPUs.
./Chronos lock -in secret.txt -out secret.vault -t 5000000

# Unlock the file (this will enforce the CPU delay)
./Chronos unlock -in secret.vault -out decrypted.txt
```
