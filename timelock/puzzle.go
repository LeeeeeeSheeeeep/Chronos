package timelock

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// Puzzle defines the public parameters needed to solve the time-lock
type Puzzle struct {
	N *big.Int // RSA Modulus
	X *big.Int // Base
	T int64    // Number of sequential squarings required
}

// GeneratePuzzle creates a new time-lock puzzle that takes T squarings to solve.
// It returns the public puzzle parameters and the expected result 'y' (for verifying or locking).
// The creator uses the trapdoor (phi) to compute 'y' instantly.
func GeneratePuzzle(t int64, bits int) (*Puzzle, *big.Int, error) {
	// 1. Generate two large primes p and q
	p, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, nil, err
	}
	q, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, nil, err
	}

	// 2. N = p * q
	n := new(big.Int).Mul(p, q)

	// 3. phi(N) = (p-1)*(q-1)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(pMinus1, qMinus1)

	// 4. Generate random base x in [2, N-1]
	x, err := rand.Int(rand.Reader, new(big.Int).Sub(n, big.NewInt(2)))
	if err != nil {
		return nil, nil, err
	}
	x.Add(x, big.NewInt(2))

	// 5. Instantly compute y = x^(2^t) mod N using trapdoor
	// We first compute e = 2^t mod phi
	two := big.NewInt(2)
	bigT := big.NewInt(t)
	
	e := new(big.Int).Exp(two, bigT, phi)
	
	// Then y = x^e mod N
	y := new(big.Int).Exp(x, e, n)

	puzzle := &Puzzle{
		N: n,
		X: x,
		T: t,
	}

	return puzzle, y, nil
}

// SolvePuzzle computes the puzzle sequentially.
// It MUST perform T sequential squarings: y = x^(2^t) mod N.
// This cannot be parallelized, thus guaranteeing a time delay.
// An optional progress channel can be passed to report the current step.
func SolvePuzzle(p *Puzzle, progress chan<- int64) (*big.Int, error) {
	if p == nil || p.N == nil || p.X == nil || p.T <= 0 {
		return nil, errors.New("invalid puzzle parameters")
	}

	y := new(big.Int).Set(p.X)
	two := big.NewInt(2)

	// Sequential squaring loop
	for i := int64(0); i < p.T; i++ {
		// y = y^2 mod N
		y.Exp(y, two, p.N)
		
		// Report progress occasionally to avoid slowing down the loop too much
		if progress != nil && i%10000 == 0 {
			// Non-blocking send
			select {
			case progress <- i:
			default:
			}
		}
	}
	
	if progress != nil {
		close(progress)
	}

	return y, nil
}
