package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/LeeeeeeSheeeeep/Chronos/crypto"
	"github.com/LeeeeeeSheeeeep/Chronos/timelock"
)

// EncryptedVault stores the puzzle and the AES-GCM ciphertext
type EncryptedVault struct {
	N          string `json:"n"`
	X          string `json:"x"`
	T          int64  `json:"t"`
	Ciphertext []byte `json:"ciphertext"`
}

func main() {
	fmt.Println(`
   _____ _                             
  / ____| |                            
 | |    | |__  _ __ ___  _ __   ___  ___ 
 | |    | '_ \| '__/ _ \| '_ \ / _ \/ __|
 | |____| | | | | | (_) | | | | (_) \__ \
  \_____|_| |_|_|  \___/|_| |_|\___/|___/
  
  [ Time-Locked Encryption Vault ]
	`)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	lockCmd := flag.NewFlagSet("lock", flag.ExitOnError)
	lockIn := lockCmd.String("in", "", "Input file to encrypt")
	lockOut := lockCmd.String("out", "locked.vault", "Output locked vault file")
	lockT := lockCmd.Int64("t", 1000000, "Time complexity (number of squarings). ~10M takes a few seconds.")

	unlockCmd := flag.NewFlagSet("unlock", flag.ExitOnError)
	unlockIn := unlockCmd.String("in", "locked.vault", "Input locked vault file")
	unlockOut := unlockCmd.String("out", "decrypted.txt", "Output decrypted file")

	switch command {
	case "lock":
		lockCmd.Parse(os.Args[2:])
		if *lockIn == "" {
			fmt.Println("Error: Input file (-in) is required for lock.")
			os.Exit(1)
		}
		handleLock(*lockIn, *lockOut, *lockT)

	case "unlock":
		unlockCmd.Parse(os.Args[2:])
		if *unlockIn == "" {
			fmt.Println("Error: Input file (-in) is required for unlock.")
			os.Exit(1)
		}
		handleUnlock(*unlockIn, *unlockOut)

	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  chronos lock -in <file> -t <squarings> [-out <vault>]")
	fmt.Println("  chronos unlock -in <vault> [-out <file>]")
}

func handleLock(inFile string, outFile string, t int64) {
	fmt.Printf("[*] Reading file: %s\n", inFile)
	plaintext, err := os.ReadFile(inFile)
	if err != nil {
		fmt.Printf("[!] Failed to read input file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Generating Time-Lock Puzzle (T=%d)...\n", t)
	start := time.Now()
	// Using 2048-bit RSA modulus
	puzzle, y, err := timelock.GeneratePuzzle(t, 2048)
	if err != nil {
		fmt.Printf("[!] Failed to generate puzzle: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Puzzle generated instantly in %s using trapdoor.\n", time.Since(start))

	fmt.Printf("[*] Deriving AES-256 key and encrypting payload...\n")
	key := crypto.DeriveKey(y)
	ciphertext, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		fmt.Printf("[!] Encryption failed: %v\n", err)
		os.Exit(1)
	}

	vault := EncryptedVault{
		N:          puzzle.N.Text(16),
		X:          puzzle.X.Text(16),
		T:          puzzle.T,
		Ciphertext: ciphertext,
	}

	vaultData, err := json.MarshalIndent(vault, "", "  ")
	if err != nil {
		fmt.Printf("[!] Failed to marshal vault: %v\n", err)
		os.Exit(1)
	}

	err = os.WriteFile(outFile, vaultData, 0644)
	if err != nil {
		fmt.Printf("[!] Failed to save vault file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Success! Locked data saved to %s\n", outFile)
}

func handleUnlock(inFile string, outFile string) {
	fmt.Printf("[*] Reading vault file: %s\n", inFile)
	vaultData, err := os.ReadFile(inFile)
	if err != nil {
		fmt.Printf("[!] Failed to read vault file: %v\n", err)
		os.Exit(1)
	}

	var vault EncryptedVault
	if err := json.Unmarshal(vaultData, &vault); err != nil {
		fmt.Printf("[!] Failed to parse vault file: %v\n", err)
		os.Exit(1)
	}

	n, _ := new(big.Int).SetString(vault.N, 16)
	x, _ := new(big.Int).SetString(vault.X, 16)

	puzzle := &timelock.Puzzle{
		N: n,
		X: x,
		T: vault.T,
	}

	fmt.Printf("[*] Starting sequential squaring to solve puzzle (T=%d)...\n", vault.T)
	fmt.Println("[*] This cannot be parallelized. Please wait.")
	
	progress := make(chan int64, 1)
	go func() {
		for i := range progress {
			if i > 0 && i%500000 == 0 {
				pct := float64(i) / float64(vault.T) * 100
				fmt.Printf("    -> Computing: %.1f%% (%d / %d)\n", pct, i, vault.T)
			}
		}
	}()

	start := time.Now()
	y, err := timelock.SolvePuzzle(puzzle, progress)
	if err != nil {
		fmt.Printf("[!] Failed to solve puzzle: %v\n", err)
		os.Exit(1)
	}
	duration := time.Since(start)
	fmt.Printf("[+] Puzzle solved in %s!\n", duration)

	fmt.Printf("[*] Deriving AES-256 key and decrypting payload...\n")
	key := crypto.DeriveKey(y)
	plaintext, err := crypto.Decrypt(key, vault.Ciphertext)
	if err != nil {
		fmt.Printf("[!] Decryption failed (wrong key or corrupted data): %v\n", err)
		os.Exit(1)
	}

	err = os.WriteFile(outFile, plaintext, 0644)
	if err != nil {
		fmt.Printf("[!] Failed to write decrypted file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Success! Decrypted data saved to %s\n", outFile)
}
