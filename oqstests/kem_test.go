// Package oqstests provides unit testing for the oqs Go package.
package oqstests

import (
	"bytes"
	"log"
	"runtime"
	"sync"
	"testing"

	"github.com/open-quantum-safe/liboqs-go/oqs"
	"github.com/open-quantum-safe/liboqs-go/oqs/rand"
)

// disabledKEMPatterns lists KEMs for which unit testing is disabled
var disabledKEMPatterns []string

// noThreadKEMPatterns lists KEMs that have issues running in a separate thread
var noThreadKEMPatterns = []string{"LEDAcryptKEM-LT52", "HQC-256"}

var allSchemes = []string{"BIKE-L1", "BIKE-L3", "BIKE-L5", "Classic-McEliece-348864", "Classic-McEliece-348864f", "Classic-McEliece-460896", "Classic-McEliece-460896f", "Classic-McEliece-6688128", "Classic-McEliece-6688128f", "Classic-McEliece-6960119", "Classic-McEliece-6960119f", "Classic-McEliece-8192128", "Classic-McEliece-8192128f", "HQC-128", "HQC-192", "HQC-256", "Kyber512", "Kyber768", "Kyber1024", "sntrup761", "FrodoKEM-640-AES", "FrodoKEM-640-SHAKE", "FrodoKEM-976-AES", "FrodoKEM-976-SHAKE", "FrodoKEM-1344-AES", "FrodoKEM-1344-SHAKE"}

// wgKEMCorrectness groups goroutines and blocks the caller until all goroutines finish.
var wgKEMCorrectness sync.WaitGroup

// wgKEMWrongCiphertext groups goroutines and blocks the caller until all goroutines finish.
var wgKEMWrongCiphertext sync.WaitGroup

// testKEMCorrectness tests the correctness of a specific KEM.
func testKEMCorrectness(kemName string, threading bool, t *testing.T) {
	log.Println("Correctness - ", kemName) // thread-safe
	if threading == true {
		defer wgKEMCorrectness.Done()
	}
	var client, server oqs.KeyEncapsulation
	defer client.Clean()
	defer server.Clean()
	// ignore potential errors everywhere
	_ = client.Init(kemName, nil)
	_ = server.Init(kemName, nil)
	clientPublicKey, _ := client.GenerateKeyPair()
	ciphertext, sharedSecretServer, _ := server.EncapSecret(clientPublicKey)
	sharedSecretClient, _ := client.DecapSecret(ciphertext)
	if !bytes.Equal(sharedSecretClient, sharedSecretServer) {
		// t.Errorf is thread-safe
		t.Errorf(kemName + ": shared secrets do not coincide")
	}
}

// testKEMWrongCiphertext tests the wrong ciphertext regime of a specific KEM.
func testKEMWrongCiphertext(kemName string, threading bool, t *testing.T) {
	log.Println("Wrong ciphertext - ", kemName) // thread-safe
	if threading == true {
		defer wgKEMWrongCiphertext.Done()
	}
	var client, server oqs.KeyEncapsulation
	defer client.Clean()
	defer server.Clean()
	// ignore potential errors everywhere
	_ = client.Init(kemName, nil)
	_ = server.Init(kemName, nil)
	clientPublicKey, _ := client.GenerateKeyPair()
	ciphertext, sharedSecretServer, _ := server.EncapSecret(clientPublicKey)
	wrongCiphertext := rand.RandomBytes(len(ciphertext))
	sharedSecretClient, _ := client.DecapSecret(wrongCiphertext)
	if bytes.Equal(sharedSecretClient, sharedSecretServer) {
		// t.Errorf is thread-safe
		t.Errorf(kemName + ": shared secrets should not coincide")
	}
}

// TestKeyEncapsulationCorrectness tests the correctness of all enabled KEMs.
func TestKeyEncapsulationCorrectness(t *testing.T) {
	// disable some KEMs in macOS/OSX
	if runtime.GOOS == "darwin" {
		disabledKEMPatterns = []string{"Classic-McEliece", "HQC-256"}
	}
	// disable some KEMs in OpenIndiana
	if runtime.GOOS == "illumos" {
		disabledKEMPatterns = []string{"Classic-McEliece"}
	}
	// disable some KEMs in Windows
	if runtime.GOOS == "windows" {
		disabledKEMPatterns = []string{"Classic-McEliece"}
	}
	// first test KEMs that belong to noThreadKEMPatterns[] in the main
	// goroutine, due to issues with stack size being too small in macOS or
	// Windows
	cnt := 0
	for _, kemName := range oqs.EnabledKEMs() {
		if stringMatchSlice(kemName, disabledKEMPatterns) {
			cnt++
			continue
		}
		// issues with stack size being too small
		if stringMatchSlice(kemName, noThreadKEMPatterns) {
			cnt++
			testKEMCorrectness(kemName, false, t)
		}
	}
	// test the remaining KEMs in separate goroutines
	wgKEMCorrectness.Add(len(oqs.EnabledKEMs()) - cnt)
	for _, kemName := range oqs.EnabledKEMs() {
		if stringMatchSlice(kemName, disabledKEMPatterns) {
			continue
		}
		if !stringMatchSlice(kemName, noThreadKEMPatterns) {
			go testKEMCorrectness(kemName, true, t)
		}
	}
	wgKEMCorrectness.Wait()
}

// TestKeyEncapsulationWrongCiphertext tests the wrong ciphertext regime of all enabled KEMs.
func TestKeyEncapsulationWrongCiphertext(t *testing.T) {
	// disable some KEMs in macOS/OSX
	if runtime.GOOS == "darwin" {
		disabledKEMPatterns = []string{"Classic-McEliece", "HQC-256"}
	}
	// disable some KEMs in OpenIndiana
	if runtime.GOOS == "illumos" {
		disabledKEMPatterns = []string{"Classic-McEliece"}
	}
	// disable some KEMs in Windows
	if runtime.GOOS == "windows" {
		disabledKEMPatterns = []string{"Classic-McEliece"}
	}
	// first test KEMs that belong to noThreadKEMPatterns[] in the main
	// goroutine, due to issues with stack size being too small in macOS or
	// Windows
	cnt := 0
	for _, kemName := range oqs.EnabledKEMs() {
		if stringMatchSlice(kemName, disabledKEMPatterns) {
			cnt++
			continue
		}
		// issues with stack size being too small
		if stringMatchSlice(kemName, noThreadKEMPatterns) {
			cnt++
			testKEMWrongCiphertext(kemName, false, t)
		}
	}
	// test the remaining KEMs in separate goroutines
	wgKEMWrongCiphertext.Add(len(oqs.EnabledKEMs()) - cnt)
	for _, kemName := range oqs.EnabledKEMs() {
		if stringMatchSlice(kemName, disabledKEMPatterns) {
			continue
		}
		if !stringMatchSlice(kemName, noThreadKEMPatterns) {
			go testKEMWrongCiphertext(kemName, true, t)
		}
	}
	wgKEMWrongCiphertext.Wait()
}

// TestUnsupportedKeyEncapsulation tests that an unsupported KEM emits an error.
func TestUnsupportedKeyEncapsulation(t *testing.T) {
	client := oqs.KeyEncapsulation{}
	defer client.Clean()
	if err := client.Init("unsupported_kem", nil); err == nil {
		t.Errorf("Unsupported KEM should have emitted an error")
	}
}

func BenchmarkGenerateKeyPair(b *testing.B) {
	for _, scheme := range allSchemes {
		kem := oqs.KeyEncapsulation{}
		defer kem.Clean()
		if err := kem.Init(scheme, nil); err != nil {
			b.Fatal(err)
		}
		b.Run(scheme, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				kem.GenerateKeyPair()
			}
		})
	}
}

func BenchmarkEncapsulate(b *testing.B) {
	for _, scheme := range allSchemes {
		kem := oqs.KeyEncapsulation{}
		defer kem.Clean()
		if err := kem.Init(scheme, nil); err != nil {
			b.Fatal(err)
		}
		pk, err := kem.GenerateKeyPair()
		if err != nil {
			b.Fatal(err)
		}
		b.Run(scheme, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				kem.EncapSecret(pk)
			}
		})
	}
}

func BenchmarkDecapsulate(b *testing.B) {
	for _, scheme := range allSchemes {
		kem := oqs.KeyEncapsulation{}
		defer kem.Clean()
		if err := kem.Init(scheme, nil); err != nil {
			b.Fatal(err)
		}
		pk, err := kem.GenerateKeyPair()
		if err != nil {
			b.Fatal(err)
		}
		ct, _, err := kem.EncapSecret(pk)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(scheme, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				kem.DecapSecret(ct)
			}
		})
	}
}
