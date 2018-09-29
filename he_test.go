package he

import (
    "testing"
    "github.com/ethereum/go-ethereum/crypto"
    "crypto/ecdsa"
    "math/big"
)

// GenerateKey() returns a key smaller than half of curve N to prevent
// out bound result by add op.
func GenerateKey() (*ecdsa.PrivateKey, error) {
    half := new(big.Int).Div(crypto.S256().Params().N, big.NewInt(2))
    for {
        k, err := crypto.GenerateKey()
        if err != nil {
            return nil, err
        }
        
        // Return a key smaller than half of curve N.
        if half.Cmp(k.D) > 0 {
            return k, nil
        }
    }
}


func TestAddHE(t *testing.T) {
    k1, err := GenerateKey()
    k2, err := GenerateKey()
    
    nPub, err := AddPub(k1.PublicKey, k2.PublicKey)
    nPriv, err := AddPriv(k1, k2)
    if err != nil {
        t.Error(err)
    }
    
    if !Verify(nPriv, nPub) {
        t.Error("curve not support add homomorphic encryption")
    }
    
    t.Log("test passed: curve support add homomorphic encryption")
}
