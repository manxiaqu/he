package he

import (
    "crypto/ecdsa"
    "errors"
    "math/big"
)

var errCurveNotEquals = errors.New("curve name not equals")

// AddPub returns result of addition of two public keys.
func AddPub(k1, k2 ecdsa.PublicKey) (*ecdsa.PublicKey, error) {
    if k1.Curve.Params().Name != k2.Curve.Params().Name {
        return nil, errCurveNotEquals
    }
    
    //
    x, y := k1.Curve.Add(k1.X, k1.Y, k2.X, k2.Y)
    pub := new(ecdsa.PublicKey)
    pub.X = x
    pub.Y = y
    pub.Curve = k1.Curve
    
    return pub, nil
}

// AddPriv returns result of addition of two private keys.
func AddPriv(k1, k2 *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
    if k1.Curve.Params().Name != k2.Params().Name {
        return nil, errCurveNotEquals
    }
    
    // Add and check.
    k := new(big.Int).Add(k1.D, k2.D)
    if k.Cmp(k1.Curve.Params().N) >= 0 {
        return nil, errors.New("can not handle a key bigger than N of curve")
    }
    
    // Set public key.
    priv := new(ecdsa.PrivateKey)
    priv.D = k
    priv.PublicKey.X, priv.PublicKey.Y = k1.Curve.ScalarBaseMult(k.Bytes())
    priv.PublicKey.Curve = k1.Curve
    
    return priv, nil
}

// Verify verifies pub is the public key of priv or not.
func Verify(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) bool {
    if priv.Curve.Params().Name != pub.Curve.Params().Name {
        return false
    }
    
    if priv.PublicKey.X.Cmp(pub.X) != 0 || priv.PublicKey.Y.Cmp(pub.Y) != 0 {
        return false
    }
    
    return true
}