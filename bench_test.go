package soroauth

import (
	"crypto/sha256"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// BenchmarkDecodeAuthorizationEntry covers the decode-limit path
// DecodeAuthorizationEntry adds over xdr.SafeUnmarshalBase64, so a change to
// MaxDecodeDepth or MaxDecodeInputBytes checking can be shown not to have
// regressed the common case of decoding a well-formed entry.
//
// BenchmarkPreimage, BenchmarkPayload and BenchmarkAuthorizeEntry already
// exist in bench_signing_test.go (issue #107) and are not duplicated here.
//
// It uses a fixed input and an in-memory deterministic key, so it never
// touches the network and is safe to run anywhere.

const benchmarkValidUntilLedger = 1234567

// benchmarkEntryAndSigner builds a complete V2 address entry whose address is
// the benchmark key's own.
func benchmarkEntryAndSigner(b *testing.B) (xdr.SorobanAuthorizationEntry, *keypair.Full) {
	b.Helper()

	seed := sha256.Sum256([]byte("soroauth-benchmark-signer"))
	kp, err := keypair.FromRawSeed(seed)
	if err != nil {
		b.Fatalf("deriving the benchmark keypair: %v", err)
	}
	accountID, err := xdr.AddressToAccountId(kp.Address())
	if err != nil {
		b.Fatalf("decoding the benchmark address: %v", err)
	}
	address := xdr.ScAddress{
		Type:      xdr.ScAddressTypeScAddressTypeAccount,
		AccountId: &accountID,
	}

	var contractID xdr.ContractId
	for i := range contractID {
		contractID[i] = byte(i)
	}
	contract := xdr.ScAddress{
		Type:       xdr.ScAddressTypeScAddressTypeContract,
		ContractId: &contractID,
	}

	amount := xdr.Int128Parts{Hi: 0, Lo: 1000}
	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:                   address,
				Nonce:                     42,
				SignatureExpirationLedger: 1,
				Signature:                 xdr.ScVal{Type: xdr.ScValTypeScvVoid},
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: contract,
					FunctionName:    xdr.ScSymbol("transfer"),
					Args: xdr.ScVec{
						{Type: xdr.ScValTypeScvAddress, Address: &address},
						{Type: xdr.ScValTypeScvAddress, Address: &contract},
						{Type: xdr.ScValTypeScvI128, I128: &amount},
					},
				},
			},
		},
	}
	return entry, kp
}

func BenchmarkDecodeAuthorizationEntry(b *testing.B) {
	entry, _ := benchmarkEntryAndSigner(b)
	encoded, err := xdr.MarshalBase64(entry)
	if err != nil {
		b.Fatalf("encoding the benchmark entry: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := DecodeAuthorizationEntry(encoded); err != nil {
			b.Fatalf("DecodeAuthorizationEntry returned an unexpected error: %v", err)
		}
	}
}
