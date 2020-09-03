// Copyright 2020 Coinbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keys

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"os/exec"

	"github.com/coinbase/rosetta-sdk-go/types"
)

const binary = "/Users/bkase/_build/default/src/app/rosetta/ocaml-signer/signer.exe"

func OcamlGeneratePrivKey() string {
	cmd := exec.Command(binary, "generate-private-key")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	return out.String()
}

func OcamlDerivePublicKey(privKeyHex string) string {
	cmd := exec.Command(binary, "derive-public-key", "-private-key", privKeyHex)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	return out.String()
}

func OcamlSign(privKeyHex string, unsignedTransactionHex string) string {
	cmd := exec.Command(
		binary,
		"sign",
		"-private-key",
		privKeyHex,
		"-unsigned-transaction",
		unsignedTransactionHex,
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	return out.String()
}

func OcamlVerify(pubKeyHex string, signedTransactionHex string) bool {
	cmd := exec.Command(
		binary,
		"verify",
		"-public-key",
		pubKeyHex,
		"-signed-transaction",
		signedTransactionHex,
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		println(err)
		return false
	}
	return true
}

// Signer

type SignerTweedle struct {
	KeyPair *KeyPair
}

var _ Signer = (*SignerTweedle)(nil)

func (s *SignerTweedle) PublicKey() *types.PublicKey {
	return s.KeyPair.PublicKey
}

// Sign arbitrary payloads using a KeyPair
func (s *SignerTweedle) Sign(
	payload *types.SigningPayload,
	sigType types.SignatureType,
) (*types.Signature, error) {
	err := s.KeyPair.IsValid()
	if err != nil {
		return nil, err
	}

	if !(payload.SignatureType == types.SchnorrPoseidon || payload.SignatureType == "") {
		return nil, fmt.Errorf(
			"%w: expected %v but got %v",
			ErrSignUnsupportedPayloadSignatureType,
			types.SchnorrPoseidon,
			payload.SignatureType,
		)
	}

	if sigType != types.SchnorrPoseidon {
		return nil, fmt.Errorf(
			"%w: expected %v but got %v",
			ErrSignUnsupportedSigType,
			types.SchnorrPoseidon,
			sigType,
		)
	}

	privKeyBytes := s.KeyPair.PrivateKey
	privKeyHex := hex.EncodeToString(privKeyBytes)

	payloadHex := hex.EncodeToString(payload.Bytes)

	signatureHex := OcamlSign(privKeyHex, payloadHex)

	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return nil, err
	}

	return &types.Signature{
		SigningPayload: payload,
		PublicKey:      s.KeyPair.PublicKey,
		SignatureType:  payload.SignatureType,
		Bytes:          signature,
	}, nil
}

// Verify verifies a Signature, by checking the validity of a Signature,
// the SigningPayload, and the PublicKey of the Signature.
func (s *SignerTweedle) Verify(signature *types.Signature) error {
	if signature.SignatureType != types.SchnorrPoseidon {
		return fmt.Errorf(
			"%w: expected %v but got %v",
			ErrVerifyUnsupportedPayloadSignatureType,
			types.SchnorrPoseidon,
			signature.SignatureType,
		)
	}

	pubKey := signature.PublicKey.Bytes
	pubKeyHex := hex.EncodeToString(pubKey)

	message := signature.SigningPayload.Bytes
	messageHex := hex.EncodeToString(message)

	verify := OcamlVerify(pubKeyHex, messageHex)
	if !verify {
		return ErrVerifyFailed
	}

	return nil
}
