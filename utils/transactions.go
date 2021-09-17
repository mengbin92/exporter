package utils

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/ledger/rwset"
	"github.com/hyperledger/fabric-protos-go/ledger/rwset/kvrwset"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric/common/tools/protolator"
	"github.com/pkg/errors"
)

type cachedIdentity struct {
	mspID string
	cert  *x509.Certificate
}

func getIdentity(serilizedIdentity []byte) (*cachedIdentity, error) {
	var err error

	sid := &msp.SerializedIdentity{}
	err = proto.Unmarshal(serilizedIdentity, sid)
	if err != nil {
		return nil, errors.Wrap(err, "error unmarshal SerializedIdentity")
	}

	var cert *x509.Certificate
	cert, err = decodeX509Pem(sid.IdBytes)
	if err != nil {
		return nil, errors.Wrap(err, "error decodeX509Pem")
	}

	return &cachedIdentity{
		mspID: sid.Mspid,
		cert:  cert,
	}, nil

}
func decodeX509Pem(certPem []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPem)
	if block == nil {
		return nil, errors.New("error bad Certificate")
	}

	return x509.ParseCertificate(block.Bytes)
}

type Endorser struct {
	MSP  string `json:"msp"`
	Name string `json:"name"`
}

// Transaction is the detail of transaction, but not contains RW set
type Transaction struct {
	ChannelName      string `json:"channel_name"`
	ID               string `json:"id"`
	Type             string `json:"type"`
	Creator          string `json:"creator"`
	CreatorMSP       string `json:"creator_msp"`
	ChaincodeName    string `json:"chaincode_name"`
	ValidationResult string `json:"validation_result"`
	BlockNumber      uint64 `json:"block_number"`
	// TxNumber         int         `json:"tx_number"`
	CreatedAt time.Time   `json:"created_at"`
	Endorsers []*Endorser `json:"endorsers"`
	Value     *RawValue   `json:"raw"`
}

// RawValue define the raw value stored into blockchain
type RawValue struct {
	ChaincodeID *peer.ChaincodeID  `json:"chaincodeid"`
	Input       []string           `json:"input"`
	Reads       []*kvrwset.KVRead  `json:"reads"`
	Writes      []*kvrwset.KVWrite `json:"writes"`
}

// TransactionDetail contains RW set
type TransactionDetail struct {
	*Transaction
	Payload interface{} `json:"payload"`
}

// Convert Envelope To TXDetail
func ConvertEnvelopeToTXDetail(txFlag int32, env *common.Envelope) (*TransactionDetail, error) {
	txDetail := &TransactionDetail{}
	payload, err := GetPayload(env)
	if err != nil {
		Log.Error(fmt.Sprintf("Unexpected error from unmarshal envelope: %s", err.Error()))
		return nil, errors.Wrap(err, "unexpected error from unmarshal envelope")
	}

	chdr, err := UnmarshalChannelHeader(payload.Header.ChannelHeader)
	if err != nil {
		Log.Error(fmt.Sprintf("Unexpected error from unmarshal channel header: %s", err.Error()))
		return nil, errors.Wrap(err, "unexpected error from unmarshal channel header")
	}

	shdr, err := GetSignatureHeader(payload.Header.SignatureHeader)
	if err != nil {
		Log.Error(fmt.Sprintf("Unexpected error from unmarshal signature header: %s", err.Error()))
		return nil, errors.Wrap(err, "unexpected error from unmarshal signature header")
	}

	identity, err := getIdentity(shdr.Creator)
	if err != nil {
		return nil, errors.Wrap(err, "error getIdentity")
	}

	tx := &Transaction{
		ID:               chdr.TxId,
		Type:             common.HeaderType_name[chdr.Type],
		CreatorMSP:       identity.mspID,
		ValidationResult: peer.TxValidationCode_name[txFlag],
		CreatedAt:        time.Unix(chdr.Timestamp.Seconds, int64(chdr.Timestamp.Nanos)),
	}

	if identity.cert != nil {
		tx.Creator = identity.cert.Subject.CommonName
	}

	hdrExt, err := GetChaincodeHeaderExtension(payload.Header)
	if err != nil {
		Log.Error(fmt.Sprintf("Unexpected error from GetChaincodeHeaderExtension: %s", err.Error()))
		return nil, errors.Wrap(err, "unexpected error from GetChaincodeHeaderExtension")
	}

	if hdrExt.ChaincodeId != nil {
		tx.ChaincodeName = hdrExt.ChaincodeId.Name
	}

	//fetch the endorsers from the envelope
	chaincodeProposalPayload, endorsements, chaincodeAction, err := parseChaincodeEnvelope(env)
	if err != nil {
		Log.Error(fmt.Sprintf("Unexpected error from parseChaincodeEnvelope: %s", err.Error()))
		return nil, errors.Wrap(err, "unexpected error from parseChaincodeEnvelope")
	}
	distinctEndorser := map[string]bool{}
	for _, e := range endorsements {
		identity, err := getIdentity(e.Endorser)
		if err != nil {
			return nil, err
		}
		userName := ""
		if identity.cert != nil {
			userName = identity.cert.Subject.CommonName
		}

		if _, ok := distinctEndorser[identity.mspID+":"+userName]; !ok {
			tx.Endorsers = append(tx.Endorsers, &Endorser{MSP: identity.mspID, Name: userName})
		}

	}

	cis := &peer.ChaincodeInvocationSpec{}
	err = proto.Unmarshal(chaincodeProposalPayload.Input, cis)
	if err != nil {
		return nil, errors.Wrap(err, "unexpected error from unmarshal ChaincodeInvocationSpec")
	}
	tx.Value = parseChaincodeInvocationSpec(cis)
	reads, writes, err := parseChaincodeAction(chaincodeAction, tx.ChaincodeName)
	if err != nil {
		Log.Error(fmt.Sprintf("Unexpected error from parse ChaincodeAction: %s", err.Error()))
		return nil, errors.Wrap(err, "Unexpected error from parse ChaincodeAction")
	}
	tx.Value.Reads = reads
	tx.Value.Writes = writes

	txDetail.Transaction = tx

	buf := new(bytes.Buffer)
	// 替代1.4.* GetMessageTree()，
	err = protolator.DeepMarshalJSON(buf, env)
	if err != nil {
		Log.Error(fmt.Sprintf("Unexpected error from unmarshal ConfigEnvelope caused by error %s", err.Error()))
		return nil, errors.Wrap(err, "unexpected error from unmarshal ConfigEnvelope")
	}
	txDetail.Payload = buf.String()

	return txDetail, nil
}

// parse Chaincode Envelope
func parseChaincodeEnvelope(env *common.Envelope) (*peer.ChaincodeProposalPayload, []*peer.Endorsement, *peer.ChaincodeAction, error) {
	payl, err := GetPayload(env)
	if err != nil {
		Log.Error(err.Error())
		return nil, nil, nil, errors.Wrap(err, "unexpected error from GetPayload")
	}

	tx, err := GetTransaction(payl.Data)
	if err != nil {
		Log.Error(err.Error())
		return nil, nil, nil, errors.Wrap(err, "unexpected error from GetTransaction")
	}

	if len(tx.Actions) == 0 {
		Log.Error("At least one TransactionAction is required")
		return nil, nil, nil, errors.Wrap(err, "at least one TransactionAction is required")
	}

	actionPayload, chaincodeAction, err := GetPayloads(tx.Actions[0])
	if err != nil {
		Log.Error(err.Error())
		return nil, nil, nil, errors.Wrap(err, "unexpected error from GetPayloads")
	}

	chaincodeProposalPayload, err := GetChaincodeProposalPayload(actionPayload.ChaincodeProposalPayload)
	if err != nil {
		Log.Error(err.Error())
		return nil, nil, nil, errors.Wrap(err, "unexpected error from GetChaincodeProposalPayload")
	}

	return chaincodeProposalPayload, actionPayload.Action.Endorsements, chaincodeAction, nil
}

func parseChaincodeInvocationSpec(cis *peer.ChaincodeInvocationSpec) *RawValue {
	raw := &RawValue{}

	raw.ChaincodeID = cis.GetChaincodeSpec().GetChaincodeId()

	args := cis.GetChaincodeSpec().GetInput().GetArgs()
	intput := make([]string, len(args))
	for i := 0; i < len(args); i++ {
		intput[i] = string(args[i])
	}
	raw.Input = intput

	return raw
}

func parseChaincodeAction(action *peer.ChaincodeAction, chaincodename string) ([]*kvrwset.KVRead, []*kvrwset.KVWrite, error) {
	resultBytes := action.GetResults()

	txRWSet := &rwset.TxReadWriteSet{}
	err := proto.Unmarshal(resultBytes, txRWSet)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unexpected error from unmarshal TxReadWriteSet")
	}

	var kvRwSetByte []byte

	for _, rwset := range txRWSet.NsRwset {
		if rwset.Namespace == chaincodename {
			kvRwSetByte = rwset.Rwset
		}
	}
	kvRWSet := &kvrwset.KVRWSet{}
	err = proto.Unmarshal(kvRwSetByte, kvRWSet)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unexpected error from unmarshal KVRWSet")
	}

	return kvRWSet.Reads, kvRWSet.Writes, nil
}
