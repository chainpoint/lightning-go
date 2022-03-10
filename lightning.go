package lightning_go

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightningnetwork/lnd/lnrpc/invoicesrpc"
	"os"
	"runtime"
	"time"

	"io/ioutil"
	"net"
	"strings"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"

	"github.com/lightningnetwork/lnd/lnrpc/signrpc"

	"github.com/btcsuite/btcd/txscript"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"

	"github.com/lightningnetwork/lnd/lnrpc"

	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	macaroon "gopkg.in/macaroon.v2"
)

type LightningClient struct {
	ServerHostPort      string
	TlsPath             string
	MacPath             string
	MinConfs            int64
	TargetConfs         int64
	LndLogLevel         string
	Testnet             bool
	WalletAddress       string
	WalletPass          string
	WalletSeed          []string
	LastFee             int64
	HashPrice           int64
	SessionSecret       string
	NoMacaroons         bool
}

var (
	maxMsgRecvSize = grpc.MaxCallRecvMsgSize(1 * 1024 * 1024 * 200)
)

// GetCurrentFuncName : get name of function being called
func GetCurrentFuncName(numCallStack int) string {
	pc, _, _, _ := runtime.Caller(numCallStack)
	return fmt.Sprintf("%s", runtime.FuncForPC(pc).Name())
}

// GetClient : Returns default lightning grpc client
func (ln *LightningClient) GetClient() (lnrpc.LightningClient, func(), error) {
	conn, err := ln.CreateConn()
	closeIt := func() {
		conn.Close()
	}
	if err != nil {
		return nil, nil, err
	}
	return lnrpc.NewLightningClient(conn), closeIt, nil
}

// GetWalletUnlockerClient : returns wallet unlocker grpc client- non-authenticated session
func (ln *LightningClient) GetWalletUnlockerClient() (lnrpc.WalletUnlockerClient, func(), error) {
	conn, err := ln.CreateConn()
	closeIt := func() {
		conn.Close()
	}
	if err != nil {
		return nil, nil, err
	}
	return lnrpc.NewWalletUnlockerClient(conn), closeIt, nil
}

// GetWalletClient : returns wallet grpc client
func (ln *LightningClient) GetWalletClient() (walletrpc.WalletKitClient, func(), error) {
	conn, err := ln.CreateConn()
	closeIt := func() {
		conn.Close()
	}
	if err != nil {
		return nil, nil, err
	}
	return walletrpc.NewWalletKitClient(conn), closeIt, nil
}

// GetInvoiceClient : retrieve invoice grpc client
func (ln *LightningClient) GetInvoiceClient() (invoicesrpc.InvoicesClient, func(), error) {
	conn, err := ln.CreateConn()
	closeIt := func() {
		conn.Close()
	}
	if err != nil {
		return nil, nil, err
	}
	return invoicesrpc.NewInvoicesClient(conn), closeIt, nil
}

// Unlocker: unlock wallet using wallet unlocker client based on this LightningClient's password
func (ln *LightningClient) Unlocker() error {
	conn, close, err := ln.GetWalletUnlockerClient()
	defer close()
	if err != nil {
		return err
	}
	unlockReq := lnrpc.UnlockWalletRequest{
		WalletPassword: []byte(ln.WalletPass),
		RecoveryWindow: 10000,
		ChannelBackups: nil,
	}
	_, err = conn.UnlockWallet(context.Background(), &unlockReq)
	if err != nil {
		if strings.Contains(err.Error(), "unknown service lnrpc.WalletUnlocker") || strings.Contains(err.Error(), "wallet already unlocked") {
			return nil
		}
		return err
	}
	return nil
}

// InitWallet : initialize wallet with given cipher phrase and passwors
func (ln *LightningClient) InitWallet() error {
	conn, close, err := ln.GetWalletUnlockerClient()
	defer close()
	if err != nil {
		return err
	}
	initReq := lnrpc.InitWalletRequest{
		WalletPassword:     []byte(ln.WalletPass),
		CipherSeedMnemonic: ln.WalletSeed,
		AezeedPassphrase:   nil,
		RecoveryWindow:     10000,
		ChannelBackups:     nil,
		StatelessInit:      false,
	}
	_, err = conn.InitWallet(context.Background(), &initReq)
	if err != nil {
		return err
	}
	return nil
}

// GenSeed : generate a wallet seed. Used for InitWallet
func (ln *LightningClient) GenSeed() ([]string, error) {
	conn, close, err := ln.GetWalletUnlockerClient()
	defer close()
	if err != nil {
		return []string{}, err
	}
	seedReq := lnrpc.GenSeedRequest{}
	resp, err := conn.GenSeed(context.Background(), &seedReq)
	if err != nil {
		return []string{}, err
	}
	return resp.CipherSeedMnemonic, nil
}

// NewAddress : create a new address for a wallet. Returns the wallet address or an error
func (ln *LightningClient) NewAddress() (string, error) {
	conn, close, err := ln.GetClient()
	defer close()
	if err != nil {
		return "", err
	}
	addrReq := lnrpc.NewAddressRequest{Type: 0}
	resp, err := conn.NewAddress(context.Background(), &addrReq)
	if err != nil {
		return "", err
	}
	return resp.Address, nil
}

// CreateClient : creates a new basic client struct
func CreateClient(serverHostPort string, tlsPath string, macPath string) LightningClient {
	return LightningClient{
		ServerHostPort: serverHostPort,
		TlsPath:        tlsPath,
		MacPath:        macPath,
	}
}

// IsLnUri : determines if a url meets criteria <pub_key>@<ip>:<port>
func IsLnUri(uri string) bool {
	peerParts := strings.Split(uri, "@")
	if len(peerParts) != 2 {
		return false
	}
	if _, err := hex.DecodeString(peerParts[0]); err != nil {
		return false
	}
	if _, _, err := net.SplitHostPort(peerParts[1]); err != nil {
		return false
	}
	return true
}

// GetIpFromUri : parses and IP from a uri as determined by IsLnUri
func GetIpFromUri(uri string) string {
	peerParts := strings.Split(uri, "@")
	if len(peerParts) != 2 {
		return ""
	}
	addrPort := peerParts[1]
	ipArr := strings.Split(addrPort, ":")
	if len(ipArr) != 2 {
		return ""
	}
	return ipArr[0]
}

// GetInfo : retrieves basic lnd node info
func (ln *LightningClient) GetInfo() (*lnrpc.GetInfoResponse, error) {
	client, closeFunc, err := ln.GetClient()
	if err != nil {
		return nil, err
	}
	defer closeFunc()
	resp, err := client.GetInfo(context.Background(), &lnrpc.GetInfoRequest{})
	return resp, err
}

// GetWalletBalance : retrieves balance from the current wallet
func (ln *LightningClient) GetWalletBalance() (*lnrpc.WalletBalanceResponse, error) {
	client, closeFunc, err := ln.GetClient()
	if err != nil {
		return nil, err
	}
	defer closeFunc()
	resp, err := client.WalletBalance(context.Background(), &lnrpc.WalletBalanceRequest{})
	return resp, err
}

// GetTransaction : retrieves a transaction from the current unlocked wallet matching @id
func (ln *LightningClient) GetTransaction(id []byte) (lnrpc.TransactionDetails, error) {
	client, closeFunc, err := ln.GetClient()
	if err != nil {
		return lnrpc.TransactionDetails{}, err
	}
	defer closeFunc()
	txResponse, err := client.GetTransactions(context.Background(), &lnrpc.GetTransactionsRequest{})
	if err != nil {
		return lnrpc.TransactionDetails{}, err
	}
	for _, tx := range txResponse.Transactions {
		if tx.TxHash == hex.EncodeToString(id) {
			return lnrpc.TransactionDetails{Transactions: []*lnrpc.Transaction{tx}}, nil
		}
	}
	return lnrpc.TransactionDetails{}, nil
}

// GetBlockByHeight : retrieve a bitcoin block of a given height. Only available from tierion/lnd
func (ln *LightningClient) GetBlockByHeight(height int64) (lnrpc.BlockDetails, error) {
	client, closeFunc, err := ln.GetClient()
	if err != nil {
		return lnrpc.BlockDetails{}, err
	}
	defer closeFunc()
	block, err := client.GetBlock(context.Background(), &lnrpc.GetBlockRequest{BlockHeight: uint32(height)})
	if err != nil {
		return lnrpc.BlockDetails{}, err
	}
	return *block, nil
}

// GetBlockByHeight : retrieve a bitcoin block of a given hash. Only available from tierion/lnd
func (ln *LightningClient) GetBlockByHash(hash string) (lnrpc.BlockDetails, error) {
	client, closeFunc, err := ln.GetClient()
	if err != nil {
		return lnrpc.BlockDetails{}, err
	}
	defer closeFunc()
	block, err := client.GetBlock(context.Background(), &lnrpc.GetBlockRequest{BlockHash: hash})
	if err != nil {
		return lnrpc.BlockDetails{}, err
	}
	return *block, nil
}

// PeerExists : determine if the current lnd node is connected to a particular peer.
// peer must be an lnd uri.
func (ln *LightningClient) PeerExists(peer string) (bool, error) {
	peerParts := strings.Split(peer, "@")
	if len(peerParts) != 2 {
		return false, errors.New("Malformed peer string (must be pubKey@host)")
	}
	pubKey := peerParts[0]
	addr := peerParts[1]
	client, closeFunc, err := ln.GetClient()
	if err != nil {
		return false, err
	}
	defer closeFunc()
	peers, err := client.ListPeers(context.Background(), &lnrpc.ListPeersRequest{})
	if err != nil {
		return false, err
	}
	for _, peer := range peers.Peers {
		if peer.PubKey == pubKey && peer.Address == addr {
			return true, nil
		}
	}
	return false, nil
}

// AddPeer : adds a peer conforming to lnd uri spec to the current node
func (ln *LightningClient) AddPeer(peer string) error {
	peerParts := strings.Split(peer, "@")
	if len(peerParts) != 2 {
		return errors.New("Malformed peer string (must be pubKey@host)")
	}
	peerAddr := lnrpc.LightningAddress{
		Pubkey: peerParts[0],
		Host:   peerParts[1],
	}
	connectPeer := lnrpc.ConnectPeerRequest{
		Addr: &peerAddr,
	}
	client, closeFunc, err := ln.GetClient()
	if err != nil {
		return err
	}
	defer closeFunc()
	_, err = client.ConnectPeer(context.Background(), &connectPeer)
	if err != nil {
		return err
	}
	return nil
}

// AnyChannelExists : determine if any channel, active or pending, exists for this peer with satVal value or greater.
func (ln *LightningClient) AnyChannelExists(peer string, satVal int64) (bool, error) {
	peerParts := strings.Split(peer, "@")
	if len(peerParts) != 2 {
		return false, errors.New("Malformed peer string (must be pubKey@host)")
	}
	remotePubkey := peerParts[0]
	channels, err := ln.GetChannels()
	if err != nil {
		return false, err
	}
	for _, chann := range channels.Channels {
		if chann.RemotePubkey == remotePubkey {
			if chann.Capacity >= satVal {
				return true, nil
			}
		}
	}
	pending, err := ln.GetPendingChannels()
	if err != nil {
		return false, err
	}
	for _, chann := range pending.PendingOpenChannels {
		if chann.Channel.RemoteNodePub == remotePubkey {
			if chann.Channel.Capacity >= satVal {
				return true, nil
			}
		}
	}
	return false, nil
}

// OurChannelOpenAndFunded : determine if the current node has opened a channel of a certain value or greater
func (ln *LightningClient) OurChannelOpenAndFunded(peer string, satVal int64) (bool, error) {
	peerParts := strings.Split(peer, "@")
	if len(peerParts) != 2 {
		return false, errors.New("Malformed peer string (must be pubKey@host)")
	}
	remotePubkey := peerParts[0]
	channels, err := ln.GetChannels()
	if err != nil {
		return false, err
	}
	for _, chann := range channels.Channels {
		if chann.RemotePubkey == remotePubkey {
			if chann.Capacity >= satVal {
				return true, nil
			}
		}
	}
	return false, nil
}

// RemoteChannelOpenAndFunded : determine if a remote peer has opened a channel of a certain value or greater
func (ln *LightningClient) RemoteChannelOpenAndFunded(peer string, satVal int64) (bool, error) {
	peerParts := strings.Split(peer, "@")
	if len(peerParts) != 2 {
		return false, errors.New("Malformed peer string (must be pubKey@host)")
	}
	remotePubkey := peerParts[0]
	channels, err := ln.GetChannels()
	if err != nil {
		return false, err
	}
	for _, chann := range channels.Channels {
		if chann.RemotePubkey == remotePubkey {
			if chann.Capacity >= satVal {
				return true, nil
			}
		}
	}
	return false, nil
}

// GetChannels : retrieve all active and funded channels
func (ln *LightningClient) GetChannels() (*lnrpc.ListChannelsResponse, error) {
	client, closeFunc, err := ln.GetClient()
	if err != nil {
		return nil, err
	}
	defer closeFunc()
	channels, err := client.ListChannels(context.Background(), &lnrpc.ListChannelsRequest{})
	return channels, err
}

// GetPendingChannels : get channels that have not yet had a funding btc tx confirmed
func (ln *LightningClient) GetPendingChannels() (*lnrpc.PendingChannelsResponse, error) {
	client, closeFunc, err := ln.GetClient()
	if err != nil {
		return nil, err
	}
	defer closeFunc()
	channels, err := client.PendingChannels(context.Background(), &lnrpc.PendingChannelsRequest{})
	return channels, err
}

// CreateChannel : open and fund a channel of a satVal amount to a peer.
func (ln *LightningClient) CreateChannel(peer string, satVal int64) (lnrpc.Lightning_OpenChannelClient, error) {
	peerParts := strings.Split(peer, "@")
	if len(peerParts) != 2 {
		return nil, errors.New("Malformed peer string (must be pubKey@host)")
	}
	pubKey, err := hex.DecodeString(peerParts[0])
	if err != nil {
		return nil, err
	}
	openSesame := lnrpc.OpenChannelRequest{
		NodePubkey: pubKey,
	}
	openSesame.LocalFundingAmount = satVal
	if ln.MinConfs != 0 {
		openSesame.MinConfs = int32(ln.MinConfs)
	}
	if ln.TargetConfs != 0 {
		openSesame.TargetConf = int32(ln.TargetConfs)
	}
	client, closeFunc, err := ln.GetClient()
	if err != nil {
		return nil, err
	}
	defer closeFunc()
	resp, err := client.OpenChannel(context.Background(), &openSesame)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Create a connection to a lightning node with a tls cert path and a macaroon path.
// Used by most other methods
func (ln *LightningClient) CreateConn() (*grpc.ClientConn, error) {
	// Load the specified TLS certificate and build transport credentials
	// with it.
	creds, err := credentials.NewClientTLSFromFile(ln.TlsPath, "")
	if err != nil {
		return nil, err
	}

	// Create a dial options array.
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
	}

	if !ln.NoMacaroons {
		macBytes, err := ioutil.ReadFile(ln.MacPath)
		if err != nil {
			return nil, err
		}

		mac := &macaroon.Macaroon{}
		if err = mac.UnmarshalBinary(macBytes); err != nil {
			return nil, err
		}

		macConstraints := []macaroons.Constraint{
			macaroons.TimeoutConstraint(60),
		}

		// Apply constraints to the macaroon.
		constrainedMac, err := macaroons.AddConstraints(mac, macConstraints...)
		if err != nil {
			return nil, err
		}

		// Now we append the macaroon credentials to the dial options.
		cred, _ := macaroons.NewMacaroonCredential(constrainedMac)
		opts = append(opts, grpc.WithPerRPCCredentials(cred))
	}
	// We need to use a custom dialer so we can also connect to unix sockets
	// and not just TCP addresses.
	hostPortArr := strings.Split(ln.ServerHostPort, ":")
	defaultRPCPort := "10009"
	if len(hostPortArr) > 1 {
		defaultRPCPort = hostPortArr[1]
	}
	genericDialer := lncfg.ClientAddressDialer(defaultRPCPort)
	opts = append(opts, grpc.WithContextDialer(genericDialer))
	opts = append(opts, grpc.WithDefaultCallOptions(maxMsgRecvSize))

	conn, err := grpc.Dial(ln.ServerHostPort, opts...)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Convert the last known lnd witness fee to non-witness fee type
func (ln *LightningClient) feeSatByteToWeight() int64 {
	return int64(ln.LastFee * 1000 / blockchain.WitnessScaleFactor)
}

// GetLndFeeEstimate : retrieve fee from lnd node's designated fee estimator
func (ln *LightningClient) GetLndFeeEstimate() (int64, error) {
	wallet, closeFunc, err := ln.GetWalletClient()
	defer closeFunc()
	fee, err := wallet.EstimateFee(context.Background(), &walletrpc.EstimateFeeRequest{ConfTarget: 2})
	if err != nil {
		return 0, err
	}
	if fee.SatPerKw == 12500 {
		return fee.SatPerKw, errors.New("static fee has been returned")
	}
	return fee.SatPerKw, nil
}

// SendOpReturn : send an op return as an output from the connected lnd node
func (ln *LightningClient) SendOpReturn(hash []byte) (string, string, error) {
	b := txscript.NewScriptBuilder()
	b.AddOp(txscript.OP_RETURN)
	b.AddData(hash)
	outputScript, err := b.Script()
	if err != nil {
		return "", "", err
	}
	wallet, closeFunc, err := ln.GetWalletClient()
	defer closeFunc()
	outputs := []*signrpc.TxOut{
		{
			Value:    0,
			PkScript: outputScript,
		},
	}
	outputRequest := walletrpc.SendOutputsRequest{SatPerKw: ln.LastFee, Outputs: outputs}
	resp, err := wallet.SendOutputs(context.Background(), &outputRequest)
	if err != nil {
		return "", "", err
	}
	tx, err := btcutil.NewTxFromBytes(resp.RawTx)
	if err != nil {
		return "", "", err
	}
	var msgTx wire.MsgTx
	if err := msgTx.BtcDecode(bytes.NewReader(resp.RawTx), 0, wire.WitnessEncoding); err != nil {
		return "", "", err
	}
	buf := bytes.NewBuffer(make([]byte, 0, msgTx.SerializeSizeStripped()))
	if err := msgTx.SerializeNoWitness(buf); err != nil {
		return "", "", err
	}
	return tx.Hash().String(), hex.EncodeToString(buf.Bytes()), nil
}

// SendCoins ; send amt of satothis to addr address and wait for confs confirmations
func (ln *LightningClient) SendCoins(addr string, amt int64, confs int32) (lnrpc.SendCoinsResponse, error) {
	wallet, closeWalletFunc, err := ln.GetWalletClient()
	if err != nil {
		return lnrpc.SendCoinsResponse{}, err
	}
	defer closeWalletFunc()
	estimatedFee, err := wallet.EstimateFee(context.Background(), &walletrpc.EstimateFeeRequest{ConfTarget: 2})
	if err != nil {
		return lnrpc.SendCoinsResponse{}, err
	}
	client, closeFunc, err := ln.GetClient()
	defer closeFunc()
	sendCoinsReq := lnrpc.SendCoinsRequest{
		Addr:       addr,
		Amount:     amt,
		TargetConf: confs,
		SatPerByte: estimatedFee.SatPerKw,
	}
	resp, err := client.SendCoins(context.Background(), &sendCoinsReq)
	return *resp, err
}

// LookupInvoices : Retrieve an invoice by payment hash. used for LSAT authentication
func (ln *LightningClient) LookupInvoice(payhash []byte) (lnrpc.Invoice, error) {
	lightning, close, err := ln.GetClient()
	if err != nil {
		return lnrpc.Invoice{}, err
	}
	defer close()
	invoice, err := lightning.LookupInvoice(context.Background(), &lnrpc.PaymentHash{RHash: payhash})
	if err != nil {
		return lnrpc.Invoice{}, err
	}
	return *invoice, nil
}

// ReplaceByFee : retrieve a pending transaction and implement rbf. Not currently functional.
func (ln *LightningClient) ReplaceByFee(txid string, OPRETURNIndex bool, newfee int) (walletrpc.BumpFeeResponse, error) {
	wallet, close, err := ln.GetWalletClient()
	if err != nil {
		return walletrpc.BumpFeeResponse{}, err
	}
	defer close()
	decodedId, err := hex.DecodeString(txid)
	if err != nil {
		return walletrpc.BumpFeeResponse{}, err
	}
	tx, err := ln.GetTransaction(decodedId)
	if err != nil {
		return walletrpc.BumpFeeResponse{}, err
	}
	if len(tx.Transactions) == 0 {
		return walletrpc.BumpFeeResponse{}, errors.New("no transaction found")
	}
	rawTxHex := tx.GetTransactions()[0].RawTxHex
	decodedTx, err := hex.DecodeString(rawTxHex)
	if err != nil {
		return walletrpc.BumpFeeResponse{}, err
	}
	var msgTx wire.MsgTx
	if err := msgTx.BtcDecode(bytes.NewReader(decodedTx), 0, wire.WitnessEncoding); err != nil {
		return walletrpc.BumpFeeResponse{}, err
	}
	chainParam := chaincfg.Params{}
	if ln.Testnet {
		chainParam = chaincfg.TestNet3Params
	} else {
		chainParam = chaincfg.MainNetParams
	}
	var outputIndex uint32
	for i, txOut := range msgTx.TxOut {
		script, _, _, err := txscript.ExtractPkScriptAddrs(
			txOut.PkScript, &chainParam,
		)
		if err != nil {
			continue
		}
		if OPRETURNIndex {
			if script.String() == txscript.NullDataTy.String() {
				outputIndex = uint32(i)
				break
			}
		} else {
			if script.String() != txscript.NullDataTy.String() {
				outputIndex = uint32(i)
				break
			}
		}
	}
	txIdHash := (msgTx).TxHash()
	txIdBytes := txIdHash.CloneBytes()
	outpoint := lnrpc.OutPoint{
		TxidBytes:   txIdBytes,
		OutputIndex: outputIndex,
	}
	rbfReq := walletrpc.BumpFeeRequest{
		Outpoint:   &outpoint,
		TargetConf: 0,
		SatPerByte: uint32(newfee),
	}
	resp, err := wallet.BumpFee(context.Background(), &rbfReq)
	if err != nil {
		return walletrpc.BumpFeeResponse{}, err
	}
	return *resp, nil
}

//WaitForConnection : Wait for a connection to an lnd node to be ready within d amount of time
func (ln *LightningClient) WaitForConnection(d time.Duration) error {
	//Wait for lightning connection
	deadline := time.Now().Add(d)
	for !time.Now().After(deadline) {
		conn, err := ln.CreateConn()
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		} else {
			conn.Close()
			return nil
		}
	}
	return errors.New("Exceeded LND Connection deadline: check that LND has peers")
}

// WaitForMacaroon : wait for an lnd node to create a macaroon within d amount of time
func (ln *LightningClient) WaitForMacaroon(d time.Duration) error {
	//Wait for lightning connection
	deadline := time.Now().Add(d)
	for !time.Now().After(deadline) {
		if _, err := os.Stat(ln.MacPath); os.IsNotExist(err) {
			time.Sleep(5 * time.Second)
			continue
		} else {
			return nil
		}
	}
	return errors.New("Exceeded LND Macaroon deadline: check that LND has peers")
}

// WaitForNewAddress : wait until a new address call succeeds within d amount of time, or error
func (ln *LightningClient) WaitForNewAddress(d time.Duration) (string, error) {
	//Wait for lightning connection
	deadline := time.Now().Add(d)
	for !time.Now().After(deadline) {
		addr, err := ln.NewAddress()
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		} else {
			return addr, nil
		}
	}
	return "", errors.New("Exceeded LND New Address deadline: check that LND has peers")
}
