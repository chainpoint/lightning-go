module github.com/chainpoint/lightning-go

go 1.16

require (
	github.com/btcsuite/btcd v0.23.1
	github.com/btcsuite/btcd/btcutil v1.1.2
	github.com/lightningnetwork/lnd v0.9.2-beta
	google.golang.org/grpc v1.38.0
	gopkg.in/macaroon.v2 v2.1.0
)

replace (
	github.com/lightningnetwork/lnd v0.9.2-beta => github.com/tierion/lnd v0.9.0-beta-rc1.0.20220822205137-db0cfb35b28c
	github.com/lightningnetwork/lnd/lnrpc/invoicesrpc v0.9.2-beta => github.com/tierion/lnd/lnrpc/invoicesrpc v0.9.0-beta-rc1.0.20220822205137-db0cfb35b28c
	github.com/lightningnetwork/lnd/lnrpc/signrpc v0.9.2-beta => github.com/tierion/lnd/lnrpc/signrpc v0.9.0-beta-rc1.0.20220822205137-db0cfb35b28c
	github.com/lightningnetwork/lnd/lnrpc/walletrpc v0.9.2-beta => github.com/tierion/lnd/lnrpc/walletrpc v0.9.0-beta-rc1.0.20220822205137-db0cfb35b28c
	github.com/lightningnetwork/lnd/lntypes v0.9.2-beta => github.com/tierion/lnd/lntypes v0.9.0-beta-rc1.0.20220822205137-db0cfb35b28c
	github.com/lightningnetwork/lnd/macaroons v0.9.2-beta => github.com/tierion/lnd/macaroons v0.9.0-beta-rc1.0.20220822205137-db0cfb35b28c
)
