module github.com/chainpoint/lightning-go

go 1.16

require (
	github.com/btcsuite/btcd v0.22.0-beta.0.20211005184431-e3449998be39
	github.com/btcsuite/btcutil v1.0.3-0.20210527170813-e2ba6805a890
	github.com/lightningnetwork/lnd v0.9.2-beta
	google.golang.org/grpc v1.45.0
	gopkg.in/macaroon.v2 v2.1.0
)

replace (
	github.com/lightningnetwork/lnd v0.9.2-beta => github.com/tierion/lnd v0.9.0-beta-rc1.0.20220119230648-75c2b68027ff
	github.com/lightningnetwork/lnd/lnrpc/invoicesrpc v0.9.2-beta => github.com/tierion/lnd/lnrpc/invoicesrpc v0.9.0-beta-rc1.0.20220119230648-75c2b68027ff
	github.com/lightningnetwork/lnd/lnrpc/signrpc v0.9.2-beta => github.com/tierion/lnd/lnrpc/signrpc v0.9.0-beta-rc1.0.20220119230648-75c2b68027ff
	github.com/lightningnetwork/lnd/lnrpc/walletrpc v0.9.2-beta => github.com/tierion/lnd/lnrpc/walletrpc v0.9.0-beta-rc1.0.20220119230648-75c2b68027ff
	github.com/lightningnetwork/lnd/lntypes v0.9.2-beta => github.com/tierion/lnd/lntypes v0.9.0-beta-rc1.0.20220119230648-75c2b68027ff
	github.com/lightningnetwork/lnd/macaroons v0.9.2-beta => github.com/tierion/lnd/macaroons v0.9.0-beta-rc1.0.20220119230648-75c2b68027ff
)
