# lightning-go

[![License](https://img.shields.io/badge/license-MIT-green)](https://opensource.org/licenses/MIT)

This golang library is used by [Chainpoint Core](https://github.com/chainpoint/chainpoint-core) to connect with a 
[Lightning Network Daemon](https://github.com/lightningnetwork/lnd) over grpc. By default Lightning, Wallet, WalletUnlocker, and 
Invoice clients are available. A number of convenience methods for working with Lightning Service Authentication Tokens and interacting
with the Bitcoin blockchain are also provided. By default this library is intended to work with Tierion Inc's [fork of lnd](https://github.com/Tierion/lnd/tree/v0.14.1-beta-tierion),
but other than exposing a block retrieval method, there is little difference from the original repository.

## Install 

This package requires Go modules.

`go get github.com/chainpoint/lightning-go`

## Usage

A basic example of declaring the library is provided below.

```go
package main

import (
    lightning "github.com/chainpoint/lightning-go"
    "encoding/json"
    "fmt"
    "time"
)

func main() {
    lndClient := lightning.LightningClient{
                        TlsPath:             "/home/ubuntu/.lnd/tls.cert",
                        MacPath:             "/home/ubuntu/.lnd/data/chain/bitcoin/mainnet/admin.macaroon",
                        ServerHostPort:      "127.0.0.1:10009",
                        LndLogLevel:         "error",
                        MinConfs:            3,
                        Testnet:             "mainnet",
                        WalletAddress:       "your_wallet_address",
                        WalletPass:          "your_wallet_password",
                        WalletSeed:          "your_wallet_seed",
                        HashPrice:           int64(2), //price to charge for issuing LSAT
                        SessionSecret:       "a mutual secret between lsat servers and clients",
                  }
     lndClient.WaitForConnection(5 * time.Minute)  //Wait until lnd is ready
     lndClient.Unlocker()                          //Unlock wallet 
     info, err := lndClient.GetInfo()              //Make a call to get lnd node info
     if err == nil {
         infoJson, _ := json.Marshal(info)
         fmt.Println(string(infoJson)) 
     }
}
```
Additionally an example of a server-side LSAT flow, RespondLSAT, is provided in `lsat.go`


