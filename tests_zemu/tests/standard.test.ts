/** ******************************************************************************
 *  (c) 2020 Zondax GmbH
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */

import Zemu, { ButtonKind, DEFAULT_START_OPTIONS, zondaxMainmenuNavigation } from '@zondax/zemu'
import StacksApp from '@zondax/ledger-stacks'
import { APP_SEED, models } from './common'
import { encode } from 'varuint-bitcoin'

import {
  AddressVersion,
  PubKeyEncoding,
  TransactionSigner,
  createStacksPrivateKey,
  createTransactionAuthField,
  isCompressed,
  makeSigHashPreSign,
  makeSTXTokenTransfer,
  makeUnsignedContractCall,
  makeUnsignedContractDeploy,
  makeUnsignedSTXTokenTransfer,
  pubKeyfromPrivKey,
  publicKeyToString,
  standardPrincipalCV,
  contractPrincipalCV,
  uintCV,
  stringAsciiCV,
  stringUtf8CV,
} from '@stacks/transactions'
import { StacksTestnet } from '@stacks/network'
import { AnchorMode } from '@stacks/transactions/src/constants'
import { bytesToHex } from '@stacks/common'

const sha512_256 = require('js-sha512').sha512_256
const sha256 = require('js-sha256').sha256
const BN = require('bn.js')
import { ec as EC } from 'elliptic'

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}

jest.setTimeout(180000)

describe('Standard', function () {
  test.concurrent.each(models)(`sign standard_contract_call_tx`, async function (m) {
    const sim = new Zemu(m.path)
    const network = new StacksTestnet()
    const senderKey = '2cefd4375fcb0b3c0935fcbc53a8cb7c7b9e0af0225581bbee006cf7b1aa0216'
    const my_key = '2e64805a5808a8a72df89b4b18d2451f8d5ab5224b4d8c7c36033aee4add3f27f'
    const path = "m/44'/5757'/0'/0/0"
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())
      // Get pubkey and check
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      console.log(pkResponse)
      expect(pkResponse.returnCode).toEqual(0x9000)
      expect(pkResponse.errorMessage).toEqual('No errors')
      const devicePublicKey = pkResponse.publicKey.toString('hex')

      const recipient = standardPrincipalCV('ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5')
      const contract_principal = contractPrincipalCV('ST39RCH114B48GY5E0K2Q4SV28XZMXW4ZZTN8QSS5', 'some-contract-name')
      const fee = new BN(10)
      const nonce = new BN(0)
      const [contract_address, contract_name] = 'SP000000000000000000002Q6VF78.pox'.split('.')
      const txOptions = {
        anchorMode: AnchorMode.Any,
        contractAddress: contract_address,
        contractName: contract_name,
        functionName: 'stack-stx',
        functionArgs: [uintCV(20000), recipient, uintCV(2), contract_principal, uintCV(10)],
        network: network,
        fee: fee,
        nonce: nonce,
        publicKey: devicePublicKey,
      }

      const transaction = await makeUnsignedContractCall(txOptions)
      const serializeTx = bytesToHex(transaction.serialize())

      const blob = Buffer.from(serializeTx, 'hex')
      const signatureRequest = app.sign(path, blob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_standard_contract_call_tx`)

      const signature = await signatureRequest
      console.log(signature)

      expect(signature.returnCode).toEqual(0x9000)

      // compute postSignHash to verify signature

      const sigHashPreSign = makeSigHashPreSign(
        transaction.signBegin(),
        // @ts-ignore
        transaction.auth.authType,
        transaction.auth.spendingCondition?.fee,
        transaction.auth.spendingCondition?.nonce,
      )
      console.log('sigHashPreSign: ', sigHashPreSign)
      const presig_hash = Buffer.from(sigHashPreSign, 'hex')

      const key_t = Buffer.alloc(1)
      key_t.writeInt8(0x00)

      const array = [presig_hash, key_t, signature.signatureVRS]
      const to_hash = Buffer.concat(array)
      const hash = sha512_256(to_hash)
      console.log('computed postSignHash: ', hash.toString('hex'))

      // compare hashes
      expect(signature.postSignHash.toString('hex')).toEqual(hash.toString('hex'))

      //Verify signature
      const ec = new EC('secp256k1')
      const signature1 = signature.signatureVRS.toString('hex')
      const signature1_obj = { r: signature1.substr(2, 64), s: signature1.substr(66, 64) }
      // @ts-ignore
      const signature1Ok = ec.verify(presig_hash, signature1_obj, devicePublicKey, 'hex')
      expect(signature1Ok).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)(`sign standard_contract_deploy_tx`, async function (m) {
    const sim = new Zemu(m.path)
    const network = new StacksTestnet()
    const path = "m/44'/5757'/0'/0/0"
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new StacksApp(sim.getTransport())
      // Get pubkey and check
      const pkResponse = await app.getAddressAndPubKey(path, AddressVersion.TestnetSingleSig)
      console.log(pkResponse)
      expect(pkResponse.returnCode).toEqual(0x9000)
      expect(pkResponse.errorMessage).toEqual('No errors')
      const devicePublicKey = pkResponse.publicKey.toString('hex')

      const fee = new BN(10)
      const nonce = new BN(0)
      const txOptions = {
        network: network,
        contractName: 'then-green-macaw',
        codeBody: `;; hello-world contract\n\n(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)\n(define-constant recipient 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)\n\n(define-fungible-token novel-token-19)\n(ft-mint? novel-token-19 u12 sender)\n(ft-transfer? novel-token-19 u2 sender recipient)\n\n(define-non-fungible-token hello-nft uint)\n\n(nft-mint? hello-nft u1 sender)\n(nft-mint? hello-nft u2 sender)\n(nft-transfer? hello-nft u1 sender recipient)\n\n(define-public (test-emit-event)\n  (begin\n    (print "Event! Hello world"\n    (ok u1)\n  )\n)\n\n(begin (test-emit-event))\n\n(define-public (test-event-types)\n  (begin\n    (unwrap-panic (ft-mint? novel-token-19 u3 recipient))\n    (unwrap-panic (nft-mint? hello-nft u2 recipient))\n    (unwrap-panic (stx-transfer? u60 tx-sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR))\n    (unwrap-panic (stx-burn? u20 tx-sender))\n    (ok u1)\n  )\n)\n\n(define-map store { key: (buff 32) } { value: (buff 32) })\n\n(define-public (get-value (key (buff 32)))\n  (begin\n    (match (map-get? store { key: key })\n      entry (ok (get value entry))\n      (err 0)\n    )\n  )\n)\n\n(define-public (set-value (key (buff 32)) (value (buff 32)))\n  (begin\n    (map-set store { key: key } { value: value })\n    (ok u1)\n  )\n)\n`,
        nonce: nonce,
        fee: fee,
        publicKey: devicePublicKey,
        anchorMode: 3,
        postConditionMode: 1,
        postConditions: [],
      }

      const transaction = await makeUnsignedContractDeploy(txOptions)
      const serializeTx = bytesToHex(transaction.serialize())

      const blob = Buffer.from(serializeTx, 'hex')
      const signatureRequest = app.sign(path, blob)

      /**
       * Prints
       * {
       *     "signatureRequest": {
       *       "returnCode": 27012,
       *       "errorMessage": "Data is invalid : Unsupported transaction payload"
       *     }
       * }
       *   **/
      console.log({ signatureRequest: await signatureRequest })

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_standard_contract_call_tx`)

      const signature = await signatureRequest
      console.log(signature)

      expect(signature.returnCode).toEqual(0x9000)

      // compute postSignHash to verify signature

      const sigHashPreSign = makeSigHashPreSign(
        transaction.signBegin(),
        // @ts-ignore
        transaction.auth.authType,
        transaction.auth.spendingCondition?.fee,
        transaction.auth.spendingCondition?.nonce,
      )
      console.log('sigHashPreSign: ', sigHashPreSign)
      const presig_hash = Buffer.from(sigHashPreSign, 'hex')

      const key_t = Buffer.alloc(1)
      key_t.writeInt8(0x00)

      const array = [presig_hash, key_t, signature.signatureVRS]
      const to_hash = Buffer.concat(array)
      const hash = sha512_256(to_hash)
      console.log('computed postSignHash: ', hash.toString('hex'))

      // compare hashes
      expect(signature.postSignHash.toString('hex')).toEqual(hash.toString('hex'))

      //Verify signature
      const ec = new EC('secp256k1')
      const signature1 = signature.signatureVRS.toString('hex')
      const signature1_obj = { r: signature1.substr(2, 64), s: signature1.substr(66, 64) }
      // @ts-ignore
      const signature1Ok = ec.verify(presig_hash, signature1_obj, devicePublicKey, 'hex')
      expect(signature1Ok).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})
