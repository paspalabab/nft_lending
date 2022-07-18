// Migrations are an early feature. Currently, they're nothing more than this
// single deploy script that's invoked from the CLI, injecting a provider
// configured from the workspace's Anchor.toml.

import * as anchor from '@project-serum/anchor';
import assert from "assert";
import * as bip39 from "bip39";
const { SystemProgram, PublicKey, Keypair} = anchor.web3;

let ownerA : anchor.web3.Keypair;
let ownerB : anchor.web3.Keypair;
let ownerC : anchor.web3.Keypair;
let ownerD : anchor.web3.Keypair;
let ownerF : anchor.web3.Keypair;
let newOwners : anchor.web3.PublicKey[];

module.exports = async function (provider) {
  // Configure client to use the provider.
  anchor.setProvider(provider);

  // Program for the tests.
  const program = anchor.workspace.Metaone;

  interface MultisigPDAParameters {
    multisigKey: anchor.web3.PublicKey,
    multisigBump: number,
    multisigSigner: anchor.web3.PublicKey,
    nonce: number,
  }

  const getMultisigPdaParams = async (): Promise<MultisigPDAParameters> => {

    let [multisigKey, multisigBump] = await anchor.web3.PublicKey.findProgramAddress(
      [Buffer.from("multisig")], program.programId,
    );

    let [multisigSigner, nonce] =await anchor.web3.PublicKey.findProgramAddress(
      [multisigKey.toBuffer()], program.programId
    );

    return {
        multisigKey,
        multisigBump,
        multisigSigner,
        nonce,
    }
  }   

  const getKeypairFromMnemonic = async (mnemonic: string): Promise<anchor.web3.Keypair> => {
    const seed = bip39.mnemonicToSeedSync(mnemonic, ""); // (mnemonic, password)
    const keypair = Keypair.fromSeed(seed.slice(0, 32));
    console.log(`Get Key Pair Form Mnemonic: ${keypair.publicKey.toBase58()}`); // 5ZWj7a1f8tWkjBESHKgrLmXshuXxqeY9SYcfbshpAqPG
    return keypair;
  };

  // Add your deploy script here.

  const keyOwnerA = new PublicKey("CzNxwBqNuBaCULtCn9xPCAVDLLdGpGooMSRzm9HSVuC"); 
  const keyOwnerB = new PublicKey("CjaTNy7FouzeoHZpjzfWaE5q8u1e9ve8wFk4xGCzix1J"); 
  const keyOwnerC = new PublicKey("5ufEjn6hmsfqAmdA6EEVyrYgBQbkYF8jich83FXQHerB"); 
  const keyOwnerD = new PublicKey("9XuXR2S3UaRzMWgVqvYNrpf1ieoJfUWoyZodw8CwTTiZ"); 
  const keyOwnerF = new PublicKey("9k1LfN1A6T4BvmmtpbXFRfkoJdqV5A3xy1rZ76MUdkNY"); 

  assert.ok(PublicKey.isOnCurve(keyOwnerA.toBytes()));
  assert.ok(PublicKey.isOnCurve(keyOwnerB.toBytes()));
  assert.ok(PublicKey.isOnCurve(keyOwnerC.toBytes()));
  assert.ok(PublicKey.isOnCurve(keyOwnerD.toBytes()));
  assert.ok(PublicKey.isOnCurve(keyOwnerF.toBytes()));

  const multisigSize = 200; // Big enough.    
  let owners = [keyOwnerA, keyOwnerB, keyOwnerC];
  const threshold = new anchor.BN(2);
  const multisigPda = await getMultisigPdaParams();

  await program.rpc.createMultisig(owners, threshold, multisigPda.nonce, {
    accounts: {
      multisig: multisigPda.multisigKey, 
      payer: provider.wallet.publicKey,
      systemProgram: anchor.web3.SystemProgram.programId,
    },
  });

  let multisigAccount = await program.account.multisig.fetch(multisigPda.multisigKey);
  
  assert.strictEqual(multisigAccount.nonce, multisigPda.nonce);
  assert.ok(multisigAccount.threshold.eq(new anchor.BN(2)));
  assert.deepStrictEqual(multisigAccount.owners, owners);
  assert.ok(multisigAccount.seqno === 0);

  for (let i in owners) {
    console.log(`Metaone Plat Owner${i}: ${owners[i].toBase58()}` );
  }
};
