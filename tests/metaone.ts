import assert from "assert";
import * as anchor from '@project-serum/anchor';
import * as bip39 from "bip39";
import { Program } from '@project-serum/anchor';
import * as spl from '@solana/spl-token';
import { TOKEN_PROGRAM_ID, Token } from "@solana/spl-token";
const { SystemProgram, PublicKey, Keypair} = anchor.web3;
import { findProgramAddressSync } from "@project-serum/anchor/dist/cjs/utils/pubkey";
const encode = anchor.utils.bytes.utf8.encode;
import { Base64 } from 'js-base64';
import { sha256 } from "js-sha256";


interface PDAParameters {
    escrowWalletKey: anchor.web3.PublicKey,
    stateKey: anchor.web3.PublicKey,
    escrowBump: number,
    stateBump: number,
    idx: anchor.BN,
}

interface MultisigPDAParameters {
  multisigKey: anchor.web3.PublicKey,
  multisigBump: number,
  multisigSigner: anchor.web3.PublicKey,
  nonce: number,
}

interface MultisigTxPDAParameters {
  txKey: anchor.web3.PublicKey,
  txBump: number,
}

interface PoolPDAParameters {
  poolKey: anchor.web3.PublicKey,
  poolBump: number,
  walletKey: anchor.web3.PublicKey,
  walletBump: number,
}

interface RentPDAParameters {
  rentStateKey: anchor.web3.PublicKey,
  rentStateBump: number,
  escrowNftWalletKey: anchor.web3.PublicKey,
  escrowNftWalletBump: number,
  escrowRentWalletKey: anchor.web3.PublicKey,
  escrowRentWalletBump: number,
}

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function buf2hex(buffer) { // buffer is an ArrayBuffer
  return [...new Uint8Array(buffer)]
      .map(x => x.toString(16).toUpperCase().padStart(2, '0'))
      .join(' ');
}

describe('metaone', () => {

  const provider = anchor.AnchorProvider.env();

  // Configure the client to use the local cluster.
  anchor.setProvider(provider);

  // Program for the tests.
  const program = anchor.workspace.Metaone;

    let mintAddress: anchor.web3.PublicKey;
    let alice: anchor.web3.Keypair;
    let aliceWallet: anchor.web3.PublicKey;
    let bob: anchor.web3.Keypair;

    let pda: PDAParameters;

    let multisigPda: MultisigPDAParameters;
    let multisigSigner: anchor.web3.PublicKey;
    let nonce: number;

    let ownerA : anchor.web3.Keypair;
    let ownerB : anchor.web3.Keypair;
    let ownerC : anchor.web3.Keypair;
    let ownerD : anchor.web3.Keypair;
    let ownerF : anchor.web3.Keypair;
    let newOwnersHasOwnerF : anchor.web3.PublicKey[];
    let newOwners : anchor.web3.PublicKey[];
    const transaction = anchor.web3.Keypair.generate();
    const transactionBuildPool = anchor.web3.Keypair.generate();
    const transactionWithdrawCommission = anchor.web3.Keypair.generate();
    const transactionConfigRatio = anchor.web3.Keypair.generate();

    const uid = new anchor.BN(parseInt((Date.now() / 1000).toString()));
    const uidBuffer = uid.toBuffer('le', 8);

    let lender: anchor.web3.Keypair; 
    let lenderNftWallet: anchor.web3.PublicKey;
    let borrower: anchor.web3.Keypair;
    let borrowerRentWallet: anchor.web3.PublicKey;
    let mintNft: anchor.web3.PublicKey;
    let mintRent: anchor.web3.PublicKey;
    let lenderRentWallet: anchor.web3.PublicKey;
    let poolPda: PoolPDAParameters; 
    let rentPda: RentPDAParameters; 
    let platAdmin: anchor.web3.Keypair; 
    let platAdminRentWallet: anchor.web3.PublicKey;

    const rentOfferPdaSpace = 8 + 32*4 + 8*2 + 1 + 165 + 165; 

    const getPdaParams = async (connection: anchor.web3.Connection, alice: anchor.web3.PublicKey, bob: anchor.web3.PublicKey, mint: anchor.web3.PublicKey): Promise<PDAParameters> => {

        let [statePubKey, stateBump] = await anchor.web3.PublicKey.findProgramAddress(
            [Buffer.from("safe_reward_pay_state"), alice.toBuffer(), bob.toBuffer(), mint.toBuffer(), uidBuffer], program.programId,
        );
        let [walletPubKey, walletBump] = await anchor.web3.PublicKey.findProgramAddress(
            [Buffer.from("safe_reward_pay_wallet"), alice.toBuffer(), bob.toBuffer(), mint.toBuffer(), uidBuffer], program.programId,
        );
        return {
            idx: uid,
            escrowBump: walletBump,
            escrowWalletKey: walletPubKey,
            stateBump,
            stateKey: statePubKey,
        }
    }

    const getPoolPdaParams = async (connection: anchor.web3.Connection,  mintRent: anchor.web3.PublicKey): Promise<PoolPDAParameters> => {
      let [poolKey, poolBump] = await anchor.web3.PublicKey.findProgramAddress(
        [Buffer.from("commission_pool_of_plat"), mintRent.toBuffer()], program.programId,
      );

      let [walletKey, walletBump] = await anchor.web3.PublicKey.findProgramAddress(
        [Buffer.from("commission_wallet_of_plat"), mintRent.toBuffer()], program.programId,
      );

      console.log("poolKey: ",poolKey.toBase58());
      console.log("poolBump: ",poolBump);
      console.log("walletKey: ",walletKey.toBase58());
      console.log("walletBump: ",walletBump);

      return {
        poolKey,
        poolBump,
        walletKey,
        walletBump,
      }
    }    

    const getRentPdaParams = async (connection: anchor.web3.Connection,  lenderkey: anchor.web3.PublicKey,
      mintNftKey: anchor.web3.PublicKey, mintRentKey: anchor.web3.PublicKey, ): Promise<RentPDAParameters> => {

      let [rentStateKey, rentStateBump] = await anchor.web3.PublicKey.findProgramAddress(
        [Buffer.from("rent_state"), lenderkey.toBuffer(), mintNftKey.toBuffer(), mintRentKey.toBuffer(), uidBuffer], program.programId,
      );

      let [escrowNftWalletKey, escrowNftWalletBump] = await anchor.web3.PublicKey.findProgramAddress(
        [Buffer.from("escrow_wallet_of_nft"), lenderkey.toBuffer(), mintNftKey.toBuffer(), mintRentKey.toBuffer(), uidBuffer], program.programId,
      );

      let [escrowRentWalletKey, escrowRentWalletBump] = await anchor.web3.PublicKey.findProgramAddress(
        [Buffer.from("escrow_wallet_of_rents"), lenderkey.toBuffer(), mintNftKey.toBuffer(), mintRentKey.toBuffer(), uidBuffer], program.programId,
      );

      console.log("poorentStateKeylKey: ",rentStateKey.toBase58());
      console.log("rentStateBump: ",rentStateBump);
      console.log("escrowNftWalletKey: ",escrowNftWalletKey.toBase58());
      console.log("escrowNftWalletBump: ",escrowNftWalletBump);
      console.log("escrowRentWalletKey: ",escrowRentWalletKey.toBase58());
      console.log("escrowRentWalletBump: ",escrowRentWalletBump);

      return {
        rentStateKey,
        rentStateBump,
        escrowNftWalletKey,
        escrowNftWalletBump,
        escrowRentWalletKey,
        escrowRentWalletBump,
      }
    }    

    const getMultisigPdaParams = async (connection: anchor.web3.Connection): Promise<MultisigPDAParameters> => {

      let [multisigKey, multisigBump] = await anchor.web3.PublicKey.findProgramAddress(
        [Buffer.from("multisig")], program.programId,
      );

      let [multisigSigner, nonce] =await anchor.web3.PublicKey.findProgramAddress(
        [multisigKey.toBuffer()], program.programId
      );

      console.log("multisigKey: ",multisigKey.toBase58());
      console.log("multisigBump: ",multisigBump);
      console.log("multisigSigner: ",multisigSigner.toBase58());
      console.log("nonce: ",nonce);

      return {
          multisigKey,
          multisigBump,
          multisigSigner,
          nonce,
      }
    }    

    const getTxMultisigPdaParams = async (connection: anchor.web3.Connection, seqno: number): Promise<MultisigTxPDAParameters> => {

      const seqnoBn = new anchor.BN(seqno);
      const seqnoBuffer = seqnoBn.toBuffer('le', 4);

      let [txKey, txBump] = await anchor.web3.PublicKey.findProgramAddress(
        [Buffer.from("multisig_transaction"), seqnoBuffer], program.programId,
      );

      return {
          txKey,
          txBump,
      }
    }    

    const createMint = async (connection: anchor.web3.Connection, decimal?: number): Promise<anchor.web3.PublicKey> => {
        const tokenMint = new anchor.web3.Keypair();
        const lamportsForMint = await provider.connection.getMinimumBalanceForRentExemption(spl.MintLayout.span);
        let tx = new anchor.web3.Transaction();

        // Allocate mint
        tx.add(
            anchor.web3.SystemProgram.createAccount({
                programId: spl.TOKEN_PROGRAM_ID,
                space: spl.MintLayout.span,
                fromPubkey: provider.wallet.publicKey,
                newAccountPubkey: tokenMint.publicKey,
                lamports: lamportsForMint,
            })
        )
        // Allocate wallet account
        if (decimal){
          tx.add(
            spl.Token.createInitMintInstruction(
                spl.TOKEN_PROGRAM_ID,
                tokenMint.publicKey,
                decimal,
                provider.wallet.publicKey,
                provider.wallet.publicKey,
            )
          );
        }else{
          tx.add(
            spl.Token.createInitMintInstruction(
                spl.TOKEN_PROGRAM_ID,
                tokenMint.publicKey,
                6,
                provider.wallet.publicKey,
                provider.wallet.publicKey,
              )
          );      
        }
    
        const signature = await provider.sendAndConfirm(tx, [tokenMint]);

        // console.log(`[${tokenMint.publicKey}] Created new mint account at ${signature}`);
        return tokenMint.publicKey;
    }

    const createUserAndAssociatedWallet = async (connection: anchor.web3.Connection, amount: number, mint?: anchor.web3.PublicKey, userExist?:anchor.web3.Keypair,): Promise<[anchor.web3.Keypair, anchor.web3.PublicKey | undefined]> => {
        let user: anchor.web3.Keypair;
        if (userExist)
        {
          user = userExist;
        }else {
          user = new anchor.web3.Keypair();
        }
       
        let userAssociatedTokenAccount: anchor.web3.PublicKey | undefined = undefined;

        // Fund user with some SOL
        let txFund = new anchor.web3.Transaction();
        txFund.add(anchor.web3.SystemProgram.transfer({
            fromPubkey: provider.wallet.publicKey,
            toPubkey: user.publicKey,
            lamports: 500 * anchor.web3.LAMPORTS_PER_SOL,
        }));
        const sigTxFund = await provider.sendAndConfirm(txFund);
        // console.log(`[${user.publicKey.toBase58()}] Funded new account with 5 SOL: ${sigTxFund}`);

        if (mint) {
            // Create a token account for the user and mint some tokens
            userAssociatedTokenAccount = await spl.Token.getAssociatedTokenAddress(
                spl.ASSOCIATED_TOKEN_PROGRAM_ID,
                spl.TOKEN_PROGRAM_ID,
                mint,
                user.publicKey
            )

            const txFundTokenAccount = new anchor.web3.Transaction();
            txFundTokenAccount.add(spl.Token.createAssociatedTokenAccountInstruction(
                spl.ASSOCIATED_TOKEN_PROGRAM_ID,
                spl.TOKEN_PROGRAM_ID,
                mint,
                userAssociatedTokenAccount,
                user.publicKey,
                user.publicKey,
            ))
            txFundTokenAccount.add(spl.Token.createMintToInstruction(
                spl.TOKEN_PROGRAM_ID,
                mint,
                userAssociatedTokenAccount,
                provider.wallet.publicKey,
                [],
                amount,
            ));
            const txFundTokenSig = await provider.sendAndConfirm(txFundTokenAccount, [user]);
            // console.log(`[${userAssociatedTokenAccount.toBase58()}] New associated account for mint ${mint.toBase58()}: ${txFundTokenSig}`);
        }
        return [user, userAssociatedTokenAccount];
    }

    const readAccount = async (accountPublicKey: anchor.web3.PublicKey, provider: anchor.Provider): Promise<[spl.AccountInfo, string]> => {
        const tokenInfoLol = await provider.connection.getAccountInfo(accountPublicKey);
        const data = Buffer.from(tokenInfoLol.data);
        const accountInfo: spl.AccountInfo = spl.AccountLayout.decode(data);

        const amount = (accountInfo.amount as any as Buffer).readBigUInt64LE();
        return [accountInfo, amount.toString()];
    }

    const readMint = async (mintPublicKey: anchor.web3.PublicKey, provider: anchor.Provider): Promise<spl.MintInfo> => {
        const tokenInfo = await provider.connection.getAccountInfo(mintPublicKey);
        const data = Buffer.from(tokenInfo.data);
        const accountInfo = spl.MintLayout.decode(data);
        return {
            ...accountInfo,
            mintAuthority: accountInfo.mintAuthority == null ? null : anchor.web3.PublicKey.decode(accountInfo.mintAuthority),
            freezeAuthority: accountInfo.freezeAuthority == null ? null : anchor.web3.PublicKey.decode(accountInfo.freezeAuthority),
        }
    }
    const getKeypairFromMnemonic = async (mnemonic: String): Promise<anchor.web3.Keypair> => {
      const seed = bip39.mnemonicToSeedSync(mnemonic, ""); // (mnemonic, password)
      const keypair = Keypair.fromSeed(seed.slice(0, 32));
      console.log(keypair.publicKey); // 5ZWj7a1f8tWkjBESHKgrLmXshuXxqeY9SYcfbshpAqPG
      console.log(keypair.publicKey.toBase58()); 
      console.log("---------------------------------")
      return keypair;
    };

    async function stateDiscriminator(name: string): Promise<Buffer> {
      let ns = "account";
      return Buffer.from(sha256.digest(`${ns}:${name}`)).slice(0, 8);
    }

    before(async () => {

      ownerA = await getKeypairFromMnemonic("bulk spell mention blue glue gun sword swamp man grace outer position");
      ownerB = await getKeypairFromMnemonic("uniform census lemon erupt fit stone slab bounce antenna stuff tree smoke");
      ownerC = await getKeypairFromMnemonic("buddy clock damp liquid giant afford grape clarify tide brief loud shop");
      ownerD = await getKeypairFromMnemonic("bracket armed claim gold smart border blade endless motion stone wire cost");
      ownerF = await getKeypairFromMnemonic("toast uphold fringe search main bring explain cup employ photo badge vital");
      // console.log(`ownerF private key: [${ownerF.secretKey.toString()}]`);
      // console.log(buf2hex(Base64.toUint8Array("4HR5ukShT+wCAAAAAAAAAAQAAAD+AwAAAAMSRGcfhkiLv1WqIX5vBQU2FffIqanHZGEqm08hFHMrrljHE3cYHcGJr2I1BanQ0BO2+a5wuBQCiTNCxBf3MeV+yE8nOvZH8Ntir8necAz7GsmsPt1nyv3uzXJEXfwpIg")));

      newOwnersHasOwnerF = [ownerA.publicKey, ownerB.publicKey, ownerF.publicKey];
      newOwners = [ownerA.publicKey, ownerB.publicKey, ownerD.publicKey];

      console.log("discrimator of pool is: ",await stateDiscriminator("Pool"));

      const rentExemptionPaid = await provider.connection.getMinimumBalanceForRentExemption(rentOfferPdaSpace);
      console.log(`  *Cost of Lender*\n  accounts space : ${rentOfferPdaSpace} bytes\n  Sol Paid : ${rentExemptionPaid/1000000000}\n  Amount to : ${(rentExemptionPaid * 33.9 / 1000000000).toFixed(2)} USD or ${(rentExemptionPaid * 33.9 * 6.73 / 1000000000).toFixed(2)} CNY\n`);
      mintNft = await createMint(provider.connection, 0);
      mintRent = await createMint(provider.connection);
      console.log("rent mint: ", mintRent.toBase58());
      lender = ownerF;
      [lender, lenderNftWallet] = await createUserAndAssociatedWallet(provider.connection, 1, mintNft, lender);
      [, lenderRentWallet] = await createUserAndAssociatedWallet(provider.connection, 1337000000,mintRent, lender);
      [platAdmin, platAdminRentWallet] = await createUserAndAssociatedWallet(provider.connection, 1337000000,mintRent);
      [borrower, borrowerRentWallet] = await createUserAndAssociatedWallet(provider.connection, 1337000000,mintRent);

      poolPda = await getPoolPdaParams(provider.connection, mintRent);
      rentPda = await getRentPdaParams(provider.connection, lender.publicKey, mintNft, mintRent);
      multisigPda = await getMultisigPdaParams(provider.connection);

      const signature = await program.provider.connection.requestAirdrop(
        ownerA.publicKey,
        anchor.web3.LAMPORTS_PER_SOL*1000,
      );
    });

    beforeEach(async () => {

    });

    it("assert unique owner when created a multisig account", async () => {

      const multisigSize = 200; // Big enough.    
      const owners = [ownerA.publicKey, ownerB.publicKey, ownerB.publicKey];

      const threshold = new anchor.BN(2);

      try 
      {
        await program.rpc.createMultisig(owners, threshold, multisigPda.nonce, {
            accounts: {
                multisig: multisigPda.multisigKey, 
                payer: provider.wallet.publicKey,
                systemProgram: anchor.web3.SystemProgram.programId,
            },
        });
        assert.fail();
      } catch (err) {
        const error = err.error;
        assert.strictEqual(error.errorCode.number, 6008);
        assert.strictEqual(error.errorMessage, "Owners must be unique");
      }

    }); 

    it("create a multisig account", async () => {

      // console.log("multisigKey: ", multisigPda.multisigKey.toBase58());
      // console.log("multisig_bump: ",multisigPda.multisigBump)
      // console.log("multisigSigner: ", multisigPda.multisigSigner.toBase58());
      // console.log("nonce: ",multisigPda.nonce)    

      const multisigSize = 200; // Big enough.    
      const owners = [ownerA.publicKey, ownerB.publicKey, ownerC.publicKey];
  
      const threshold = new anchor.BN(2);
  
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
    });    

    it("create a multisig transaction", async () => {
  
      const pid = program.programId;
      const accounts = [
        {
          pubkey: multisigPda.multisigKey,
          isWritable: true,
          isSigner: false,
        },
        {
          pubkey: multisigPda.multisigSigner,
          isWritable: false,
          isSigner: true,
        },
      ];

      const data = program.coder.instruction.encode("set_owners", {
        owners: newOwnersHasOwnerF,
      });
  
      const multisigTxPda = await getTxMultisigPdaParams(provider.connection, 0);

      // const txSize = 1000; // Big enough, cuz I'm lazy.
      await program.rpc.createTransaction(pid, accounts, data,{
        accounts: {
          multisig: multisigPda.multisigKey,
          // transaction: transaction.publicKey,
          transaction: multisigTxPda.txKey,
          proposer: ownerA.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        },
        // instructions: [
        //   await program.account.transaction.createInstruction(
        //     transaction,
        //     txSize
        //   ),
        // ],
        // signers: [transaction, ownerA],
        signers: [ownerA],
      });
  
      const txAccount = await program.account.transaction.fetch(
        multisigTxPda.txKey,
      );
  
      assert.ok(txAccount.programId.equals(pid));
      assert.deepStrictEqual(txAccount.accounts, accounts);
      assert.deepStrictEqual(txAccount.data, data);
      assert.ok(txAccount.multisig.equals(multisigPda.multisigKey));
      assert.deepStrictEqual(txAccount.didExecute, false);
      assert.ok(txAccount.seqno === 0);

    });    

    it("multisig transaction above can be replaced before execution ", async () => {
  
      const pid = program.programId;
      const accounts = [
        {
          pubkey: multisigPda.multisigKey,
          isWritable: true,
          isSigner: false,
        },
        {
          pubkey: multisigPda.multisigSigner,
          isWritable: false,
          isSigner: true,
        },
      ];

      const data = program.coder.instruction.encode("set_owners", {
        owners: newOwners,
      });
  
      const multisigTxPda = await getTxMultisigPdaParams(provider.connection, 0);

      // const txSize = 1000; // Big enough, cuz I'm lazy.
      await program.rpc.createTransaction(pid, accounts, data,{
        accounts: {
          multisig: multisigPda.multisigKey,
          // transaction: transaction.publicKey,
          transaction: multisigTxPda.txKey,
          proposer: ownerA.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        },
        // instructions: [
        //   await program.account.transaction.createInstruction(
        //     transaction,
        //     txSize
        //   ),
        // ],
        // signers: [transaction, ownerA],
        signers: [ownerA],
      });
  
      const txAccount = await program.account.transaction.fetch(
        multisigTxPda.txKey,
      );
  
      assert.ok(txAccount.programId.equals(pid));
      assert.deepStrictEqual(txAccount.accounts, accounts);
      assert.deepStrictEqual(txAccount.data, data);
      assert.ok(txAccount.multisig.equals(multisigPda.multisigKey));
      assert.deepStrictEqual(txAccount.didExecute, false);
      assert.ok(txAccount.seqno === 0);

    });    

    it("approve and execute the multisig transaction", async () => {

      const multisigTxPda = await getTxMultisigPdaParams(provider.connection, 0);

      await program.rpc.approve({
          accounts: {
            multisig: multisigPda.multisigKey,
            transaction: multisigTxPda.txKey,
            owner: ownerB.publicKey,
          },
          signers: [ownerB],
        });

      // Now that we've reached the threshold, send the transactoin.
      await program.rpc.executeTransaction({
        accounts: {
          multisig: multisigPda.multisigKey,
          multisigSigner: multisigPda.multisigSigner,
          transaction: multisigTxPda.txKey,
          proposer: ownerA.publicKey,
        },
        remainingAccounts: program.instruction.setOwners
          .accounts({
            multisig: multisigPda.multisigKey,
            multisigSigner: multisigPda.multisigSigner,
          })
          // Change the signer status on the vendor signer since it's signed by the program, not the client.
          .map((meta) =>
            meta.pubkey.equals(multisigPda.multisigSigner)
              ? { ...meta, isSigner: false }
              : meta
          )
          .concat({
            pubkey: program.programId,
            isWritable: false,
            isSigner: false,
          }),
      });
  
      let multisigAccount = await program.account.multisig.fetch(multisigPda.multisigKey);
  
      assert.strictEqual(multisigAccount.nonce, multisigPda.nonce);
      assert.ok(multisigAccount.threshold.eq(new anchor.BN(2)));
      assert.deepStrictEqual(multisigAccount.owners, newOwners);
      assert.ok(multisigAccount.seqno === 1);

      // const txAccount = await program.account.transaction.fetch(
      //   multisigTxPda.txKey,
      // );

    });   
    
    it("multisig : propose to build rents pool", async () => {
  
      const pid = program.programId;
      const accounts = [
        {
          pubkey: multisigPda.multisigKey,
          isWritable: true,
          isSigner: false,
        },
        {
          pubkey: multisigPda.multisigSigner,
          isWritable: false,
          isSigner: true,
        },
        {
          pubkey: poolPda.poolKey,
          isWritable: true,
          isSigner: false,
        },
        {
          pubkey: poolPda.walletKey,
          isWritable: true,
          isSigner: false,
        },
        {
          pubkey: provider.wallet.publicKey,
          isWritable: true,
          isSigner: true,
        },
        {
          pubkey: mintRent,
          isWritable: false,
          isSigner: false,
        },
        {
          pubkey: anchor.web3.SystemProgram.programId,
          isWritable: false,
          isSigner: false,
        },
        {
          pubkey: spl.TOKEN_PROGRAM_ID,
          isWritable: false,
          isSigner: false,
        },
        {
          pubkey: anchor.web3.SYSVAR_RENT_PUBKEY,
          isWritable: false,
          isSigner: false,
        },
      ];
      const data = program.coder.instruction.encode("build_plat_pool", {
        numerator: new anchor.BN(3),
        denominator: new anchor.BN(100),
      });

      const multisigTxPda = await getTxMultisigPdaParams(provider.connection, 1);
      await program.rpc.createTransaction(pid, accounts, data,{
        accounts: {
          multisig: multisigPda.multisigKey,
          transaction: multisigTxPda.txKey,
          proposer: ownerA.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        },
        signers: [ownerA],
      });
  
      const txAccount = await program.account.transaction.fetch(
        multisigTxPda.txKey
      );
  
      assert.ok(txAccount.programId.equals(pid));
      assert.deepStrictEqual(txAccount.accounts, accounts);
      assert.deepStrictEqual(txAccount.data, data);
      assert.ok(txAccount.multisig.equals(multisigPda.multisigKey));
      assert.deepStrictEqual(txAccount.didExecute, false);

    });    

    it("multisig and ipc : approve and implement pool setup", async () => {

      const multisigTxPda = await getTxMultisigPdaParams(provider.connection, 1);
      await program.rpc.approve({
          accounts: {
            multisig: multisigPda.multisigKey,
            transaction: multisigTxPda.txKey,
            owner: ownerB.publicKey,
          },
          signers: [ownerB],
      });

      let listener = null;  
      let [event, slot] = await new Promise((resolve, _reject) => {
        listener = program.addEventListener("EventPoolUpdate", (event, slot) => {
          resolve([event, slot]);
        });
        program.rpc.executeTransaction({
          accounts: {
            multisig: multisigPda.multisigKey,
            multisigSigner: multisigPda.multisigSigner,
            transaction: multisigTxPda.txKey,
            proposer: ownerA.publicKey,
          },
          remainingAccounts: program.instruction.buildPlatPool
            .accounts({
              multisig: multisigPda.multisigKey,
              multisigSigner: multisigPda.multisigSigner,
              commissionPool: poolPda.poolKey,
              commissionWallet: poolPda.walletKey,
              proposer: provider.wallet.publicKey,
              mintOfTokenForPayRents: mintRent,
              systemProgram: anchor.web3.SystemProgram.programId,
              rent: anchor.web3.SYSVAR_RENT_PUBKEY,
              tokenProgram: spl.TOKEN_PROGRAM_ID,
  
            })
            // Change the signer status on the vendor signer since it's signed by the program, not the client.
            .map((meta) =>
              meta.pubkey.equals(multisigPda.multisigSigner)
                ? { ...meta, isSigner: false }
                : meta
            )
            .concat({
              pubkey: program.programId,
              isWritable: false,
              isSigner: false,
            }),
        });
      });
  
      await program.removeEventListener(listener);
  
      assert.equal(event.mint.toBase58(), mintRent.toBase58());
      assert.strictEqual(event.ratioNumerator.toNumber(), 3);
      assert.strictEqual(event.ratioDenominator.toNumber(), 100);
      assert.strictEqual(event.amountCollected.toNumber(), 0);
      assert.strictEqual(event.label, "EventBuildPlatPool");
      
      let pool = await program.account.pool.fetch(
        poolPda.poolKey,
      );
      assert.deepStrictEqual(pool.mint.toBase58(), mintRent.toBase58());
      assert.deepStrictEqual(pool.amountCollected.toNumber(), 0);
      assert.deepStrictEqual(pool.ratioNumerator.toNumber(), 3);
      assert.deepStrictEqual(pool.ratioDenominator.toNumber(), 100);
  
      let multisigAccount = await program.account.multisig.fetch(multisigPda.multisigKey);
      assert.strictEqual(multisigAccount.nonce, multisigPda.nonce);
      assert.ok(multisigAccount.threshold.eq(new anchor.BN(2)));
      assert.deepStrictEqual(multisigAccount.owners, newOwners);
      assert.ok(multisigAccount.seqno === 2);

    });    

    it("multisig : propose to change commission ratio", async () => {
  
      const pid = program.programId;
      const accounts = [
        {
          pubkey: multisigPda.multisigKey,
          isWritable: true,
          isSigner: false,
        },
        {
          pubkey: multisigPda.multisigSigner,
          isWritable: false,
          isSigner: true,
        },
        {
          pubkey: poolPda.poolKey,
          isWritable: true,
          isSigner: false,
        },
        {
          pubkey: mintRent,
          isWritable: false,
          isSigner: false,
        },
      ];

      const data = program.coder.instruction.encode("change_ratio", {
        numerator: new anchor.BN(10),
        denominator: new anchor.BN(100),
      });
  
      const multisigTxPda = await getTxMultisigPdaParams(provider.connection, 2);
      await program.rpc.createTransaction(pid, accounts, data,{
        accounts: {
          multisig: multisigPda.multisigKey,
          transaction: multisigTxPda.txKey,
          proposer: ownerA.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        },
        signers: [ownerA],
      });
  
      const txAccount = await program.account.transaction.fetch(
        multisigTxPda.txKey
      );
  
      assert.ok(txAccount.programId.equals(pid));
      assert.deepStrictEqual(txAccount.accounts, accounts);
      assert.deepStrictEqual(txAccount.data, data);
      assert.ok(txAccount.multisig.equals(multisigPda.multisigKey));
      assert.deepStrictEqual(txAccount.didExecute, false);

    });    

    it("multisig and ipc: approve and implement plat commisssion ratio adjusting proposal", async () => {

      const multisigTxPda = await getTxMultisigPdaParams(provider.connection, 2);
      await program.rpc.approve({
          accounts: {
            multisig: multisigPda.multisigKey,
            transaction: multisigTxPda.txKey,
            owner: ownerB.publicKey,
          },
          signers: [ownerB],
        });

      let listener = null;  
      let [event, slot] = await new Promise((resolve, _reject) => {
        listener = program.addEventListener("EventPoolUpdate", (event, slot) => {
          resolve([event, slot]);
        });
 
        program.rpc.executeTransaction({
          accounts: {
            multisig: multisigPda.multisigKey,
            multisigSigner: multisigPda.multisigSigner,
            transaction: multisigTxPda.txKey,
            proposer: ownerA.publicKey,
          },
          remainingAccounts: program.instruction.changeRatio
            .accounts({
              multisig: multisigPda.multisigKey,
              multisigSigner: multisigPda.multisigSigner,
              commissionPool: poolPda.poolKey,
              mintOfTokenForPayRents: mintRent,
            })
            // Change the signer status on the vendor signer since it's signed by the program, not the client.
            .map((meta) =>
              meta.pubkey.equals(multisigPda.multisigSigner)
                ? { ...meta, isSigner: false }
                : meta
            )
            .concat({
              pubkey: program.programId,
              isWritable: false,
              isSigner: false,
            }),
        });        
      });
  
      await program.removeEventListener(listener);
  
      assert.equal(event.mint.toBase58(), mintRent.toBase58());
      assert.strictEqual(event.ratioNumerator.toNumber(), 10);
      assert.strictEqual(event.ratioDenominator.toNumber(), 100);
      assert.strictEqual(event.amountCollected.toNumber(), 0);
      assert.strictEqual(event.label, "EventChangeRatio");


      let pool = await program.account.pool.fetch(
        poolPda.poolKey,
      );
      assert.deepStrictEqual(pool.amountCollected.toNumber(), 0);
      assert.deepStrictEqual(pool.ratioNumerator.toNumber(), 10);
      assert.deepStrictEqual(pool.ratioDenominator.toNumber(), 100);
      assert.deepStrictEqual(pool.mint.toBase58(), mintRent.toBase58());
     
      let multisigAccount = await program.account.multisig.fetch(multisigPda.multisigKey);
      assert.strictEqual(multisigAccount.nonce, multisigPda.nonce);
      assert.ok(multisigAccount.threshold.eq(new anchor.BN(2)));
      assert.deepStrictEqual(multisigAccount.owners, newOwners);
      assert.ok(multisigAccount.seqno === 3);

    });    

    it('offer nft for rent', async () => {
      const [, lenderBalancePre] = await readAccount(lenderNftWallet, provider);
      assert.equal(lenderBalancePre, '1');
      
      let listener = null;  
      const minDuration = 5;
      const maxDuration = 20;
      const timeUnit = 1;
      const price = 100;
      let [event, slot] = await new Promise((resolve, _reject) => {
        listener = program.addEventListener("EventRentStateUpdate", (event, slot) => {
          resolve([event, slot]);
        });
        program.rpc.rentOffer(uid, new anchor.BN(price),new anchor.BN(timeUnit),
          new anchor.BN(minDuration), new anchor.BN(maxDuration), false, rentPda.rentStateBump, {
        accounts: {
            commissionPool: poolPda.poolKey,
            commissionWallet: poolPda.walletKey,
            rentState: rentPda.rentStateKey,
            escrowWalletOfNft: rentPda.escrowNftWalletKey,
            escrowWalletOfRents: rentPda.escrowRentWalletKey,
            walletToWithdrawNftFrom: lenderNftWallet,

            lender: lender.publicKey,
            mintOfNftForLending: mintNft,
            mintOfTokenForPayRents: mintRent,

            systemProgram: anchor.web3.SystemProgram.programId,
            rent: anchor.web3.SYSVAR_RENT_PUBKEY,
            tokenProgram: spl.TOKEN_PROGRAM_ID,
        },
        signers: [lender],
      });
      });
  
      await program.removeEventListener(listener);
  
      // assert.isAbove(slot, 0);
      assert.strictEqual(event.durationMax.toNumber(), maxDuration);
      assert.strictEqual(event.durationMin.toNumber(), minDuration);
      assert.strictEqual(event.timeUnit.toNumber(), timeUnit);
      assert.strictEqual(event.pricePerTimeUnit.toNumber(), price);
      assert.strictEqual(event.extendable, false);
      assert.strictEqual(event.idx.toNumber(), uid.toNumber());
      assert.strictEqual(event.amountRents.toNumber(), 0);
      assert.strictEqual(event.stage, 1);
      assert.strictEqual(event.withdrawRents.toNumber(), 0);
      assert.strictEqual(event.depositRents.toNumber(), 0);
      assert.strictEqual(event.commissionGen.toNumber(), 0);
      assert.strictEqual(event.expireClock.toNumber(), 0);

      assert.equal(event.borrower.toBase58(), '11111111111111111111111111111111');
      assert.strictEqual(event.mintOfNftForLending.toBase58(), mintNft.toBase58());
      assert.strictEqual(event.mintOfTokenForPayRents.toBase58(), mintRent.toBase58());
      assert.strictEqual(event.lender.toBase58(), lender.publicKey.toBase58());
      assert.strictEqual(event.escrowWalletOfNft.toBase58(), rentPda.escrowNftWalletKey.toBase58());
      assert.strictEqual(event.escrowWalletOfRents.toBase58(), rentPda.escrowRentWalletKey.toBase58());
      assert.strictEqual(event.label, "EventRentOffer");

      const [,accBalance] = await readAccount(rentPda.escrowNftWalletKey, provider);
      assert.equal(accBalance, '1');
      const [, lenderBalancePost] = await readAccount(lenderNftWallet, provider);
      assert.equal(lenderBalancePost, '0');

      const state = await program.account.rentState.fetch(
        rentPda.rentStateKey
      );
      assert.equal(state.timeUnit.toString(), timeUnit.toString());
      assert.equal(state.pricePerTimeUnit.toString(), price.toString());
      assert.equal(state.durationMax.toString(), maxDuration.toString());
      assert.equal(state.durationMin.toString(), minDuration.toString());
      assert.equal(state.extendable.toString(), 'false');

      let pool = await program.account.pool.fetch(
        poolPda.poolKey,
      );
      assert.deepStrictEqual(pool.amountCollected.toNumber(), 0);
      assert.deepStrictEqual(pool.ratioNumerator.toNumber(), 10);
      assert.deepStrictEqual(pool.ratioDenominator.toNumber(), 100);
      assert.deepStrictEqual(pool.mint.toBase58(), mintRent.toBase58());
    })  
    
    it('modify nft for rent', async () => {
      
      let listener = null;  
      let [event, slot] = await new Promise((resolve, _reject) => {
        listener = program.addEventListener("EventRentStateUpdate", (event, slot) => {
          resolve([event, slot]);
        });
        program.rpc.rentChangeOffer(uid,new anchor.BN(200),new anchor.BN(1),
        new anchor.BN(10), new anchor.BN(40), false, {
          accounts: {
              rentState: rentPda.rentStateKey,
              lender: lender.publicKey,
              mintOfNftForLending: mintNft,
              mintOfTokenForPayRents: mintRent,
              systemProgram: anchor.web3.SystemProgram.programId,
              clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
          },
          signers: [lender],
        });
      });
  
      await program.removeEventListener(listener);
  
      // assert.isAbove(slot, 0);
      assert.strictEqual(event.durationMax.toNumber(), 40);
      assert.strictEqual(event.durationMin.toNumber(), 10);
      assert.strictEqual(event.timeUnit.toNumber(), 1);
      assert.strictEqual(event.pricePerTimeUnit.toNumber(), 200);
      assert.strictEqual(event.extendable, false);
      assert.strictEqual(event.idx.toNumber(), uid.toNumber());
      assert.strictEqual(event.amountRents.toNumber(), 0);
      assert.strictEqual(event.stage, 1);
      assert.strictEqual(event.withdrawRents.toNumber(), 0);
      assert.strictEqual(event.depositRents.toNumber(), 0);
      assert.strictEqual(event.commissionGen.toNumber(), 0);
      assert.strictEqual(event.expireClock.toNumber(), 0);

      assert.equal(event.borrower.toBase58(), '11111111111111111111111111111111');
      assert.strictEqual(event.mintOfNftForLending.toBase58(), mintNft.toBase58());
      assert.strictEqual(event.mintOfTokenForPayRents.toBase58(), mintRent.toBase58());
      assert.strictEqual(event.lender.toBase58(), lender.publicKey.toBase58());
      assert.strictEqual(event.escrowWalletOfNft.toBase58(), rentPda.escrowNftWalletKey.toBase58());
      assert.strictEqual(event.escrowWalletOfRents.toBase58(), rentPda.escrowRentWalletKey.toBase58());
      assert.strictEqual(event.label, "EventChangeOffer");

      const state = await program.account.rentState.fetch(
        rentPda.rentStateKey
      );

      assert.equal(state.timeUnit.toString(), '1');
      assert.equal(state.pricePerTimeUnit.toString(), '200');
      assert.equal(state.durationMax.toString(), '40');
      assert.equal(state.durationMin.toString(), '10');
      assert.equal(state.extendable.toString(), 'false');
      // console.log("state.mintOfNftForLending: ", state.mintOfNftForLending.toBase58());
      // console.log("mintNft: ", mintNft.toBase58());
      assert.ok(state.mintOfNftForLending.equals(mintNft));
      assert.ok(state.mintOfTokenForPayRents.equals(mintRent));

      let pool = await program.account.pool.fetch(
        poolPda.poolKey,
      );
      assert.deepStrictEqual(pool.amountCollected.toNumber(), 0);
      assert.deepStrictEqual(pool.ratioNumerator.toNumber(), 10);
      assert.deepStrictEqual(pool.ratioDenominator.toNumber(), 100);
      assert.deepStrictEqual(pool.mint.toBase58(), mintRent.toBase58());

    })    

    it('rent deal', async () => {
      const [, borrowBalancePre] = await readAccount(borrowerRentWallet, provider);
      assert.equal(borrowBalancePre, '1337000000');

      let listener = null;  
      let [event, slot] = await new Promise((resolve, _reject) => {
        listener = program.addEventListener("EventRentStateUpdate", (event, slot) => {
          resolve([event, slot]);
        });
        program.rpc.rentDeal(uid, new anchor.BN(10), 
        rentPda.rentStateBump, poolPda.walletBump, 
          {
            accounts: {
              commissionPool: poolPda.poolKey,
              commissionWallet: poolPda.walletKey,
              rentState: rentPda.rentStateKey,
              escrowWalletOfRents: rentPda.escrowRentWalletKey,
              walletToWithdrawRentsFrom: borrowerRentWallet,

              borrower: borrower.publicKey,
              lender: lender.publicKey,
              mintOfNftForLending: mintNft,
              mintOfTokenForPayRents: mintRent,

              systemProgram: anchor.web3.SystemProgram.programId,
              rent: anchor.web3.SYSVAR_RENT_PUBKEY,
              tokenProgram: spl.TOKEN_PROGRAM_ID,
              clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
            },
            signers: [borrower],
          });
      });
  
      await program.removeEventListener(listener);
  
      // assert.isAbove(slot, 0);
      assert.strictEqual(event.durationMax.toNumber(), 40);
      assert.strictEqual(event.durationMin.toNumber(), 10);
      assert.strictEqual(event.timeUnit.toNumber(), 1);
      assert.strictEqual(event.pricePerTimeUnit.toNumber(), 200);
      assert.strictEqual(event.extendable, false);
      assert.strictEqual(event.idx.toNumber(), uid.toNumber());
      assert.strictEqual(event.amountRents.toNumber(), 1800);
      assert.strictEqual(event.stage, 3);
      assert.strictEqual(event.withdrawRents.toNumber(), 0);
      assert.strictEqual(event.depositRents.toNumber(), 1800);
      assert.strictEqual(event.commissionGen.toNumber(), 200);
      // console.log("expireClock: ",event.expireClock.toNumber());
      // assert.strictEqual(event.expireClock.toNumber(), 0);

      assert.equal(event.borrower.toBase58(), borrower.publicKey.toBase58());
      assert.strictEqual(event.mintOfNftForLending.toBase58(), mintNft.toBase58());
      assert.strictEqual(event.mintOfTokenForPayRents.toBase58(), mintRent.toBase58());
      assert.strictEqual(event.lender.toBase58(), lender.publicKey.toBase58());
      assert.strictEqual(event.escrowWalletOfNft.toBase58(), rentPda.escrowNftWalletKey.toBase58());
      assert.strictEqual(event.escrowWalletOfRents.toBase58(), rentPda.escrowRentWalletKey.toBase58());
      assert.strictEqual(event.label, "EventDealOffer");


      const [,accBalance] = await readAccount(rentPda.escrowRentWalletKey, provider);
      assert.equal(accBalance, '1800');
      const [,accBalancePool] = await readAccount(poolPda.walletKey, provider);
      assert.equal(accBalancePool, '200');
      const [, borrowerBalancePost] = await readAccount(borrowerRentWallet, provider);
      assert.equal(borrowerBalancePost, '1336998000');

      let pool = await program.account.pool.fetch(
        poolPda.poolKey,
      );
      assert.deepStrictEqual(pool.amountCollected.toNumber(), 200);
      assert.deepStrictEqual(pool.ratioNumerator.toNumber(), 10);
      assert.deepStrictEqual(pool.ratioDenominator.toNumber(), 100);
      // assert.deepStrictEqual(pool.mint.toBase58(), mintRent.toBase58());


      let rentState = await program.account.rentState.fetch(
        rentPda.rentStateKey,
      );
      assert.deepStrictEqual(rentState.amountRents.toNumber(), 1800);
    })   

    it('close rent offer for first time', async () => {
      const [, lenderBalancePre] = await readAccount(lenderNftWallet, provider);
      assert.equal(lenderBalancePre, '0');
      

      try {
         await program.rpc.rentClose(uid, rentPda.rentStateBump, {
          accounts: {
              rentState: rentPda.rentStateKey,
              escrowWalletOfNft: rentPda.escrowNftWalletKey,
              escrowWalletOfRents: rentPda.escrowRentWalletKey,
              refundWalletOfNftForLending: lenderNftWallet,
  
              lender: lender.publicKey,
              mintOfNftForLending: mintNft,
              mintOfTokenForPayRents: mintRent,
  
              systemProgram: anchor.web3.SystemProgram.programId,
              rent: anchor.web3.SYSVAR_RENT_PUBKEY,
              tokenProgram: spl.TOKEN_PROGRAM_ID,
              clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
          },
          signers: [lender],
        });
        assert.fail();
      } catch (err) {
        const error = err.error;
        assert.strictEqual(error.errorCode.number, 6017);
        assert.strictEqual(error.errorMessage, "Rents left uncollected before trying to close escrow account");
      } 

    })    

    it('collect rents', async () => {
      const [, borrowBalancePre] = await readAccount(lenderRentWallet, provider);
      assert.equal(borrowBalancePre, '1337000000');
      
      let listener = null;  
      let [event, slot] = await new Promise((resolve, _reject) => {
        listener = program.addEventListener("EventRentStateUpdate", (event, slot) => {
          resolve([event, slot]);
        });
          program.rpc.rentCollect(uid, new anchor.BN(1800), rentPda.rentStateBump, {
            accounts: {
                rentState: rentPda.rentStateKey,
                escrowWalletOfRents: rentPda.escrowRentWalletKey,
                walletToCollectRents: lenderRentWallet,
    
                lender: lender.publicKey,
                mintOfNftForLending: mintNft,
                mintOfTokenForPayRents: mintRent,
    
                systemProgram: anchor.web3.SystemProgram.programId,
                rent: anchor.web3.SYSVAR_RENT_PUBKEY,
                associatedTokenProgram: spl.ASSOCIATED_TOKEN_PROGRAM_ID,
                tokenProgram: spl.TOKEN_PROGRAM_ID,
            },
            signers: [lender],
          });
      });
  
      await program.removeEventListener(listener);
  
      // assert.isAbove(slot, 0);
      assert.strictEqual(event.durationMax.toNumber(), 40);
      assert.strictEqual(event.durationMin.toNumber(), 10);
      assert.strictEqual(event.timeUnit.toNumber(), 1);
      assert.strictEqual(event.pricePerTimeUnit.toNumber(), 200);
      assert.strictEqual(event.extendable, false);
      assert.strictEqual(event.idx.toNumber(), uid.toNumber());
      assert.strictEqual(event.amountRents.toNumber(), 0);
      assert.strictEqual(event.stage, 3);
      assert.strictEqual(event.withdrawRents.toNumber(), 1800);
      assert.strictEqual(event.depositRents.toNumber(), 0);
      assert.strictEqual(event.commissionGen.toNumber(), 0);
      // console.log("expireClock: ",event.expireClock.toNumber());
      // assert.strictEqual(event.expireClock.toNumber(), 0);

      assert.equal(event.borrower.toBase58(), borrower.publicKey.toBase58());
      assert.strictEqual(event.mintOfNftForLending.toBase58(), mintNft.toBase58());
      assert.strictEqual(event.mintOfTokenForPayRents.toBase58(), mintRent.toBase58());
      assert.strictEqual(event.lender.toBase58(), lender.publicKey.toBase58());
      assert.strictEqual(event.escrowWalletOfNft.toBase58(), rentPda.escrowNftWalletKey.toBase58());
      assert.strictEqual(event.escrowWalletOfRents.toBase58(), rentPda.escrowRentWalletKey.toBase58());
      assert.strictEqual(event.label, "EventCollectRents");

      const [,accBalance] = await readAccount(rentPda.escrowRentWalletKey, provider);
      assert.equal(accBalance, '0');
      const [, borrowerBalancePost] = await readAccount(lenderRentWallet, provider);
      assert.equal(borrowerBalancePost, '1337001800');

      let rentState = await program.account.rentState.fetch(
        rentPda.rentStateKey,
      );
      assert.deepStrictEqual(rentState.amountRents.toNumber(), 0);

    })   

    it('close rent offer for second time', async () => {
      const [, lenderBalancePre] = await readAccount(lenderNftWallet, provider);
      assert.equal(lenderBalancePre, '0');
      console.log("\twait about 10 secondes for rent deal overdue...");
      await sleep(12000);

      let listener = null;  
      let [event, slot] = await new Promise((resolve, _reject) => {
        listener = program.addEventListener("EventRentStateUpdate", (event, slot) => {
          resolve([event, slot]);
        });
          program.rpc.rentClose(uid, rentPda.rentStateBump, {
            accounts: {
                rentState: rentPda.rentStateKey,
                escrowWalletOfNft: rentPda.escrowNftWalletKey,
                escrowWalletOfRents: rentPda.escrowRentWalletKey,
                refundWalletOfNftForLending: lenderNftWallet,
    
                lender: lender.publicKey,
                mintOfNftForLending: mintNft,
                mintOfTokenForPayRents: mintRent,
    
                systemProgram: anchor.web3.SystemProgram.programId,
                rent: anchor.web3.SYSVAR_RENT_PUBKEY,
                tokenProgram: spl.TOKEN_PROGRAM_ID,
                clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
            },
            signers: [lender],
          });
      });
  
      await program.removeEventListener(listener);
  
      // assert.isAbove(slot, 0);
      assert.strictEqual(event.durationMax.toNumber(), 40);
      assert.strictEqual(event.durationMin.toNumber(), 10);
      assert.strictEqual(event.timeUnit.toNumber(), 1);
      assert.strictEqual(event.pricePerTimeUnit.toNumber(), 200);
      assert.strictEqual(event.extendable, false);
      assert.strictEqual(event.idx.toNumber(), uid.toNumber());
      assert.strictEqual(event.amountRents.toNumber(), 0);
      assert.strictEqual(event.stage, 2);
      assert.strictEqual(event.withdrawRents.toNumber(), 0);
      assert.strictEqual(event.depositRents.toNumber(), 0);
      assert.strictEqual(event.commissionGen.toNumber(), 0);
      // console.log("expireClock: ",event.expireClock.toNumber());
      // assert.strictEqual(event.expireClock.toNumber(), 0);

      assert.equal(event.borrower.toBase58(), borrower.publicKey.toBase58());
      assert.strictEqual(event.mintOfNftForLending.toBase58(), mintNft.toBase58());
      assert.strictEqual(event.mintOfTokenForPayRents.toBase58(), mintRent.toBase58());
      assert.strictEqual(event.lender.toBase58(), lender.publicKey.toBase58());
      assert.strictEqual(event.escrowWalletOfNft.toBase58(), rentPda.escrowNftWalletKey.toBase58());
      assert.strictEqual(event.escrowWalletOfRents.toBase58(), rentPda.escrowRentWalletKey.toBase58());
      assert.strictEqual(event.label, "EventOfferClose");
      
      const [, lenderBalancePost] = await readAccount(lenderNftWallet, provider);
      assert.equal(lenderBalancePost, '1');

    })    

    it("multisig : propose to withdraw commission", async () => {
  
      const pid = program.programId;
      const accounts = [
        {
          pubkey: multisigPda.multisigKey,
          isWritable: true,
          isSigner: false,
        },
        {
          pubkey: multisigPda.multisigSigner,
          isWritable: false,
          isSigner: true,
        },
        {
          pubkey: poolPda.poolKey,
          isWritable: true,
          isSigner: false,
        },
        {
          pubkey: poolPda.walletKey,
          isWritable: true,
          isSigner: false,
        },
        {
          pubkey: platAdminRentWallet,
          isWritable: true,
          isSigner: false,
        },
        {
          pubkey: platAdmin.publicKey,
          isWritable: false,
          isSigner: false,
        },
        // {
        //   pubkey: provider.wallet.publicKey,
        //   isWritable: true,
        //   isSigner: true,
        // },
        {
          pubkey: mintRent,
          isWritable: false,
          isSigner: false,
        },
        {
          pubkey: anchor.web3.SystemProgram.programId,
          isWritable: false,
          isSigner: false,
        },
        {
          pubkey: spl.TOKEN_PROGRAM_ID,
          isWritable: false,
          isSigner: false,
        },
        {
          pubkey: spl.ASSOCIATED_TOKEN_PROGRAM_ID,
          isWritable: false,
          isSigner: false,
        },
        {
          pubkey: anchor.web3.SYSVAR_RENT_PUBKEY,
          isWritable: false,
          isSigner: false,
        },
      ];

      const data = program.coder.instruction.encode("withdraw_commissions", {
        rentamount: new anchor.BN(200),
        poolbump: poolPda.poolBump,
      });
  
      const multisigTxPda = await getTxMultisigPdaParams(provider.connection, 3);
      await program.rpc.createTransaction(pid, accounts, data,{
        accounts: {
          multisig: multisigPda.multisigKey,
          transaction: multisigTxPda.txKey,
          proposer: ownerA.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        },
        signers: [ownerA],
      });
  
      const txAccount = await program.account.transaction.fetch(
        multisigTxPda.txKey,
      );
  
      assert.ok(txAccount.programId.equals(pid));
      assert.deepStrictEqual(txAccount.accounts, accounts);
      assert.deepStrictEqual(txAccount.data, data);
      assert.ok(txAccount.multisig.equals(multisigPda.multisigKey));
      assert.deepStrictEqual(txAccount.didExecute, false);

    });    

    it("multisig and ipc : approve and implement commission withdrawl", async () => {

      const multisigTxPda = await getTxMultisigPdaParams(provider.connection, 3);
      await program.rpc.approve({
          accounts: {
            multisig: multisigPda.multisigKey,
            transaction: multisigTxPda.txKey,
            owner: ownerB.publicKey,
          },
          signers: [ownerB],
        });

      const [, BalancePre] = await readAccount(platAdminRentWallet, provider);
      assert.equal(BalancePre, '1337000000');
      const [, poolBalancePre] = await readAccount(poolPda.walletKey, provider);
      assert.equal(poolBalancePre, '200');

      let listener = null;  
      let [event, slot] = await new Promise((resolve, _reject) => {
        listener = program.addEventListener("EventPoolUpdate", (event, slot) => {
          resolve([event, slot]);
        });
        program.rpc.executeTransaction({
          accounts: {
            multisig: multisigPda.multisigKey,
            multisigSigner: multisigPda.multisigSigner,
            transaction: multisigTxPda.txKey,
            proposer: ownerA.publicKey,
          },
          remainingAccounts: program.instruction.withdrawCommissions
            .accounts({
              multisig: multisigPda.multisigKey,
              multisigSigner: multisigPda.multisigSigner,
  
              commissionPool: poolPda.poolKey,
              commissionWallet: poolPda.walletKey,
              walletToCollectCommission: platAdminRentWallet,
              dest: platAdmin.publicKey,
              // payer: provider.wallet.publicKey,
              mintOfTokenForPayRents: mintRent,
  
              systemProgram: anchor.web3.SystemProgram.programId,
              rent: anchor.web3.SYSVAR_RENT_PUBKEY,
              associatedTokenProgram: spl.ASSOCIATED_TOKEN_PROGRAM_ID,
              tokenProgram: spl.TOKEN_PROGRAM_ID,
  
            })
            // Change the signer status on the vendor signer since it's signed by the program, not the client.
            .map((meta) =>
              meta.pubkey.equals(multisigPda.multisigSigner)
                ? { ...meta, isSigner: false }
                : meta
            )
            .concat({
              pubkey: program.programId,
              isWritable: false,
              isSigner: false,
            }),
        });
        
      });
  
      await program.removeEventListener(listener);
  
      assert.equal(event.mint.toBase58(), mintRent.toBase58());
      assert.strictEqual(event.ratioNumerator.toNumber(), 10);
      assert.strictEqual(event.ratioDenominator.toNumber(), 100);
      // console.log("event.amountCollected: ", event.amountCollected);
      // assert.strictEqual(event.amountCollected.toNumber(), 0);
      assert.strictEqual(event.withdrawCommissions.toNumber(), 200);
      assert.strictEqual(event.label, "EventWithDrawCommissions");
  
      let multisigAccount = await program.account.multisig.fetch(multisigPda.multisigKey);
  
      assert.strictEqual(multisigAccount.nonce, multisigPda.nonce);
      assert.ok(multisigAccount.threshold.eq(new anchor.BN(2)));
      assert.deepStrictEqual(multisigAccount.owners, newOwners);
      assert.ok(multisigAccount.seqno === 4);

      const [, poolBalancePost] = await readAccount(poolPda.walletKey, provider);
      assert.equal(poolBalancePost, '0');
      const [, BalancePost] = await readAccount(platAdminRentWallet, provider);
      assert.equal(BalancePost, '1337000200');

    });    

    it('can initialize a safe payment by Alice', async () => {
      mintAddress = await createMint(provider.connection);
      [alice, aliceWallet] = await createUserAndAssociatedWallet(provider.connection, 1337000000,mintAddress);
      let _rest;
      [bob, ..._rest] = await createUserAndAssociatedWallet(provider.connection, 1337000000,);
      pda = await getPdaParams(provider.connection, alice.publicKey, bob.publicKey, mintAddress);

      const [, aliceBalancePre] = await readAccount(aliceWallet, provider);
      assert.equal(aliceBalancePre, '1337000000');

      const amount = new anchor.BN(20000000);

      // console.log(`Initialized a new Safe Pay instance. Alice will pay bob 20 tokens`);

      let listener = null;  
      let [event, slot] = await new Promise((resolve, _reject) => {
        listener = program.addEventListener("EventSafePay", (event, slot) => {
          resolve([event, slot]);
        });
     
          program.rpc.initializeNewGrant(pda.idx, new anchor.BN(0), pda.stateBump, pda.escrowBump, amount, {
            accounts: {
              safePayState: pda.stateKey,
                escrowWalletState: pda.escrowWalletKey,
                mintOfTokenBeingSent: mintAddress,
                userSending: alice.publicKey,
                userReceiving: bob.publicKey,
                walletToWithdrawFrom: aliceWallet,

                systemProgram: anchor.web3.SystemProgram.programId,
                rent: anchor.web3.SYSVAR_RENT_PUBKEY,
                clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
                tokenProgram: spl.TOKEN_PROGRAM_ID,
            },
            signers: [alice],
        });
        
      });
  
      await program.removeEventListener(listener);
  
      assert.strictEqual(event.label, "EventInitializeNewGrant");

      // Assert that 20 tokens were moved from Alice's account to the escrow.
      const [, aliceBalancePost] = await readAccount(aliceWallet, provider);
      assert.equal(aliceBalancePost, '1317000000');
      const [, escrowBalancePost] = await readAccount(pda.escrowWalletKey, provider);
      assert.equal(escrowBalancePost, '20000000');

      const state = await program.account.safePayState.fetch(pda.stateKey);
      assert.equal(state.amountTokens.toString(), '20000000');
      assert.equal(state.stage.toString(), '1');
    })

    it('can send escrow funds to Bob without timelimit', async () => {
      mintAddress = await createMint(provider.connection);
      [alice, aliceWallet] = await createUserAndAssociatedWallet(provider.connection,1337000000, mintAddress);
      let _rest;
      [bob, ..._rest] = await createUserAndAssociatedWallet(provider.connection, 1337000000,);
      pda = await getPdaParams(provider.connection, alice.publicKey, bob.publicKey, mintAddress);

      const [, aliceBalancePre] = await readAccount(aliceWallet, provider);
      assert.equal(aliceBalancePre, '1337000000');

      const amount = new anchor.BN(20000000);

      // console.log(`Initialized a new Safe Pay instance. Alice will pay bob 20 tokens`);
      let listener = null;  
      let [event, slot] = await new Promise((resolve, _reject) => {
        listener = program.addEventListener("EventSafePay", (event, slot) => {
          resolve([event, slot]);
        });
     
        program.rpc.initializeNewGrant(pda.idx, new anchor.BN(0), pda.stateBump, pda.escrowBump, amount, {
          accounts: {
              safePayState: pda.stateKey,
              escrowWalletState: pda.escrowWalletKey,
              mintOfTokenBeingSent: mintAddress,
              userSending: alice.publicKey,
              userReceiving: bob.publicKey,
              walletToWithdrawFrom: aliceWallet,

              systemProgram: anchor.web3.SystemProgram.programId,
              rent: anchor.web3.SYSVAR_RENT_PUBKEY,
              clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
              tokenProgram: spl.TOKEN_PROGRAM_ID,
          },
          signers: [alice],
      });
        
      });
  
      await program.removeEventListener(listener);
  
      assert.strictEqual(event.label, "EventInitializeNewGrant");

      // Assert that 20 tokens were moved from Alice's account to the escrow.
      const [, aliceBalancePost] = await readAccount(aliceWallet, provider);
      assert.equal(aliceBalancePost, '1317000000');
      const [, escrowBalancePost] = await readAccount(pda.escrowWalletKey, provider);
      assert.equal(escrowBalancePost, '20000000');

      // Create a token account for Bob.
      const bobTokenAccount = await spl.Token.getAssociatedTokenAddress(
          spl.ASSOCIATED_TOKEN_PROGRAM_ID,
          spl.TOKEN_PROGRAM_ID,
          mintAddress,
          bob.publicKey
      )

      let listener1 = null;  
      let [event1, slot1] = await new Promise((resolve, _reject) => {
        listener1 = program.addEventListener("EventSafePay", (event, slot) => {
          resolve([event, slot]);
        });
        program.rpc.completeGrant(pda.idx, pda.stateBump, pda.escrowBump, {
          accounts: {
              safePayState: pda.stateKey,
              escrowWalletState: pda.escrowWalletKey,
              mintOfTokenBeingSent: mintAddress,
              userSending: alice.publicKey,
              userReceiving: bob.publicKey,
              walletToDepositTo: bobTokenAccount,

              systemProgram: anchor.web3.SystemProgram.programId,
              rent: anchor.web3.SYSVAR_RENT_PUBKEY,
              tokenProgram: spl.TOKEN_PROGRAM_ID,
              clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
              associatedTokenProgram: spl.ASSOCIATED_TOKEN_PROGRAM_ID,
          },
          signers: [bob],
        });
        
      });

      // Assert that 20 tokens were sent back.
      const [, bobBalance] = await readAccount(bobTokenAccount, provider);
      assert.equal(bobBalance, '20000000');

      // // Assert that escrow was correctly closed.
      try {
          await readAccount(pda.escrowWalletKey, provider);
          return assert.fail("Account should be closed");
      } catch (e) {
          assert.equal(e.message, "Cannot read properties of null (reading 'data')");
      }
    })


    it('can send escrow funds to Bob within timelimit', async () => {
      mintAddress = await createMint(provider.connection);
      [alice, aliceWallet] = await createUserAndAssociatedWallet(provider.connection,1337000000, mintAddress);
      let _rest;
      [bob, ..._rest] = await createUserAndAssociatedWallet(provider.connection, 1337000000,);
      pda = await getPdaParams(provider.connection, alice.publicKey, bob.publicKey, mintAddress);

      const [, aliceBalancePre] = await readAccount(aliceWallet, provider);
      assert.equal(aliceBalancePre, '1337000000');

      const amount = new anchor.BN(20000000);

      // console.log(`Initialized a new Safe Pay instance. Alice will pay bob 20 tokens`);
      let listener = null;  
      let [event, slot] = await new Promise((resolve, _reject) => {
        listener = program.addEventListener("EventSafePay", (event, slot) => {
          resolve([event, slot]);
        });
     
        program.rpc.initializeNewGrant(pda.idx, new anchor.BN(100), pda.stateBump, pda.escrowBump, amount, {
          accounts: {
              safePayState: pda.stateKey,
              escrowWalletState: pda.escrowWalletKey,
              mintOfTokenBeingSent: mintAddress,
              userSending: alice.publicKey,
              userReceiving: bob.publicKey,
              walletToWithdrawFrom: aliceWallet,

              systemProgram: anchor.web3.SystemProgram.programId,
              rent: anchor.web3.SYSVAR_RENT_PUBKEY,
              clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
              tokenProgram: spl.TOKEN_PROGRAM_ID,
          },
          signers: [alice],
      });
        
      });
  
      await program.removeEventListener(listener);
  
      assert.strictEqual(event.label, "EventInitializeNewGrant");

      // Assert that 20 tokens were moved from Alice's account to the escrow.
      const [, aliceBalancePost] = await readAccount(aliceWallet, provider);
      assert.equal(aliceBalancePost, '1317000000');
      const [, escrowBalancePost] = await readAccount(pda.escrowWalletKey, provider);
      assert.equal(escrowBalancePost, '20000000');

      // Create a token account for Bob.
      const bobTokenAccount = await spl.Token.getAssociatedTokenAddress(
          spl.ASSOCIATED_TOKEN_PROGRAM_ID,
          spl.TOKEN_PROGRAM_ID,
          mintAddress,
          bob.publicKey
      )

      let listener1 = null;  
      let [event1, slot1] = await new Promise((resolve, _reject) => {
        listener1 = program.addEventListener("EventSafePay", (event, slot) => {
          resolve([event, slot]);
        });
        program.rpc.completeGrant(pda.idx, pda.stateBump, pda.escrowBump, {
          accounts: {
              safePayState: pda.stateKey,
              escrowWalletState: pda.escrowWalletKey,
              mintOfTokenBeingSent: mintAddress,
              userSending: alice.publicKey,
              userReceiving: bob.publicKey,
              walletToDepositTo: bobTokenAccount,

              systemProgram: anchor.web3.SystemProgram.programId,
              rent: anchor.web3.SYSVAR_RENT_PUBKEY,
              tokenProgram: spl.TOKEN_PROGRAM_ID,
              clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
              associatedTokenProgram: spl.ASSOCIATED_TOKEN_PROGRAM_ID,
          },
          signers: [bob],
        });
        
      });

      // Assert that 20 tokens were sent back.
      const [, bobBalance] = await readAccount(bobTokenAccount, provider);
      assert.equal(bobBalance, '20000000');

      // // Assert that escrow was correctly closed.
      try {
          await readAccount(pda.escrowWalletKey, provider);
          return assert.fail("Account should be closed");
      } catch (e) {
          assert.equal(e.message, "Cannot read properties of null (reading 'data')");
      }
    })


    it('Bob is failed to claim the fund because of passing over the time limit', async () => {
      mintAddress = await createMint(provider.connection);
      [alice, aliceWallet] = await createUserAndAssociatedWallet(provider.connection,1337000000, mintAddress);
      let _rest;
      [bob, ..._rest] = await createUserAndAssociatedWallet(provider.connection, 1337000000,);
      pda = await getPdaParams(provider.connection, alice.publicKey, bob.publicKey, mintAddress);

      const [, aliceBalancePre] = await readAccount(aliceWallet, provider);
      assert.equal(aliceBalancePre, '1337000000');

      const amount = new anchor.BN(20000000);

      // console.log(`Initialized a new Safe Pay instance. Alice will pay bob 20 tokens`);
      let listener = null;  
      let [event, slot] = await new Promise((resolve, _reject) => {
        listener = program.addEventListener("EventSafePay", (event, slot) => {
          resolve([event, slot]);
        });
     
        program.rpc.initializeNewGrant(pda.idx, new anchor.BN(1), pda.stateBump, pda.escrowBump, amount, {
          accounts: {
              safePayState: pda.stateKey,
              escrowWalletState: pda.escrowWalletKey,
              mintOfTokenBeingSent: mintAddress,
              userSending: alice.publicKey,
              userReceiving: bob.publicKey,
              walletToWithdrawFrom: aliceWallet,

              systemProgram: anchor.web3.SystemProgram.programId,
              rent: anchor.web3.SYSVAR_RENT_PUBKEY,
              clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
              tokenProgram: spl.TOKEN_PROGRAM_ID,
          },
          signers: [alice],
      });
        
      });
  
      await program.removeEventListener(listener);
  
      assert.strictEqual(event.label, "EventInitializeNewGrant");

      // Assert that 20 tokens were moved from Alice's account to the escrow.
      const [, aliceBalancePost] = await readAccount(aliceWallet, provider);
      assert.equal(aliceBalancePost, '1317000000');
      const [, escrowBalancePost] = await readAccount(pda.escrowWalletKey, provider);
      assert.equal(escrowBalancePost, '20000000');

      // Create a token account for Bob.
      const bobTokenAccount = await spl.Token.getAssociatedTokenAddress(
          spl.ASSOCIATED_TOKEN_PROGRAM_ID,
          spl.TOKEN_PROGRAM_ID,
          mintAddress,
          bob.publicKey
      )

      await sleep(2000);
      console.log("\twait about 2 seconds for overpass of timelimit...");

      try 
      {
        await program.rpc.completeGrant(pda.idx, pda.stateBump, pda.escrowBump, {
          accounts: {
              safePayState: pda.stateKey,
              escrowWalletState: pda.escrowWalletKey,
              mintOfTokenBeingSent: mintAddress,
              userSending: alice.publicKey,
              userReceiving: bob.publicKey,
              walletToDepositTo: bobTokenAccount,
  
              systemProgram: anchor.web3.SystemProgram.programId,
              rent: anchor.web3.SYSVAR_RENT_PUBKEY,
              tokenProgram: spl.TOKEN_PROGRAM_ID,
              clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
              associatedTokenProgram: spl.ASSOCIATED_TOKEN_PROGRAM_ID,
          },
            signers: [bob],
         });
         assert.fail();
      } catch (err) {
        const error = err.error;
        assert.strictEqual(error.errorCode.number, 6023);
        assert.strictEqual(error.errorMessage, "Off the time limit");
      }
    })

    it('can pull back funds once they are deposited', async () => {
      mintAddress = await createMint(provider.connection);
      [alice, aliceWallet] = await createUserAndAssociatedWallet(provider.connection, 1337000000,mintAddress);
      let _rest;
      [bob, ..._rest] = await createUserAndAssociatedWallet(provider.connection, 1337000000,);
      pda = await getPdaParams(provider.connection, alice.publicKey, bob.publicKey, mintAddress);

      const [, aliceBalancePre] = await readAccount(aliceWallet, provider);
      assert.equal(aliceBalancePre, '1337000000');

      const amount = new anchor.BN(20000000);

      let listener = null;  
      let [event, slot] = await new Promise((resolve, _reject) => {
        listener = program.addEventListener("EventSafePay", (event, slot) => {
          resolve([event, slot]);
        });
     
        program.rpc.initializeNewGrant(pda.idx, new anchor.BN(0), pda.stateBump, pda.escrowBump, amount, {
          accounts: {
              safePayState: pda.stateKey,
              escrowWalletState: pda.escrowWalletKey,
              mintOfTokenBeingSent: mintAddress,
              userSending: alice.publicKey,
              userReceiving: bob.publicKey,
              walletToWithdrawFrom: aliceWallet,
  
              systemProgram: anchor.web3.SystemProgram.programId,
              rent: anchor.web3.SYSVAR_RENT_PUBKEY,
              clock: anchor.web3.SYSVAR_CLOCK_PUBKEY,
              tokenProgram: spl.TOKEN_PROGRAM_ID,
          },
          signers: [alice],
        });
        
      });
  
      await program.removeEventListener(listener);
  
      assert.strictEqual(event.label, "EventInitializeNewGrant");

      // console.log(`Initialized a new Safe Pay instance. Alice will pay bob 20 tokens`);

      // Assert that 20 tokens were moved from Alice's account to the escrow.
      const [, aliceBalancePost] = await readAccount(aliceWallet, provider);
      assert.equal(aliceBalancePost, '1317000000');
      const [, escrowBalancePost] = await readAccount(pda.escrowWalletKey, provider);
      assert.equal(escrowBalancePost, '20000000');

      let listener1 = null;  
      let [event1, slot1] = await new Promise((resolve, _reject) => {
        listener1 = program.addEventListener("EventSafePay", (event, slot) => {
          resolve([event, slot]);
        });
     
        program.rpc.pullBack(pda.idx, pda.stateBump, pda.escrowBump, {
          accounts: {
              safePayState: pda.stateKey,
              escrowWalletState: pda.escrowWalletKey,
              mintOfTokenBeingSent: mintAddress,
              userSending: alice.publicKey,
              userReceiving: bob.publicKey,
              refundWallet: aliceWallet,

              systemProgram: anchor.web3.SystemProgram.programId,
              rent: anchor.web3.SYSVAR_RENT_PUBKEY,
              tokenProgram: spl.TOKEN_PROGRAM_ID,
          },
          signers: [alice],
        });
        
      });
  
      await program.removeEventListener(listener1);
  
      assert.strictEqual(event1.label, "EventPullBack");

      // Assert that 20 tokens were sent back.
      const [, aliceBalanceRefund] = await readAccount(aliceWallet, provider);
      assert.equal(aliceBalanceRefund, '1337000000');

      // Assert that escrow was correctly closed.
      try {
          await readAccount(pda.escrowWalletKey, provider);
          return assert.fail("Account should be closed");
      } catch (e) {
          assert.equal(e.message, "Cannot read properties of null (reading 'data')");
      }

      const state = await program.account.safePayState.fetch(pda.stateKey);
      assert.equal(state.amountTokens.toString(), '20000000');
      assert.equal(state.stage.toString(), '3');

    })

});