pub mod utils;

use std::convert::TryInto;
use crate::utils::{Stage, ErrorCode, SafePayState, RentState, RentStage, Pool,
transfer_safe_pay_escrow_out, MULTISIG_SEED_STR, MULTISIG_TX_SEED_STR, POOL_OF_PLAT_COMMISSION_SEED_STR,WALLET_OF_PLAT_COMMISSION_SEED_STR,RENT_STATE_SEED_STR, NFT_ESCROW_WALLET_SEED_STR, RENTS_ESCROW_WALLET_SEED_STR,
transfer_nft_asset_to_vault, transfer_nft_asset_to_lender, transfer_rent_to_lender,transfer_rent_to_vault, transfer_commission_to_dest_account,
close_rent_escrow_token_account, SAFE_REWARD_PAY_STATE_SEED_STR, SAFE_REWARD_PAY_WALLET_SEED_STR,
EventRentStateUpdate, EventPoolUpdate, EventSafePay};
use anchor_lang::prelude::*;
use anchor_spl::{associated_token::AssociatedToken, token::{Mint, Token, TokenAccount}};
use solana_program::{
    self,
    instruction::Instruction,
};
use std::convert::Into;
use std::ops::Deref;

declare_id!("Metah4NXvuBAFNLHLoie5aiDksKvJsUDRGfXNJRr8EJ");


#[program]
pub mod metaone {

    use anchor_spl::token::Transfer;
    use super::*;


  // Initializes a new multisig account with a set of owners and a threshold.
  pub fn create_multisig(
    ctx: Context<CreateMultisig>,
    owners: Vec<Pubkey>,
    threshold: u64,
    nonce: u8,
    ) -> Result<()> {
        assert_unique_owners(&owners)?;
        require!(
            threshold > 0 && threshold <= owners.len() as u64,
            ErrorCode::InvalidThreshold
        );
        require!(!owners.is_empty(), ErrorCode::InvalidOwnersLen);

        let multisig = &mut ctx.accounts.multisig;
        multisig.owners = owners;
        multisig.threshold = threshold;
        multisig.nonce = nonce;
        multisig.seqno = 0;
        Ok(())
    }

    // Creates a new transaction account, automatically signed by the creator,
    // which must be one of the owners of the multisig.
    pub fn create_transaction(
        ctx: Context<CreateTransaction>,
        pid: Pubkey,
        accs: Vec<TransactionAccount>,
        data: Vec<u8>,
    ) -> Result<()> {
        let owner_index = ctx
            .accounts
            .multisig
            .owners
            .iter()
            .position(|a| a == ctx.accounts.proposer.key)
            .ok_or(ErrorCode::InvalidOwner)?;

        let mut signers = Vec::new();
        signers.resize(ctx.accounts.multisig.owners.len(), false);
        signers[owner_index] = true;

        let tx = &mut ctx.accounts.transaction;
        tx.program_id = pid;
        tx.accounts = accs;
        tx.data = data;
        tx.signers = signers;
        tx.multisig = ctx.accounts.multisig.key();
        tx.did_execute = false;
        tx.seqno = ctx.accounts.multisig.seqno;
        tx.proposer = ctx.accounts.proposer.key();

        Ok(())
    }

    // Approves a transaction on behalf of an owner of the multisig.
    pub fn approve(ctx: Context<Approve>) -> Result<()> {
        let owner_index = ctx
            .accounts
            .multisig
            .owners
            .iter()
            .position(|a| a == ctx.accounts.owner.key)
            .ok_or(ErrorCode::InvalidOwner)?;

        ctx.accounts.transaction.signers[owner_index] = true;

        Ok(())
    }

    // Set owners and threshold at once.
    pub fn set_owners_and_change_threshold<'info>(
        ctx: Context<'_, '_, '_, 'info, Auth<'info>>,
        owners: Vec<Pubkey>,
        threshold: u64,
    ) -> Result<()> {
        set_owners(
            Context::new(
                ctx.program_id,
                ctx.accounts,
                ctx.remaining_accounts,
                ctx.bumps.clone(),
            ),
            owners,
        )?;
        change_threshold(ctx, threshold)
    }

    // Sets the owners field on the multisig. The only way this can be invoked
    // is via a recursive call from execute_transaction -> set_owners.
    pub fn set_owners(ctx: Context<Auth>, owners: Vec<Pubkey>) -> Result<()> {
        assert_unique_owners(&owners)?;
        require!(!owners.is_empty(), ErrorCode::InvalidOwnersLen);

        let multisig = &mut ctx.accounts.multisig;

        if (owners.len() as u64) < multisig.threshold {
            multisig.threshold = owners.len() as u64;
        }

        multisig.owners = owners;
        multisig.seqno += 1;

        Ok(())
    }

    // Changes the execution threshold of the multisig. The only way this can be
    // invoked is via a recursive call from execute_transaction ->
    // change_threshold.
    pub fn change_threshold(ctx: Context<Auth>, threshold: u64) -> Result<()> {
        require!(threshold > 0, InvalidThreshold);
        if threshold > ctx.accounts.multisig.owners.len() as u64 {
            return Err(ErrorCode::InvalidThreshold.into());
        }
        let multisig = &mut ctx.accounts.multisig;
        multisig.threshold = threshold;
        Ok(())
    }

    // Executes the given transaction if threshold owners have signed it.
    pub fn execute_transaction(ctx: Context<ExecuteTransaction>) -> Result<()> {
        // Has this been executed already?
        if ctx.accounts.transaction.did_execute {
            return Err(ErrorCode::AlreadyExecuted.into());
        }

        // Do we have enough signers.
        let sig_count = ctx
            .accounts
            .transaction
            .signers
            .iter()
            .filter(|&did_sign| *did_sign)
            .count() as u64;
        if sig_count < ctx.accounts.multisig.threshold {
            return Err(ErrorCode::NotEnoughSigners.into());
        }

        // Execute the transaction signed by the multisig.
        let mut ix: Instruction = (*ctx.accounts.transaction).deref().into();
        ix.accounts = ix
            .accounts
            .iter()
            .map(|acc| {
                let mut acc = acc.clone();
                if &acc.pubkey == ctx.accounts.multisig_signer.key {
                    acc.is_signer = true;
                }
                acc
            })
            .collect();
        let multisig_key = ctx.accounts.multisig.key();
        let seeds = &[multisig_key.as_ref(), &[ctx.accounts.multisig.nonce]];
        let signer = &[&seeds[..]];
        let accounts = ctx.remaining_accounts;
        solana_program::program::invoke_signed(&ix, accounts, signer)?;

        // Burn the transaction to ensure one time use.
        ctx.accounts.transaction.did_execute = true;

        Ok(())
    }


    pub fn complete_grant(ctx: Context<CompleteGrant>, idx: u64, state_bump: u8, _wallet_bump: u8) -> Result<()>  {
       
        if Stage::from(ctx.accounts.safe_pay_state.stage)? != Stage::FundsDeposited {
            msg!("Stage is invalid, state stage is {}", ctx.accounts.safe_pay_state.stage);
            return Err(ErrorCode::StageInvalid.into());
        }

        require!(
            ctx.accounts.safe_pay_state.deadline > ctx.accounts.clock.unix_timestamp || ctx.accounts.safe_pay_state.deadline == 0,
            ErrorCode::OffTimeLimit
        );

        transfer_safe_pay_escrow_out(
            ctx.accounts.user_sending.to_account_info(),
            ctx.accounts.user_receiving.to_account_info(),
            ctx.accounts.mint_of_token_being_sent.to_account_info(),
            &mut ctx.accounts.escrow_wallet_state,
            idx,
            ctx.accounts.safe_pay_state.to_account_info(),
            state_bump,
            ctx.accounts.token_program.to_account_info(),
            ctx.accounts.wallet_to_deposit_to.to_account_info(),
            ctx.accounts.safe_pay_state.amount_tokens
        )?;

        let state = &mut ctx.accounts.safe_pay_state;
        state.stage = Stage::EscrowComplete.to_code();

        emit!(EventSafePay {
            label: "EventCompleteGrant".to_string(),

            idx: state.idx,
            user_sending: state.user_sending,
            user_receiving:  state.user_receiving,
            mint_of_token_being_sent: state.mint_of_token_being_sent,
            escrow_wallet: state.escrow_wallet,
            amount_tokens: state.amount_tokens,
            stage: state.stage,
        });

        Ok(())
    }

    pub fn pull_back(ctx: Context<PullBackInstruction>, idx: u64, state_bump: u8, _wallet_bump: u8) -> Result<()>  {
        let current_stage = Stage::from(ctx.accounts.safe_pay_state.stage)?;
        let is_valid_stage = current_stage == Stage::FundsDeposited || current_stage == Stage::PullBackComplete;
        if !is_valid_stage {
            msg!("Stage is invalid, state stage is {}", ctx.accounts.safe_pay_state.stage);
            return Err(ErrorCode::StageInvalid.into());
        }

        let wallet_amount = ctx.accounts.escrow_wallet_state.amount;
        transfer_safe_pay_escrow_out(
            ctx.accounts.user_sending.to_account_info(),
            ctx.accounts.user_receiving.to_account_info(),
            ctx.accounts.mint_of_token_being_sent.to_account_info(),
            &mut ctx.accounts.escrow_wallet_state,
            idx,
            ctx.accounts.safe_pay_state.to_account_info(),
            state_bump,
            ctx.accounts.token_program.to_account_info(),
            ctx.accounts.refund_wallet.to_account_info(),
            wallet_amount,
        )?;
        let state = &mut ctx.accounts.safe_pay_state;
        state.stage = Stage::PullBackComplete.to_code();

        emit!(EventSafePay {
            label: "EventPullBack".to_string(),

            idx: state.idx,
            user_sending: state.user_sending,
            user_receiving:  state.user_receiving,
            mint_of_token_being_sent: state.mint_of_token_being_sent,
            escrow_wallet: state.escrow_wallet,
            amount_tokens: state.amount_tokens,
            stage: state.stage,
        });

        Ok(())
    }

    pub fn initialize_new_grant(ctx: Context<InitializeNewGrant>, idx: u64, deadline: u64, state_bump: u8, _wallet_bump: u8, amount: u64) -> Result<()>  {

        require!(deadline < i64::MAX as u64, ErrorCode::RentInvalidPara);

        // Set the state attributes
        let state = &mut ctx.accounts.safe_pay_state;
        state.idx = idx;
        state.user_sending = ctx.accounts.user_sending.key();
        state.user_receiving = ctx.accounts.user_receiving.key();
        state.mint_of_token_being_sent = ctx.accounts.mint_of_token_being_sent.key();
        state.escrow_wallet = ctx.accounts.escrow_wallet_state.key();
        state.amount_tokens = amount;
        state.deadline = if deadline == 0 {0} else {deadline as i64 + ctx.accounts.clock.unix_timestamp};
        
        msg!("Initialized new Safe Transfer instance for {}", amount);

        let bump_vector = state_bump.to_le_bytes();
        let mint_of_token_being_sent_pk = ctx.accounts.mint_of_token_being_sent.key();
        let idx_bytes = idx.to_le_bytes();
        let inner = vec![
            SAFE_REWARD_PAY_STATE_SEED_STR.as_bytes(),
            ctx.accounts.user_sending.key.as_ref(),
            ctx.accounts.user_receiving.key.as_ref(),
            mint_of_token_being_sent_pk.as_ref(), 
            idx_bytes.as_ref(),
            bump_vector.as_ref(),
        ];
        let outer = vec![inner.as_slice()];

        // Below is the actual instruction that we are going to send to the Token program.
        let transfer_instruction = Transfer{
            from: ctx.accounts.wallet_to_withdraw_from.to_account_info(),
            to: ctx.accounts.escrow_wallet_state.to_account_info(),
            authority: ctx.accounts.user_sending.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            transfer_instruction,
            outer.as_slice(),
        );

        // The `?` at the end will cause the function to return early in case of an error.
        // This pattern is common in Rust.
        anchor_spl::token::transfer(cpi_ctx, state.amount_tokens)?;

        // Mark stage as deposited.
        state.stage = Stage::FundsDeposited.to_code();

        emit!(EventSafePay {
            label: "EventInitializeNewGrant".to_string(),

            idx: idx,
            user_sending: state.user_sending,
            user_receiving:  state.user_receiving,
            mint_of_token_being_sent: state.mint_of_token_being_sent,
            escrow_wallet: state.escrow_wallet,
            amount_tokens: state.amount_tokens,
            stage: state.stage,
        });

        Ok(())
    }

    pub fn build_plat_pool(
        ctx: Context<BuildPlatPool>,
        numerator: u64,
        denominator: u64,
    ) -> Result<()> {

        require!(denominator > 0 && denominator > numerator, ErrorCode::RentInvalidPara);

        let pool = &mut ctx.accounts.commission_pool;
        pool.ratio_numerator = numerator;
        pool.ratio_denominator = denominator;
        pool.mint = ctx.accounts.mint_of_token_for_pay_rents.key();
        pool.amount_collected = 0;

        emit!(EventPoolUpdate {
            label: "EventBuildPlatPool".to_string(),

            mint: pool.mint.key(),
            ratio_numerator: pool.ratio_numerator,
            ratio_denominator: pool.ratio_denominator,
            withdraw_commissions: 0,
            amount_collected: 0,
        });

        let multisig = &mut ctx.accounts.multisig;
        multisig.seqno += 1;

        Ok(())
    }  

    pub fn change_ratio(
        ctx: Context<ChangeRatio>,
        numerator: u64,
        denominator: u64,
    ) -> Result<()> {

        require!(denominator > 0 && denominator > numerator, ErrorCode::RentInvalidPara);

        let pool = &mut ctx.accounts.commission_pool;
        pool.ratio_numerator = numerator;
        pool.ratio_denominator = denominator;

        let multisig = &mut ctx.accounts.multisig;
        multisig.seqno += 1;
        
        emit!(EventPoolUpdate {
            label: "EventChangeRatio".to_string(),

            mint: pool.mint.key(),
            ratio_numerator: pool.ratio_numerator,
            ratio_denominator: pool.ratio_denominator,
            withdraw_commissions: 0,
            amount_collected: 0,
        });

        Ok(())
    }

    pub fn withdraw_commissions(
        ctx: Context<WithdrawCommissions>,
        rentamount: u64,
        poolbump: u8,
    ) -> Result<()> {

        let pool = &mut ctx.accounts.commission_pool;

        // withdrawl amount can not suppass the amount deposit in pool
        require!(pool.amount_collected >= rentamount, ErrorCode::RentInvalidPara);
        
        // record the deduction     
        let amount_collected_cal = &mut pool.amount_collected;
        *amount_collected_cal -= rentamount;

        // transfer the commission out to dst account asked for
        transfer_commission_to_dest_account(
            rentamount,
            poolbump,
            pool.to_account_info(),
            ctx.accounts.commission_wallet.to_account_info(),
            ctx.accounts.wallet_to_collect_commission.to_account_info(),
            ctx.accounts.dest.to_account_info(),
            ctx.accounts.mint_of_token_for_pay_rents.to_account_info(),
            ctx.accounts.token_program.to_account_info(),
        )?;

        let multisig = &mut ctx.accounts.multisig;
        multisig.seqno += 1;

        emit!(EventPoolUpdate {
            label: "EventWithDrawCommissions".to_string(),

            mint: pool.mint.key(),
            ratio_numerator: pool.ratio_numerator,
            ratio_denominator: pool.ratio_denominator,
            withdraw_commissions: rentamount,
            amount_collected: pool.amount_collected,
        });

        Ok(())
    } 

    pub fn rent_offer(
        ctx: Context<RentOffer>,
        idx: u64,
        price_per_time_unit: u64,
        time_unit: u64,
        duration_min: u64,
        duration_max: u64,
        extendable: bool,
        state_bump: u8,
    ) -> Result<()> {
        
        // para check
        require!(time_unit >0 && duration_min > 0 && duration_max > 0 && duration_max >= duration_min && price_per_time_unit > 0, ErrorCode::RentInvalidPara);
        require!(duration_max.checked_mul(time_unit).unwrap() < i64::MAX as u64, ErrorCode::RentInvalidPara);

        // Set the state attributes
        let state = &mut ctx.accounts.rent_state;
        {   
            state.idx = idx;
            state.price_per_time_unit = price_per_time_unit;
            state.time_unit = time_unit as i64;
            state.duration_min = duration_min as i64;
            state.duration_max = duration_max as i64;
            state.extendable = extendable;
            state.amount_rents = 0;
    
            state.mint_of_nft_for_lending = ctx.accounts.mint_of_nft_for_lending.key();
            state.mint_of_token_for_pay_rents = ctx.accounts.mint_of_token_for_pay_rents.key();
            state.escrow_wallet_of_nft = ctx.accounts.escrow_wallet_of_nft.key();
            state.escrow_wallet_of_rents = ctx.accounts.escrow_wallet_of_rents.key();
            state.lender = ctx.accounts.lender.key();
        }

        // transfer nft asset to vault
        transfer_nft_asset_to_vault(
            idx,
            state_bump,
            ctx.accounts.escrow_wallet_of_nft.to_account_info(),
            ctx.accounts.wallet_to_withdraw_nft_from.to_account_info(),
            ctx.accounts.lender.to_account_info(),                  
            ctx.accounts.mint_of_nft_for_lending.to_account_info(),  
            ctx.accounts.mint_of_token_for_pay_rents.to_account_info(),  
            ctx.accounts.token_program.to_account_info(),
        )?;

        state.stage = RentStage::Available.to_code();

        emit!(EventRentStateUpdate {
            label: "EventRentOffer".to_string(),
            stage: state.stage,

            mint_of_nft_for_lending: ctx.accounts.mint_of_nft_for_lending.key(),
            escrow_wallet_of_nft: ctx.accounts.escrow_wallet_of_nft.key(),
            lender: ctx.accounts.lender.key(),
            mint_of_token_for_pay_rents: ctx.accounts.mint_of_token_for_pay_rents.key(),
            escrow_wallet_of_rents: ctx.accounts.escrow_wallet_of_rents.key(),
            borrower: ctx.accounts.rent_state.borrower.key(),

            idx,
            price_per_time_unit,
            time_unit: time_unit as i64,
            duration_min: duration_min as i64,
            duration_max: duration_max as i64,
            expire_clock: ctx.accounts.rent_state.expire_clock,
            extendable,

            withdraw_rents: 0,
            deposit_rents: 0,
            commission_gen: 0,

            amount_rents:ctx.accounts.rent_state.amount_rents,
        });

        Ok(())
    }

    pub fn rent_change_offer(
        ctx: Context<RentChangeOffer>,
        idx: u64,
        price_per_time_unit: u64,
        time_unit: u64,
        duration_min: u64,
        duration_max: u64,
        extendable: bool,
    ) -> Result<()> {

        // para check
        require!(time_unit >0 && duration_min > 0 && duration_max > 0 && duration_max >= duration_min && price_per_time_unit > 0, ErrorCode::RentInvalidPara);
        require!(duration_max.checked_mul(time_unit).unwrap() < i64::MAX as u64, ErrorCode::RentInvalidPara);

        let state = &mut ctx.accounts.rent_state;

        if extendable == false {
            match RentStage::from(state.stage)? {
                RentStage::Occupied => {
                    if state.expire_clock < ctx.accounts.clock.unix_timestamp  {
                        if state.amount_rents == 0  {state.stage = RentStage::Idle.to_code();}
                    }
                },
                // RentStage::Available => {
                //     state.stage = RentStage::Idle.to_code();
                // },
                _ => (),
            }
        } else {
            match RentStage::from(state.stage)? {
                RentStage::Occupied => {
                    if state.expire_clock < ctx.accounts.clock.unix_timestamp  {
                        state.stage = RentStage::Available.to_code();
                    }
                },                
                RentStage::Idle => {
                    state.stage = RentStage::Available.to_code();
                },
                _ => (),
            }
        }

        // nft asset in rent, not allow to change the paras associated with this deal
        require!(RentStage::from(state.stage)? != RentStage::Occupied, ErrorCode::RentUpdateParasNotAllowed);

        state.price_per_time_unit = price_per_time_unit;
        state.time_unit = time_unit as i64;
        state.duration_min = duration_min as i64;
        state.duration_max = duration_max as i64;
        state.extendable = extendable;

        emit!(EventRentStateUpdate {
            label: "EventChangeOffer".to_string(),
            stage: state.stage,

            mint_of_nft_for_lending: state.mint_of_nft_for_lending.key(),
            escrow_wallet_of_nft: state.escrow_wallet_of_nft.key(),
            lender: state.lender.key(),
            mint_of_token_for_pay_rents: state.mint_of_token_for_pay_rents.key(),
            escrow_wallet_of_rents: state.escrow_wallet_of_rents.key(),
            borrower: state.borrower.key(),

            idx,
            price_per_time_unit,
            time_unit: time_unit as i64,
            duration_min: duration_min as i64,
            duration_max: duration_max as i64,
            expire_clock: state.expire_clock,
            extendable,

            withdraw_rents: 0,
            deposit_rents: 0,
            commission_gen: 0,

            amount_rents: state.amount_rents,
        });

        Ok(())
    }

    pub fn rent_close(
        ctx: Context<RentClose>,
        idx: u64,
        state_bump: u8,
    ) -> Result<()> {

        let state = &mut ctx.accounts.rent_state;

        // nft recalled only at stage of IDLE
        require!(state.amount_rents == 0, ErrorCode::RentUncollectedRents);

        // force to idle stage
        match RentStage::from(state.stage)? {
            RentStage::Occupied => {
                if state.expire_clock < ctx.accounts.clock.unix_timestamp  {
                    state.stage = RentStage::Idle.to_code();
                }
            },
            _ => {state.stage = RentStage::Idle.to_code();},
        }

        // nft recalled only at stage of IDLE
        require!(RentStage::from(state.stage)? != RentStage::Occupied, ErrorCode::RentLendingUnfinished);

        // transfer NFT back to lender's eoa wallet and close the account
        transfer_nft_asset_to_lender(
            idx,
            state_bump,
            state.to_account_info(),
            &mut ctx.accounts.escrow_wallet_of_nft,
            ctx.accounts.refund_wallet_of_nft_for_lending.to_account_info(),
            ctx.accounts.lender.to_account_info(),                  
            ctx.accounts.mint_of_nft_for_lending.to_account_info(),
            ctx.accounts.mint_of_token_for_pay_rents.to_account_info(),
            ctx.accounts.token_program.to_account_info(),
        )?;

        // close the escrow token account
        close_rent_escrow_token_account(
            idx,
            state_bump,
            state.to_account_info(),
            &mut ctx.accounts.escrow_wallet_of_rents,
            ctx.accounts.lender.to_account_info(),               
            ctx.accounts.mint_of_nft_for_lending.to_account_info(),
            ctx.accounts.mint_of_token_for_pay_rents.to_account_info(),
            ctx.accounts.token_program.to_account_info(),
        )?;

        emit!(EventRentStateUpdate {
            label: "EventOfferClose".to_string(),
            stage: state.stage,

            mint_of_nft_for_lending: state.mint_of_nft_for_lending.key(),
            escrow_wallet_of_nft: state.escrow_wallet_of_nft.key(),
            lender: state.lender.key(),
            mint_of_token_for_pay_rents: state.mint_of_token_for_pay_rents.key(),
            escrow_wallet_of_rents: state.escrow_wallet_of_rents.key(),
            borrower: state.borrower.key(),

            idx: state.idx,
            price_per_time_unit: state.price_per_time_unit,
            time_unit: state.time_unit,
            duration_min: state.duration_min,
            duration_max: state.duration_max,
            expire_clock: state.expire_clock,
            extendable: state.extendable,

            withdraw_rents: 0,
            deposit_rents: 0,
            commission_gen: 0,

            amount_rents: state.amount_rents,
        });

        Ok(())
    }    

    pub fn rent_deal(
        ctx: Context<RentDeal>,
        idx: u64,
        duration: u64,
        state_bump: u8,
        pool_bump: u8,
    ) -> Result<()> {
        
        // Set the state attributes
        let state = &mut ctx.accounts.rent_state;

        // if last lending deal finished and offer still valid by default
        // change stage to available automatically 
        if state.extendable == true
            && state.expire_clock < ctx.accounts.clock.unix_timestamp
            && RentStage::from(state.stage)? == RentStage::Occupied
        {
                state.stage = RentStage::Available.to_code();
        }

        // msg!("state.stag: {:?}", RentStage::from(state.stage)?);

        // stage check, nft available for borrowing only at available stage 
        require!(RentStage::from(state.stage)? == RentStage::Available, ErrorCode::RentUnavailable);

        // para check
        require!(duration <= state.duration_max as u64 &&  duration >= state.duration_min as u64, ErrorCode::RentDurationWBeyondBoundary);

        // record the current borrower account
        state.borrower = ctx.accounts.borrower.key().clone();
        
        // cal the total rents must be paid
        let rent_amount: u64 = state.price_per_time_unit
        .checked_mul(duration)
        .unwrap();

        // calc the commission paid by the lender, the lender can only recieve 
        // the rents deducted by the commission
        let numerator = ctx.accounts.commission_pool.ratio_numerator;
        let denominator = ctx.accounts.commission_pool.ratio_denominator;
        let commission_amount: u64 = u128::from(rent_amount)
            .checked_mul(numerator.into())
            .unwrap()
            .checked_div(denominator.into())
            .unwrap()
            .try_into()
            .map_err(|_| error!(ErrorCode::U128CannotConvert))?;
        let rent_amount = rent_amount - commission_amount;

        //transfer the rents and commissions to escrow wallet of vault
        transfer_rent_to_vault(
            idx,
            rent_amount,
            commission_amount,
            state_bump,
            pool_bump,
            ctx.accounts.commission_wallet.to_account_info(),
            ctx.accounts.escrow_wallet_of_rents.to_account_info(),
            ctx.accounts.wallet_to_withdraw_rents_from.to_account_info(),
            ctx.accounts.borrower.to_account_info(),
            ctx.accounts.lender.to_account_info(),               
            ctx.accounts.mint_of_nft_for_lending.to_account_info(),
            ctx.accounts.mint_of_token_for_pay_rents.to_account_info(),
            ctx.accounts.token_program.to_account_info(),
        )?;
 
        
        // record the newly added rents owed to lender
        let state_amount_rents_cal = &mut state.amount_rents;
        *state_amount_rents_cal += rent_amount;
      
        // record the expiring point of time for effective lending
        state.expire_clock = ctx.accounts.clock.unix_timestamp + ( duration as i64 *  state.time_unit as i64);

        // record the newly added commission
        let pool = &mut ctx.accounts.commission_pool;        
        let amount_collected_cal = &mut pool.amount_collected;
        *amount_collected_cal += commission_amount;

        // claim the asset be borrowed and occupied for a period of time forced by rent_duration
        state.stage = RentStage::Occupied.to_code();

        emit!(EventRentStateUpdate {
            label: "EventDealOffer".to_string(),
            stage: state.stage,

            mint_of_nft_for_lending: state.mint_of_nft_for_lending.key(),
            escrow_wallet_of_nft: state.escrow_wallet_of_nft.key(),
            lender: state.lender.key(),
            mint_of_token_for_pay_rents: state.mint_of_token_for_pay_rents.key(),
            escrow_wallet_of_rents: state.escrow_wallet_of_rents.key(),
            borrower: state.borrower.key(),

            idx: state.idx,
            price_per_time_unit: state.price_per_time_unit,
            time_unit: state.time_unit,
            duration_min: state.duration_min,
            duration_max: state.duration_max,
            expire_clock: state.expire_clock,
            extendable: state.extendable,

            withdraw_rents: 0,
            deposit_rents: rent_amount,
            commission_gen: commission_amount,

            amount_rents: state.amount_rents,
        });

        Ok(())
    }  

    pub fn rent_collect(
        ctx: Context<RentCollect>,
        idx: u64,
        rent_amount: u64,
        state_bump: u8,
    ) -> Result<()> {

        // Set the state attributes
        let state = &mut ctx.accounts.rent_state;

        require!(state.amount_rents > 0, ErrorCode::RentUnLeft);
        require!(state.amount_rents >= rent_amount, ErrorCode::RentNotEnoughDepositRents);

        let state_amount_rents_cal = &mut state.amount_rents;
        // msg!("6 change ratiobefore calc: commission_amount: {} +  amount_collected: {}", commission_amount, *amount_collected_cal);
        *state_amount_rents_cal -= rent_amount;

        transfer_rent_to_lender(
            idx,
            rent_amount,
            state_bump,
            state.to_account_info(),
            &mut ctx.accounts.escrow_wallet_of_rents,
            ctx.accounts.wallet_to_collect_rents.to_account_info(),
            ctx.accounts.lender.to_account_info(),              
            ctx.accounts.mint_of_nft_for_lending.to_account_info(),
            ctx.accounts.mint_of_token_for_pay_rents.to_account_info(),
            ctx.accounts.token_program.to_account_info(),
        )?;


        emit!(EventRentStateUpdate {
            label: "EventCollectRents".to_string(),
            stage: state.stage,

            mint_of_nft_for_lending: state.mint_of_nft_for_lending.key(),
            escrow_wallet_of_nft: state.escrow_wallet_of_nft.key(),
            lender: state.lender.key(),
            mint_of_token_for_pay_rents: state.mint_of_token_for_pay_rents.key(),
            escrow_wallet_of_rents: state.escrow_wallet_of_rents.key(),
            borrower: state.borrower.key(),

            idx: state.idx,
            price_per_time_unit: state.price_per_time_unit,
            time_unit: state.time_unit,
            duration_min: state.duration_min,
            duration_max: state.duration_max,
            expire_clock: state.expire_clock,
            extendable: state.extendable,

            withdraw_rents: rent_amount,
            deposit_rents: 0,
            commission_gen: 0,

            amount_rents: state.amount_rents,
        });

        Ok(())
    }  
}


#[derive(Accounts)]
pub struct CreateMultisig<'info> {
    // #[account(zero, signer)]
    #[account(
        init,
        payer = payer,
        space = 8+1000, //big enough
        seeds = [
            MULTISIG_SEED_STR.as_bytes(),
        ],
        bump,
    )]
    multisig: Box<Account<'info, Multisig>>,
    #[account(mut)]
    payer: Signer<'info>,
    system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CreateTransaction<'info> {
    #[account(
        seeds = [
            MULTISIG_SEED_STR.as_bytes(),
        ],
        bump,
    )]
    multisig: Box<Account<'info, Multisig>>,
    // #[account(zero, signer)]
    #[account(
        init_if_needed,
        payer = proposer,
        space = 1000, //big enough
        seeds = [
            MULTISIG_TX_SEED_STR.as_bytes(),
            multisig.seqno.to_le_bytes().as_ref(),
        ],
        bump,
    )]
    transaction: Box<Account<'info, Transaction>>,
    // One of the owners. Checked in the handler.
    #[account(mut)]
    proposer: Signer<'info>,
    system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Approve<'info> {
    #[account(
        seeds = [
            MULTISIG_SEED_STR.as_bytes(),
        ],
        bump,
        constraint = multisig.seqno == transaction.seqno
    )]
    multisig: Box<Account<'info, Multisig>>,
    #[account(mut, has_one = multisig)]
    transaction: Box<Account<'info, Transaction>>,
    // One of the multisig owners. Checked in the handler.
    owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct Auth<'info> {
    #[account(
        mut,
        seeds = [
            MULTISIG_SEED_STR.as_bytes(),
        ],
        bump,
    )]
    multisig: Box<Account<'info, Multisig>>,
    #[account(
        seeds = [multisig.key().as_ref()],
        bump = multisig.nonce,
    )]
    multisig_signer: Signer<'info>,
}

#[derive(Accounts)]
pub struct ChangeRatio<'info> {
    #[account(
        mut,
        seeds = [
            MULTISIG_SEED_STR.as_bytes(),
        ],
        bump,
    )]
    multisig: Box<Account<'info, Multisig>>,
    #[account(
        seeds = [multisig.key().as_ref()],
        bump = multisig.nonce,
    )]
    multisig_signer: Signer<'info>,

    // glabal commitments pool
    #[account(
        mut,
        seeds=[POOL_OF_PLAT_COMMISSION_SEED_STR.as_bytes(), 
            mint_of_token_for_pay_rents.key().as_ref(),
        ],
        bump,
    )]
    commission_pool: Box<Account<'info, Pool>>,
               
    mint_of_token_for_pay_rents: Box<Account<'info, Mint>>,  
}

#[derive(Accounts)]
pub struct ExecuteTransaction<'info> {
    #[account(
        seeds = [
            MULTISIG_SEED_STR.as_bytes(),
        ],
        bump,
        constraint = multisig.seqno == transaction.seqno
    )]
    multisig: Box<Account<'info, Multisig>>,
    /// CHECK: multisig_signer is a PDA program signer. Data is never read or written to
    #[account(
        seeds = [multisig.key().as_ref()],
        bump = multisig.nonce,
    )]
    multisig_signer: UncheckedAccount<'info>,
    #[account(mut, 
        has_one = multisig,
        has_one = proposer,
        close = proposer,
    )]
    transaction: Box<Account<'info, Transaction>>,
    /// CHECK: 
    #[account(mut)]
    proposer: UncheckedAccount<'info>,
}

#[account]
pub struct Multisig {
    pub threshold: u64,
    pub seqno: u32,
    pub nonce: u8,
    pub owners: Vec<Pubkey>,
}

#[account]
pub struct Transaction {
    pub proposer: Pubkey,
    // The multisig account this transaction belongs to.
    pub multisig: Pubkey,
    // Target program to execute against.
    pub program_id: Pubkey,
    // Accounts requried for the transaction.
    pub accounts: Vec<TransactionAccount>,
    // Instruction data for the transaction.
    pub data: Vec<u8>,
    // signers[index] is true iff multisig.owners[index] signed the transaction.
    pub signers: Vec<bool>,
    // Boolean ensuring one time execution.
    pub did_execute: bool,
    // Owner set sequence number.
    pub seqno: u32,
}

impl From<&Transaction> for Instruction {
    fn from(tx: &Transaction) -> Instruction {
        Instruction {
            program_id: tx.program_id,
            accounts: tx.accounts.iter().map(Into::into).collect(),
            data: tx.data.clone(),
        }
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct TransactionAccount {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

impl From<&TransactionAccount> for AccountMeta {
    fn from(account: &TransactionAccount) -> AccountMeta {
        match account.is_writable {
            false => AccountMeta::new_readonly(account.pubkey, account.is_signer),
            true => AccountMeta::new(account.pubkey, account.is_signer),
        }
    }
}

impl From<&AccountMeta> for TransactionAccount {
    fn from(account_meta: &AccountMeta) -> TransactionAccount {
        TransactionAccount {
            pubkey: account_meta.pubkey,
            is_signer: account_meta.is_signer,
            is_writable: account_meta.is_writable,
        }
    }
}

fn assert_unique_owners(owners: &[Pubkey]) -> Result<()> {
    for (i, owner) in owners.iter().enumerate() {
        require!(
            !owners.iter().skip(i + 1).any(|item| item == owner),
            ErrorCode::UniqueOwners
        )
    }
    Ok(())
}

#[derive(Accounts)]
#[instruction(idx: u64, state_bump: u8, wallet_bump: u8)]
pub struct InitializeNewGrant<'info> {
    #[account(
        init,
        payer = user_sending,
        space = SafePayState::LEN, // big enough
        seeds=[SAFE_REWARD_PAY_STATE_SEED_STR.as_bytes(), user_sending.key().as_ref(), user_receiving.key.as_ref(), mint_of_token_being_sent.key().as_ref(), idx.to_le_bytes().as_ref()],
        bump,
    )]
    safe_pay_state: Account<'info, SafePayState>,
    #[account(
        init,
        payer = user_sending,
        seeds=[SAFE_REWARD_PAY_WALLET_SEED_STR.as_bytes(), user_sending.key().as_ref(), user_receiving.key.as_ref(), mint_of_token_being_sent.key().as_ref(), idx.to_le_bytes().as_ref()],
        bump,
        token::mint=mint_of_token_being_sent,
        token::authority=safe_pay_state,
    )]
    escrow_wallet_state: Account<'info, TokenAccount>,

    // Users and accounts in the system
    #[account(mut)]
    user_sending: Signer<'info>,                     // Alice
    /// CHECK:
    user_receiving: AccountInfo<'info>,              // Bob
    mint_of_token_being_sent: Account<'info, Mint>,  // USDC

    // Alice's USDC wallet that has already approved the escrow wallet
    #[account(
        mut,
        constraint=wallet_to_withdraw_from.owner == user_sending.key(),
        constraint=wallet_to_withdraw_from.mint == mint_of_token_being_sent.key()
    )]
    wallet_to_withdraw_from: Account<'info, TokenAccount>,

    // Application level accounts
    system_program: Program<'info, System>,
    token_program: Program<'info, Token>,
    clock: Sysvar<'info, Clock>,
    rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(idx: u64, state_bump: u8, wallet_bump: u8)]
pub struct CompleteGrant<'info> {
    #[account(
        mut,
        seeds=[SAFE_REWARD_PAY_STATE_SEED_STR.as_bytes(), user_sending.key().as_ref(), user_receiving.key.as_ref(), mint_of_token_being_sent.key().as_ref(), idx.to_le_bytes().as_ref()],
        bump = state_bump,
        has_one = user_sending,
        has_one = user_receiving,
        has_one = mint_of_token_being_sent,
    )]
    safe_pay_state: Account<'info, SafePayState>,
    #[account(
        mut,
        seeds=[SAFE_REWARD_PAY_WALLET_SEED_STR.as_bytes(), user_sending.key().as_ref(), user_receiving.key.as_ref(), mint_of_token_being_sent.key().as_ref(), idx.to_le_bytes().as_ref()],
        bump = wallet_bump,
    )]
    escrow_wallet_state: Account<'info, TokenAccount>,

    #[account(
        init_if_needed,
        payer = user_receiving,
        associated_token::mint = mint_of_token_being_sent,
        associated_token::authority = user_receiving,
    )]
    wallet_to_deposit_to: Account<'info, TokenAccount>,   // Bob's USDC wallet (will be initialized if it did not exist)

    // Users and accounts in the system
    #[account(mut)]
    /// CHECK:
    user_sending: AccountInfo<'info>,                     // Alice
    #[account(mut)]
    user_receiving: Signer<'info>,                        // Bob
    mint_of_token_being_sent: Account<'info, Mint>,       // USDC

    // Application level accounts
    system_program: Program<'info, System>,
    token_program: Program<'info, Token>,
    associated_token_program: Program<'info, AssociatedToken>,
    clock: Sysvar<'info, Clock>,
    rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(idx: u64, state_bump: u8, wallet_bump: u8)]
pub struct PullBackInstruction<'info> {
    #[account(
        mut,
        seeds=[SAFE_REWARD_PAY_STATE_SEED_STR.as_bytes(), user_sending.key().as_ref(), user_receiving.key.as_ref(), mint_of_token_being_sent.key().as_ref(), idx.to_le_bytes().as_ref()],
        bump = state_bump,
        has_one = user_sending,
        has_one = user_receiving,
        has_one = mint_of_token_being_sent,
    )]
    safe_pay_state: Account<'info, SafePayState>,
    #[account(
        mut,
        seeds=[SAFE_REWARD_PAY_WALLET_SEED_STR.as_bytes(), user_sending.key().as_ref(), user_receiving.key.as_ref(), mint_of_token_being_sent.key().as_ref(), idx.to_le_bytes().as_ref()],
        bump = wallet_bump,
    )]
    escrow_wallet_state: Account<'info, TokenAccount>,    
    // Users and accounts in the system
    #[account(mut)]
    user_sending: Signer<'info>,
    /// CHECK:
    user_receiving: AccountInfo<'info>,
    mint_of_token_being_sent: Account<'info, Mint>,

    // Application level accounts
    system_program: Program<'info, System>,
    token_program: Program<'info, Token>,
    rent: Sysvar<'info, Rent>,

    // Wallet to deposit to
    #[account(
        mut,
        constraint=refund_wallet.owner == user_sending.key(),
        constraint=refund_wallet.mint == mint_of_token_being_sent.key()
    )]
    refund_wallet: Account<'info, TokenAccount>,
}

#[derive(Accounts)]
pub struct BuildPlatPool<'info> {
    #[account(
        mut,
        seeds = [
            MULTISIG_SEED_STR.as_bytes(),
        ],
        bump,
    )]
    multisig: Box<Account<'info, Multisig>>,
    #[account(
        seeds = [multisig.key().as_ref()],
        bump = multisig.nonce,
    )]
    multisig_signer: Signer<'info>,

    // glabal commitments pool
    #[account(
        init,
        payer = proposer,
        space = Pool::LEN,
        seeds=[POOL_OF_PLAT_COMMISSION_SEED_STR.as_bytes(), 
            mint_of_token_for_pay_rents.key().as_ref(),
        ],
        bump,
    )]
    commission_pool: Box<Account<'info, Pool>>,

    // plat commission token accounts
    #[account(
        init,
        payer = proposer,
        seeds=[WALLET_OF_PLAT_COMMISSION_SEED_STR.as_bytes(), 
            mint_of_token_for_pay_rents.key().as_ref(),
        ],
        bump,
        token::mint=mint_of_token_for_pay_rents,
        token::authority=commission_pool,
    )]
    commission_wallet: Box<Account<'info, TokenAccount>>, 
    
    #[account(mut)]
    /// UNCHECK:
    proposer: AccountInfo<'info>,    
    mint_of_token_for_pay_rents: Box<Account<'info, Mint>>,  

    //sys and npl prog-accs used
    system_program: Program<'info, System>,
    token_program: Program<'info, Token>,
    rent: Sysvar<'info, Rent>,
}


#[event]
pub struct EventBuildPool {
    // pub Pool: pool,
    pub data: u64,
    // pub clock: i64,

    #[index]
    pub label: String,
}


#[derive(Accounts)]
pub struct WithdrawCommissions<'info> {
    #[account(
        mut,
        seeds = [
            MULTISIG_SEED_STR.as_bytes(),
        ],
        bump,
    )]
    multisig: Box<Account<'info, Multisig>>,
    #[account(
        seeds = [multisig.key().as_ref()],
        bump = multisig.nonce,
    )]
    multisig_signer: Signer<'info>,

    // glabal commitments pool
    #[account(
        mut,
        seeds=[POOL_OF_PLAT_COMMISSION_SEED_STR.as_bytes(), 
            mint_of_token_for_pay_rents.key().as_ref(),
        ],
        bump,
    )]
    commission_pool: Box<Account<'info, Pool>>,

    // plat commission token accounts
    #[account(
        mut,
        seeds=[WALLET_OF_PLAT_COMMISSION_SEED_STR.as_bytes(), 
            mint_of_token_for_pay_rents.key().as_ref(),
        ],
        bump,
        token::mint=mint_of_token_for_pay_rents,
        token::authority=commission_pool,
    )]
    commission_wallet: Box<Account<'info, TokenAccount>>,   

    #[account(
        // init_if_needed,
        // payer = payer,
        mut,
        associated_token::mint = mint_of_token_for_pay_rents,
        associated_token::authority = dest,
    )]
    wallet_to_collect_commission: Box<Account<'info, TokenAccount>>,

    /// UNCHECK:
    dest: AccountInfo<'info>,     
    
    // #[account(mut)]
    // payer: Signer<'info>,      
    mint_of_token_for_pay_rents: Box<Account<'info, Mint>>,  

    //sys and npl prog-accs used
    system_program: Program<'info, System>,
    token_program: Program<'info, Token>,
    associated_token_program: Program<'info, AssociatedToken>,
    rent: Sysvar<'info, Rent>,
}


#[derive(Accounts)]
#[instruction(idx: u64)]
pub struct RentOffer<'info> {
    // glabal commitments pool
    #[account(
        seeds=[POOL_OF_PLAT_COMMISSION_SEED_STR.as_bytes(), 
            mint_of_token_for_pay_rents.key().as_ref(),
        ],
        bump,
    )]
    commission_pool: Box<Account<'info, Pool>>,

    // plat commit token accounts
    #[account(
        seeds=[WALLET_OF_PLAT_COMMISSION_SEED_STR.as_bytes(), 
            mint_of_token_for_pay_rents.key().as_ref(),
        ],
        bump,
        token::mint=mint_of_token_for_pay_rents,
        token::authority=commission_pool,
    )]
    commission_wallet: Box<Account<'info, TokenAccount>>,   

    // create a rent state account
    #[account(
        init,
        payer = lender,
        space = RentState::LEN,
        seeds=[RENT_STATE_SEED_STR.as_bytes(), lender.key().as_ref(), mint_of_nft_for_lending.key().as_ref(), mint_of_token_for_pay_rents.key().as_ref(), idx.to_le_bytes().as_ref()],
        bump,
    )]
    rent_state: Account<'info, RentState>,

    // create a pda wallet to escrow nft asset
    #[account(
        init,
        payer = lender,
        seeds=[NFT_ESCROW_WALLET_SEED_STR.as_bytes(), lender.key().as_ref(), mint_of_nft_for_lending.key().as_ref(), mint_of_token_for_pay_rents.key().as_ref(), idx.to_le_bytes().as_ref()],
        bump,
        token::mint=mint_of_nft_for_lending,
        token::authority=rent_state,
    )]
    escrow_wallet_of_nft: Account<'info, TokenAccount>,

    // create a escrow accoutto store the rents waiting lender to collect
    #[account(
        init,
        payer = lender,
        seeds=[RENTS_ESCROW_WALLET_SEED_STR.as_bytes(), lender.key().as_ref(), mint_of_nft_for_lending.key().as_ref(), mint_of_token_for_pay_rents.key().as_ref(), idx.to_le_bytes().as_ref()],
        bump,
        token::mint=mint_of_token_for_pay_rents,
        token::authority=rent_state,
    )]
    escrow_wallet_of_rents: Account<'info, TokenAccount>,

    // lender's wallet to withdraw nft from lender to pda wallet
    #[account(
        mut,
        constraint=wallet_to_withdraw_nft_from.owner == lender.key(),
        constraint=wallet_to_withdraw_nft_from.mint == mint_of_nft_for_lending.key()
    )]
    wallet_to_withdraw_nft_from: Box<Account<'info, TokenAccount>>,

    // lender's wallet accounts as signer, nft mint account ref and rents mint account ref.
    #[account(mut)]
    lender: Signer<'info>,                    
    mint_of_nft_for_lending: Box<Account<'info, Mint>>,  
    mint_of_token_for_pay_rents: Box<Account<'info, Mint>>,  

    //sys and npl prog-accs used
    // clock: Sysvar<'info, Clock>,
    system_program: Program<'info, System>,
    token_program: Program<'info, Token>,
    rent: Sysvar<'info, Rent>,
}


#[derive(Accounts)]
#[instruction(idx: u64)]
pub struct RentChangeOffer<'info> {
    // rent state reference
    #[account(
        mut,
        seeds=[RENT_STATE_SEED_STR.as_bytes(), lender.key().as_ref(), mint_of_nft_for_lending.key().as_ref(), mint_of_token_for_pay_rents.key().as_ref(), idx.to_le_bytes().as_ref()],
        bump,
        has_one = lender,
        has_one = mint_of_nft_for_lending,
        has_one = mint_of_token_for_pay_rents,
        // constraint = rent_state.amount_rents > 0,
    )]
    rent_state: Box<Account<'info, RentState>>,

    // // lender's wallet accounts as signer, nft mint account ref and rents mint account ref.
    #[account(mut)]
    lender: Signer<'info>,                    
    mint_of_nft_for_lending: Box<Account<'info, Mint>>,  
    mint_of_token_for_pay_rents: Box<Account<'info, Mint>>,  

    //sys and npl prog-accs used
    system_program: Program<'info, System>,
    clock: Sysvar<'info, Clock>,
}

#[derive(Accounts)]
#[instruction(idx: u64)]
pub struct RentDeal<'info> {

    // glabal commitments pool
    #[account(
        mut,
        seeds=[POOL_OF_PLAT_COMMISSION_SEED_STR.as_bytes(), 
            mint_of_token_for_pay_rents.key().as_ref(),
        ],
        bump,
    )]
    commission_pool: Box<Account<'info, Pool>>,

    // plat commit token accounts
    #[account(
        mut,
        seeds=[WALLET_OF_PLAT_COMMISSION_SEED_STR.as_bytes(), 
            mint_of_token_for_pay_rents.key().as_ref(),
        ],
        bump,
        token::mint=mint_of_token_for_pay_rents,
        token::authority=commission_pool,
    )]
    commission_wallet: Box<Account<'info, TokenAccount>>,   

    // rent state reference, and must not at Occupied stage, the nft asset cant be lent twice
    #[account(
        mut,
        seeds=[RENT_STATE_SEED_STR.as_bytes(), lender.key().as_ref(), mint_of_nft_for_lending.key().as_ref(), mint_of_token_for_pay_rents.key().as_ref(), idx.to_le_bytes().as_ref()],
        bump,
        has_one = lender,
        has_one = mint_of_nft_for_lending,
        has_one = mint_of_token_for_pay_rents,
        // constraint=rent_state.stage == RentStage::Available.to_code(),
    )]
    rent_state: Box<Account<'info, RentState>>,

    #[account(
        mut,
        seeds=[RENTS_ESCROW_WALLET_SEED_STR.as_bytes(), lender.key().as_ref(), mint_of_nft_for_lending.key().as_ref(), mint_of_token_for_pay_rents.key().as_ref(), idx.to_le_bytes().as_ref()],
        bump,
        constraint=escrow_wallet_of_rents.owner == rent_state.key(),
        constraint=escrow_wallet_of_rents.mint == mint_of_token_for_pay_rents.key()
    )]
    escrow_wallet_of_rents: Box<Account<'info, TokenAccount>>,

    // wallet to withdraw rents from borrower
    #[account(
        mut,
        constraint=wallet_to_withdraw_rents_from.owner == borrower.key(),
        constraint=wallet_to_withdraw_rents_from.mint == mint_of_token_for_pay_rents.key()
    )]
    wallet_to_withdraw_rents_from: Box<Account<'info, TokenAccount>>,

    // borrower's wallet accounts as signer, lender account ref, nft mint account ref and rents mint account ref.
    #[account(mut)]
    borrower: Signer<'info>,                    
    /// CHECK: 
    lender: AccountInfo<'info>,
    mint_of_nft_for_lending: Box<Account<'info, Mint>>,  
    mint_of_token_for_pay_rents: Box<Account<'info, Mint>>,

    //sys and npl prog-accs used 
    system_program: Program<'info, System>,
    token_program: Program<'info, Token>,
    rent: Sysvar<'info, Rent>,
    clock: Sysvar<'info, Clock>,
}

#[derive(Accounts)]
#[instruction(idx: u64)]
pub struct RentCollect<'info> {
    // rent state reference
    #[account(
        mut,
        seeds=[RENT_STATE_SEED_STR.as_bytes(), lender.key().as_ref(), mint_of_nft_for_lending.key().as_ref(), mint_of_token_for_pay_rents.key().as_ref(), idx.to_le_bytes().as_ref()],
        bump,
        has_one = lender,
        has_one = mint_of_nft_for_lending,
        has_one = mint_of_token_for_pay_rents,
        // constraint = rent_state.amount_rents > 0,
    )]
    rent_state: Box<Account<'info, RentState>>,

    // escrow wallets of rents
    #[account(
        mut,
        seeds=[RENTS_ESCROW_WALLET_SEED_STR.as_bytes(), lender.key().as_ref(), mint_of_nft_for_lending.key().as_ref(), mint_of_token_for_pay_rents.key().as_ref(), idx.to_le_bytes().as_ref()],
        bump,
        constraint=escrow_wallet_of_rents.owner == rent_state.key(),
        constraint=escrow_wallet_of_rents.mint == mint_of_token_for_pay_rents.key()
    )]
    escrow_wallet_of_rents: Box<Account<'info, TokenAccount>>,

    // lender's wallet to collect rents
    #[account(
        init_if_needed,
        payer = lender,
        associated_token::mint = mint_of_token_for_pay_rents,
        associated_token::authority = lender,
    )]
    wallet_to_collect_rents: Box<Account<'info, TokenAccount>>,

    // lender's wallet accounts as signer, nft mint account ref and rents mint account ref.
    #[account(mut)]
    lender: Signer<'info>,                    
    mint_of_nft_for_lending: Box<Account<'info, Mint>>,  
    mint_of_token_for_pay_rents: Box<Account<'info, Mint>>,

    //sys and npl prog-accs used 
    system_program: Program<'info, System>,
    token_program: Program<'info, Token>,
    associated_token_program: Program<'info, AssociatedToken>,
    rent: Sysvar<'info, Rent>,
}


#[derive(Accounts)]
#[instruction(idx: u64)]
pub struct RentClose<'info> {
    // rent state reference, must be mutable and at idle stage (not lent and no rents left to collect)
    #[account(
        mut,
        seeds=[RENT_STATE_SEED_STR.as_bytes(), lender.key().as_ref(), mint_of_nft_for_lending.key().as_ref(), mint_of_token_for_pay_rents.key().as_ref(), idx.to_le_bytes().as_ref()],
        bump,
        has_one = lender,
        has_one = mint_of_nft_for_lending,
        has_one = mint_of_token_for_pay_rents,
        // constraint=rent_state.stage == RentStage::Idle.to_code(), 
        close = lender,
    )]
    rent_state: Box<Account<'info, RentState>>,

    // pda wallet ref used to escrow nft asset
    #[account(
        mut,
        seeds=[NFT_ESCROW_WALLET_SEED_STR.as_bytes(), lender.key().as_ref(), mint_of_nft_for_lending.key().as_ref(), mint_of_token_for_pay_rents.key().as_ref(), idx.to_le_bytes().as_ref()],
        bump,
        constraint=escrow_wallet_of_nft.owner == rent_state.key(),
        constraint=escrow_wallet_of_nft.mint == mint_of_nft_for_lending.key()
    )]
    escrow_wallet_of_nft: Box<Account<'info, TokenAccount>>,    

    // escrow wallets of rents
    #[account(
        mut,
        seeds=[RENTS_ESCROW_WALLET_SEED_STR.as_bytes(), lender.key().as_ref(), mint_of_nft_for_lending.key().as_ref(), mint_of_token_for_pay_rents.key().as_ref(), idx.to_le_bytes().as_ref()],
        bump,
        constraint=escrow_wallet_of_rents.owner == rent_state.key(),
        constraint=escrow_wallet_of_rents.mint == mint_of_token_for_pay_rents.key()
    )]
    escrow_wallet_of_rents: Box<Account<'info, TokenAccount>>,

    // refunt nft to lender's wallet
    #[account(
        mut,
        constraint=refund_wallet_of_nft_for_lending.owner == lender.key(),
        constraint=refund_wallet_of_nft_for_lending.mint == mint_of_nft_for_lending.key()
    )]
    refund_wallet_of_nft_for_lending: Box<Account<'info, TokenAccount>>,

    // lender's wallet accounts as signer, nft mint account ref and rents mint account ref.
    #[account(mut)]
    lender: Signer<'info>,                    
    mint_of_nft_for_lending: Box<Account<'info, Mint>>,  
    mint_of_token_for_pay_rents: Box<Account<'info, Mint>>,

    //sys and npl prog-accs used 
    system_program: Program<'info, System>,
    token_program: Program<'info, Token>,
    rent: Sysvar<'info, Rent>,
    clock: Sysvar<'info, Clock>,
}