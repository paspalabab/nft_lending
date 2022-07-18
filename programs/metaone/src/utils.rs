use anchor_lang::prelude::*;
use anchor_spl::{token::{CloseAccount, TokenAccount, Transfer}};
// use solana_program::{
//     self,
//     entrypoint::ProgramResult,
// };
use std::convert::Into;

// plat Seeds
pub const SAFE_REWARD_PAY_STATE_SEED_STR: &str = "safe_reward_pay_state";
pub const SAFE_REWARD_PAY_WALLET_SEED_STR: &str = "safe_reward_pay_wallet";

// plat Seeds
pub const MULTISIG_SEED_STR: &str = "multisig";
pub const MULTISIG_TX_SEED_STR: &str = "multisig_transaction";
pub const POOL_OF_PLAT_COMMISSION_SEED_STR: &str = "commission_pool_of_plat";
pub const WALLET_OF_PLAT_COMMISSION_SEED_STR: &str = "commission_wallet_of_plat";

// Per Instance Seeds
pub const RENT_STATE_SEED_STR: &str = "rent_state";
pub const NFT_ESCROW_WALLET_SEED_STR: &str = "escrow_wallet_of_nft";
pub const RENTS_ESCROW_WALLET_SEED_STR: &str = "escrow_wallet_of_rents";

#[error_code]
pub enum ErrorCode {
    #[msg("The given owner is not part of this multisig.")]
    InvalidOwner,
    #[msg("Owners length must be non zero.")]
    InvalidOwnersLen,
    #[msg("Not enough owners signed this transaction.")]
    NotEnoughSigners,
    #[msg("Cannot delete a transaction that has been signed by an owner.")]
    TransactionAlreadySigned,
    #[msg("Overflow when adding.")]
    Overflow,
    #[msg("Cannot delete a transaction the owner did not create.")]
    UnableToDelete,
    #[msg("The given transaction has already been executed.")]
    AlreadyExecuted,
    #[msg("Threshold must be less than or equal to the number of owners.")]
    InvalidThreshold,
    #[msg("Owners must be unique")]
    UniqueOwners,    
    #[msg("Wallet to withdraw from is not owned by owner")]
    WalletToWithdrawFromInvalid,
    #[msg("State index is inconsistent")]
    InvalidStateIdx,
    #[msg("Delegate is not set correctly")]
    DelegateNotSetCorrectly,
    #[msg("Stage is invalid")]
    StageInvalid,
    #[msg("Rent Stage is invalid")]
    RentStageInvalid,
    #[msg("Unavailble for lending now")]
    RentUnavailable,
    #[msg("not enough deposit rents for collecting")]
    RentNotEnoughDepositRents,
    #[msg("no rents lef in escrow vaults for collecting")]
    RentUnLeft,
    #[msg("Rents left uncollected before trying to close escrow account")]
    RentUncollectedRents,
    #[msg("Rents nft asset lending still in effective period before trying to close escrow account")]
    RentLendingUnfinished,
    #[msg("Rents paras such as duration,prices not allowed during lending process")]
    RentUpdateParasNotAllowed,
    #[msg("Rents para config such as duration,prices not valid")]
    RentInvalidPara,
    #[msg("Rents duration beyond time boundary")]
    RentDurationWBeyondBoundary,
    #[msg("u128 cannot be converted into u64")]
    U128CannotConvert,
    #[msg("Off the time limit")]
    OffTimeLimit,
}


impl From<ErrorCode> for ProgramError {
    fn from(e: ErrorCode) -> Self {
        ProgramError::Custom(e as u32)
    }
}

// 
/// A small utility function that allows us to transfer funds out of the Escrow.
///
/// # Arguments
///
/// * `user_sending` - Alice's account
/// * `user_sending` - Bob's account
/// * `mint_of_token_being_sent` - The mint of the token being held in escrow
/// * `escrow_wallet` - The escrow Token account
/// * `application_idx` - The primary key (timestamp) of the instance
/// * `state` - the application state public key (PDA)
/// * `state_bump` - the application state public key (PDA) bump
/// * `token_program` - the token program address
/// * `destination_wallet` - The public key of the destination address (where to send funds)
/// * `amount` - the amount of `mint_of_token_being_sent` that is sent from `escrow_wallet` to `destination_wallet`
///
pub fn transfer_safe_pay_escrow_out<'info>(
    user_sending: AccountInfo<'info>,
    user_receiving: AccountInfo<'info>,
    mint_of_token_being_sent: AccountInfo<'info>,
    escrow_wallet: &mut Account<'info, TokenAccount>,
    application_idx: u64,
    state: AccountInfo<'info>,
    state_bump: u8,
    token_program: AccountInfo<'info>,
    destination_wallet: AccountInfo<'info>,
    amount: u64
) -> Result<()>  {

    // Nothing interesting here! just boilerplate to compute our signer seeds for
    // signing on behalf of our PDA.
    let bump_vector = state_bump.to_le_bytes();
    let mint_of_token_being_sent_pk = mint_of_token_being_sent.key().clone();
    let application_idx_bytes = application_idx.to_le_bytes();
    let inner = vec![
        SAFE_REWARD_PAY_STATE_SEED_STR.as_bytes(),
        user_sending.key.as_ref(),
        user_receiving.key.as_ref(),
        mint_of_token_being_sent_pk.as_ref(), 
        application_idx_bytes.as_ref(),
        bump_vector.as_ref(),
    ];
    let outer = vec![inner.as_slice()];

    // Perform the actual transfer
    let transfer_instruction = Transfer{
        from: escrow_wallet.to_account_info(),
        to: destination_wallet,
        authority: state.to_account_info(),
    };
    let cpi_ctx = CpiContext::new_with_signer(
        token_program.to_account_info(),
        transfer_instruction,
        outer.as_slice(),
    );
    anchor_spl::token::transfer(cpi_ctx, amount)?;


    // Use the `reload()` function on an account to reload it's state. Since we performed the
    // transfer, we are expecting the `amount` field to have changed.
    let should_close = {
        escrow_wallet.reload()?;
        escrow_wallet.amount == 0
    };

    // If token account has no more tokens, it should be wiped out since it has no other use case.
    if should_close {
        let ca = CloseAccount{
            account: escrow_wallet.to_account_info(),
            destination: user_sending.to_account_info(),
            authority: state.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            token_program.to_account_info(),
            ca,
            outer.as_slice(),
        );
        anchor_spl::token::close_account(cpi_ctx)?;
    }

    Ok(())
}

pub fn transfer_nft_asset_to_vault<'info>(
    idx: u64,
    state_bump: u8,
    escrow_wallet_of_nft: AccountInfo<'info>,
    wallet_to_withdraw_nft_from: AccountInfo<'info>,
    lender: AccountInfo<'info>,                   
    mint_of_nft_for_lending: AccountInfo<'info>,
    mint_of_token_for_pay_rents: AccountInfo<'info>,
    token_program: AccountInfo<'info>,
) -> Result<()> {

    // transfer nft to escrowed wallet
    let lender_key = lender.key().clone();
    let mint_of_nft_for_lending_key = mint_of_nft_for_lending.key().clone();
    let mint_of_token_for_pay_rents_key = mint_of_token_for_pay_rents.key().clone();
    let bump_vecs = state_bump.to_le_bytes();
    let idx_bytes = idx.to_le_bytes();

    let inner = vec![
        RENT_STATE_SEED_STR.as_bytes(),
        lender_key.as_ref(),
        mint_of_nft_for_lending_key.as_ref(),
        mint_of_token_for_pay_rents_key.as_ref(),
        idx_bytes.as_ref(),
        bump_vecs.as_ref(),
    ];
    let outer = vec![inner.as_slice()];

    let transfer_instruction = Transfer{
        from: wallet_to_withdraw_nft_from.to_account_info(),
        to: escrow_wallet_of_nft.to_account_info(),
        authority: lender.to_account_info(),
    };
    let cpi_ctx = CpiContext::new_with_signer(
        token_program.to_account_info(),
        transfer_instruction,
        outer.as_slice(),
    );

    anchor_spl::token::transfer(cpi_ctx, 1)?;

    Ok(())
}


pub fn transfer_nft_asset_to_lender<'info>(
    idx: u64,
    state_bump: u8,
    rent_state: AccountInfo<'info>,
    escrow_wallet_of_nft: &mut Account<'info, TokenAccount>,
    refund_wallet_of_nft_for_lending: AccountInfo<'info>,
    lender: AccountInfo<'info>,                   
    mint_of_nft_for_lending: AccountInfo<'info>,
    mint_of_token_for_pay_rents: AccountInfo<'info>,
    token_program: AccountInfo<'info>,
) -> Result<()> {

    // transfer nft to escrowed wallet
    let lender_key = lender.key().clone();
    let mint_of_nft_for_lending_key = mint_of_nft_for_lending.key().clone();
    let mint_of_token_for_pay_rents_key = mint_of_token_for_pay_rents.key().clone();
    let bump_vecs = state_bump.to_le_bytes();
    let idx_bytes = idx.to_le_bytes();

    let inner = vec![
        RENT_STATE_SEED_STR.as_bytes(),
        lender_key.as_ref(),
        mint_of_nft_for_lending_key.as_ref(),
        mint_of_token_for_pay_rents_key.as_ref(),
        idx_bytes.as_ref(),
        bump_vecs.as_ref(),
    ];
    let outer = vec![inner.as_slice()];

    let transfer_instruction = Transfer{
        from: escrow_wallet_of_nft.to_account_info(),
        to: refund_wallet_of_nft_for_lending.to_account_info(),
        authority: rent_state.to_account_info(),
    };
    let cpi_ctx = CpiContext::new_with_signer(
        token_program.to_account_info(),
        transfer_instruction,
        outer.as_slice(),
    );

    anchor_spl::token::transfer(cpi_ctx, 1)?;

    // Use the `reload()` function on an account to reload it's state. Since we performed the
    // transfer, we are expecting the `amount` field to have changed.
    let should_close = {
        escrow_wallet_of_nft.reload()?;
        escrow_wallet_of_nft.amount == 0
    };

    // If token account has no more tokens, it should be wiped out since it has no other use case.
    if should_close {
        let ca = CloseAccount{
            account: escrow_wallet_of_nft.to_account_info(),
            destination: lender.to_account_info(),
            authority: rent_state.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            token_program.to_account_info(),
            ca,
            outer.as_slice(),
        );
        anchor_spl::token::close_account(cpi_ctx)?;
    }

    Ok(())
}

pub fn transfer_rent_to_vault<'info>(
    idx: u64,
    rent_amount: u64,
    commission_amount: u64,
    state_bump: u8,
    pool_bump: u8,
    commission_wallet: AccountInfo<'info>,
    escrow_wallet_of_rents: AccountInfo<'info>,
    wallet_to_withdraw_rents_from: AccountInfo<'info>,
    borrower: AccountInfo<'info>, 
    lender: AccountInfo<'info>,                   
    mint_of_nft_for_lending: AccountInfo<'info>,
    mint_of_token_for_pay_rents: AccountInfo<'info>,
    token_program: AccountInfo<'info>,
) -> Result<()> {

    // transfer nft to escrowed wallet
    let lend_key =lender.key().clone();
    let mint_of_nft_for_lending_key = mint_of_nft_for_lending.key().clone();
    let mint_of_token_for_pay_rents_key = mint_of_token_for_pay_rents.key().clone();
    let bump_vecs = state_bump.to_le_bytes();
    let idx_bytes = idx.to_le_bytes();

    let inner = vec![
        RENT_STATE_SEED_STR.as_bytes(),
        lend_key.as_ref(),
        mint_of_nft_for_lending_key.as_ref(),
        mint_of_token_for_pay_rents_key.as_ref(),
        idx_bytes.as_ref(),
        bump_vecs.as_ref(),
    ];
    let outer = vec![inner.as_slice()];

    let transfer_instruction = Transfer{
        from: wallet_to_withdraw_rents_from.to_account_info(),
        to:escrow_wallet_of_rents.to_account_info(),
        authority: borrower.to_account_info(),
    };
    let cpi_ctx = CpiContext::new_with_signer(
        token_program.to_account_info(),
        transfer_instruction,
        outer.as_slice(),
    );

    anchor_spl::token::transfer(cpi_ctx, rent_amount)?;

    let bump_vecs = pool_bump.to_le_bytes();
    let inner = vec![
        WALLET_OF_PLAT_COMMISSION_SEED_STR.as_bytes(),
        mint_of_token_for_pay_rents_key.as_ref(),
        bump_vecs.as_ref(),
    ];
    let outer = vec![inner.as_slice()];
    
    let transfer_instruction = Transfer{
        from: wallet_to_withdraw_rents_from.to_account_info(),
        to:commission_wallet.to_account_info(),
        authority: borrower.to_account_info(),
    };
    let cpi_ctx = CpiContext::new_with_signer(
        token_program.to_account_info(),
        transfer_instruction,
        outer.as_slice(),
    );
    anchor_spl::token::transfer(cpi_ctx, commission_amount)?;

    Ok(())
}


pub fn transfer_rent_to_lender<'info>(
    idx: u64,
    rent_amount: u64,
    state_bump: u8,
    rent_state: AccountInfo<'info>,
    escrow_wallet_of_rents: &mut Account<'info, TokenAccount>,
    wallet_to_collect_rents: AccountInfo<'info>,
    lender: AccountInfo<'info>,                 
    mint_of_nft_for_lending: AccountInfo<'info>, 
    mint_of_token_for_pay_rents: AccountInfo<'info>,
    token_program: AccountInfo<'info>,
) -> Result<()> {

    // transfer nft to escrowed wallet
    let lend_key = lender.key().clone();
    let mint_of_nft_for_lending_key = mint_of_nft_for_lending.key().clone();
    let mint_of_token_for_pay_rents_key = mint_of_token_for_pay_rents.key().clone();
    let bump_vecs = state_bump.to_le_bytes();
    let idx_bytes = idx.to_le_bytes();

    let inner = vec![
        RENT_STATE_SEED_STR.as_bytes(),
        lend_key.as_ref(),
        mint_of_nft_for_lending_key.as_ref(),
        mint_of_token_for_pay_rents_key.as_ref(),
        idx_bytes.as_ref(),
        bump_vecs.as_ref(),
    ];
    let outer = vec![inner.as_slice()];

    let transfer_instruction = Transfer{
        from: escrow_wallet_of_rents.to_account_info(),
        to: wallet_to_collect_rents.to_account_info(),
        authority: rent_state.to_account_info(),
    };
    let cpi_ctx = CpiContext::new_with_signer(
        token_program.to_account_info(),
        transfer_instruction,
        outer.as_slice(),
    );

    anchor_spl::token::transfer(cpi_ctx, rent_amount)?;

  Ok(())
}

pub fn transfer_commission_to_dest_account<'info>(
    rent_amount: u64,
    pool_bump: u8,
    commission_pool: AccountInfo<'info>,
    commission_wallet: AccountInfo<'info>,
    wallet_to_collect_commission: AccountInfo<'info>,
    _dest: AccountInfo<'info>,                 
    mint_of_token_for_pay_rents: AccountInfo<'info>,
    token_program: AccountInfo<'info>,
) -> Result<()> {

    // msg!("rent_amount: {}", rent_amount);
    // msg!("pool_bump: {}", pool_bump);
    // msg!("commission_pool: {:?}", commission_pool.to_account_info());
    // msg!("rent_amount: {:?}", commission_wallet.to_account_info());
    // msg!("rent_amount: {:?}", wallet_to_collect_commission.to_account_info());
    // msg!("rent_amount: {:?}", dest.to_account_info());
    // msg!("rent_amount: {:?}", mint_of_token_for_pay_rents.to_account_info());
    // msg!("rent_amount: {:?}", token_program.to_account_info());

    // transfer nft to escrowed wallet
    let mint_of_token_for_pay_rents_key = mint_of_token_for_pay_rents.key().clone();
    let bump_vecs = pool_bump.to_le_bytes();

    let inner = vec![
        POOL_OF_PLAT_COMMISSION_SEED_STR.as_bytes(), 
        mint_of_token_for_pay_rents_key.as_ref(),
        bump_vecs.as_ref(),
    ];
    let outer = vec![inner.as_slice()];

    let transfer_instruction = Transfer{
        from: commission_wallet.to_account_info(),
        to: wallet_to_collect_commission.to_account_info(),
        authority: commission_pool.to_account_info(),
    };
    let cpi_ctx = CpiContext::new_with_signer(
        token_program.to_account_info(),
        transfer_instruction,
        outer.as_slice(),
    );

    anchor_spl::token::transfer(cpi_ctx, rent_amount)?;

    Ok(())
}

pub fn close_rent_escrow_token_account<'info>(
    idx: u64,
    state_bump: u8,
    rent_state: AccountInfo<'info>,
    escrow_wallet_of_rents: &mut Account<'info, TokenAccount>,
    lender: AccountInfo<'info>,                 
    mint_of_nft_for_lending: AccountInfo<'info>, 
    mint_of_token_for_pay_rents: AccountInfo<'info>,
    token_program: AccountInfo<'info>,
) -> Result<()> {

    // transfer nft to escrowed wallet
    let lend_key = lender.key().clone();
    let mint_of_nft_for_lending_key = mint_of_nft_for_lending.key().clone();
    let mint_of_token_for_pay_rents_key = mint_of_token_for_pay_rents.key().clone();
    let bump_vecs = state_bump.to_le_bytes();
    let idx_bytes = idx.to_le_bytes();

    let inner = vec![
        RENT_STATE_SEED_STR.as_bytes(),
        lend_key.as_ref(),
        mint_of_nft_for_lending_key.as_ref(),
        mint_of_token_for_pay_rents_key.as_ref(),
        idx_bytes.as_ref(),
        bump_vecs.as_ref(),
    ];
    let outer = vec![inner.as_slice()];

    let should_close = {
        escrow_wallet_of_rents.reload()?;
        escrow_wallet_of_rents.amount == 0
    };
    // require!(should_close, ErrorCode::RentleftUncollected);

    // If token account has no more tokens, it should be wiped out since it has no other use case.
    if should_close {
        let ca = CloseAccount{
            account: escrow_wallet_of_rents.to_account_info(),
            destination: lender.to_account_info(),
            authority: rent_state.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            token_program.to_account_info(),
            ca,
            outer.as_slice(),
        );
        anchor_spl::token::close_account(cpi_ctx)?;
    }

    Ok(())
}


#[account]
#[derive(Default)]
pub struct RentState {
    // primary key
    pub idx: u64,

    // mint of nft for lending
    pub mint_of_nft_for_lending: Pubkey,

    // The escrow wallet of the nft
    pub escrow_wallet_of_nft: Pubkey,

    // lender of nft
    pub lender: Pubkey,

    // mint of token for paying rents
    pub mint_of_token_for_pay_rents: Pubkey,

    // The escrow wallet of the nft
    pub escrow_wallet_of_rents: Pubkey,

    // borrower of the nft
    pub borrower: Pubkey,

    // parameters of offer
    pub price_per_time_unit: u64,   // price per day
    pub duration_min: i64,     // least renting duration
    pub duration_max: i64,      // max renting duration
    pub extendable: bool,     // if the nft asset can still effect for rent after the latest rent deal
    
    pub expire_clock: i64,
    pub time_unit: i64,

    // The amount of rents paid already
    pub amount_rents: u64,

    // An enumm that is to represent some kind of state machine
    pub stage: u8,
}

#[event]
pub struct EventRentStateUpdate {
    #[index]
    pub label: String,
   
    // primary key
    pub idx: u64,

    // mint of nft for lending
    pub mint_of_nft_for_lending: Pubkey,

    // The escrow wallet of the nft
    pub escrow_wallet_of_nft: Pubkey,

    // lender of nft
    pub lender: Pubkey,

    // mint of token for paying rents
    pub mint_of_token_for_pay_rents: Pubkey,

    // The escrow wallet of the nft
    pub escrow_wallet_of_rents: Pubkey,

    // borrower of the nft
    pub borrower: Pubkey,

    // parameters of offer
    pub price_per_time_unit: u64,   // price per day
    pub duration_min: i64,     // least renting duration
    pub duration_max: i64,      // max renting duration
    pub extendable: bool,     // if the nft asset can still effect for rent after the latest rent deal
    
    pub expire_clock: i64,
    pub time_unit: i64,

    // The amount of rents paid already
    pub amount_rents: u64,

    pub withdraw_rents: u64,
    pub deposit_rents: u64,
    pub commission_gen: u64,
    // An enumm that is to represent some kind of state machine
    pub stage: u8,
}



impl RentState {
    pub const LEN: usize = 8 + 8*7 + 32*6 + 1*2;

    // pub fn state(&self) -> RentStage {
    //     if self.extendable == false {
    //         match RentStage::from(self.stage)? {
    //             RentStage::Occupied => {
    //                 if self.expire_clock < ctx.accounts.clock.unix_timestamp  {
    //                     if self.amount_rents == 0  {self.stage = RentStage::Idle.to_code();}
    //                     else {self.stage = RentStage::IdleWithRentsUncollected.to_code();}
    //                 }
    //             },
    //             RentStage::IdleWithRentsUncollected => {
    //                 if self.amount_rents == 0  {self.stage = RentStage::Idle.to_code();}
    //             },
    //             _ => (),
    //         }
    //     } else {
    //         match RentStage::from(self.stage)? {
    //             RentStage::IdleWithRentsUncollected | RentStage::Idle => {
    //                 panic!("should not be in idle or idle uncollect stage while extensible allowed!");
    //             },
    //             RentStage::Occupied => {
    //                 if self.expire_clock < ctx.accounts.clock.unix_timestamp  {
    //                     self.stage = RentStage::Available.to_code();
    //                 }
    //             },
    //             _ => (),
    //         }
    //     }

    //     RentStage::from(self.stage)  
    // } 
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum RentStage {
    //nft asset available for renting
    Available,

    //nft asset escrowed but not available for renting, rents collected completely
    Idle,

    // rent deal has gone effect
    Occupied,
}

impl RentStage {
    pub fn to_code(&self) -> u8 {
        match self {
            RentStage::Available => 1,
            RentStage::Idle => 2,
            RentStage::Occupied => 3,
        }
    }

    pub fn from(val: u8) -> std::result::Result<RentStage, ProgramError> {
        match val {
            1 => Ok(RentStage::Available),
            2 => Ok(RentStage::Idle),
            3 => Ok(RentStage::Occupied),
            unknown_value => {
                msg!("Unknown stage: {}", unknown_value);
                Err(ErrorCode::RentStageInvalid.into())
            }
        }
    }
}


// 1 State account instance == 1 Safe Pay instance
#[account]
#[derive(Default)]
pub struct SafePayState {

    // A primary key that allows us to derive other important accounts
    pub idx: u64,
    
    // initiator
    pub user_sending: Pubkey,

    // reciever
    pub user_receiving: Pubkey,

    // The Mint of the token that initiator wants to send to reciever
    pub mint_of_token_being_sent: Pubkey,

    // The escrow wallet
    pub escrow_wallet: Pubkey,

    // The amount of tokens to be sent
    pub amount_tokens: u64,

    pub deadline: i64,

    // An enumm that is to represent some kind of state machine
    pub stage: u8,
}

#[event]
pub struct EventSafePay {
    #[index]
    pub label: String,

    // A primary key that allows us to derive other important accounts
    pub idx: u64,

    // initiator
    pub user_sending: Pubkey,

    // reciever
    pub user_receiving: Pubkey,

    // The Mint of the token that initiator wants to send to reciever
    pub mint_of_token_being_sent: Pubkey,

    // The escrow wallet
    pub escrow_wallet: Pubkey,

    // The amount of tokens to be sent
    pub amount_tokens: u64,

    // An enumm that is to represent some kind of state machine
    pub stage: u8,
}

impl SafePayState {
    pub const LEN: usize = 8 + 32*4 + 8*3 + 1;
}

// Each state corresponds with a separate transaction and represents different moments in the lifecycle
// of the app.
//
// FundsDeposited -> EscrowComplete
//                OR
//                -> PullBackComplete
//
#[derive(Clone, Copy, PartialEq)]
pub enum Stage {
    // Safe Pay withdrew funds from Alice and deposited them into the escrow wallet
    FundsDeposited,

    // {from FundsDeposited} Bob withdrew the funds from the escrow. We are done.
    EscrowComplete,

    // {from FundsDeposited} Alice pulled back the funds
    PullBackComplete,
}

impl Stage {
    pub fn to_code(&self) -> u8 {
        match self {
            Stage::FundsDeposited => 1,
            Stage::EscrowComplete => 2,
            Stage::PullBackComplete => 3,
        }
    }

    pub fn from(val: u8) -> std::result::Result<Stage, ProgramError> {
        match val {
            1 => Ok(Stage::FundsDeposited),
            2 => Ok(Stage::EscrowComplete),
            3 => Ok(Stage::PullBackComplete),
            unknown_value => {
                msg!("Unknown stage: {}", unknown_value);
                Err(ErrorCode::StageInvalid.into())
            }
        }
    }
}

#[account]
#[derive(Default)]
pub struct Pool {

    // commitments ratio
    pub ratio_numerator: u64,
    pub ratio_denominator: u64,
    
    // The amount of rents paid already
    pub amount_collected: u64,

    // commission token mint
    pub mint: Pubkey,
}

#[event]
pub struct EventPoolUpdate {
    #[index]
    pub label: String,

    // commission token mint
    pub mint: Pubkey,

    // commitments ratio
    pub ratio_numerator: u64,
    pub ratio_denominator: u64,
    
    // The amount of rents paid already
    pub amount_collected: u64,
    pub withdraw_commissions: u64,
}

impl Pool {
    pub const LEN: usize = 8 + 8*3 + 32*1;
}