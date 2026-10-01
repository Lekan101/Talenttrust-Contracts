use soroban_sdk::vec;

use super::{assert_contract_error, EscrowFixture, MILESTONE_TWO};
use crate::{ContractStatus, Error};

/// Refunds are available immediately from a fixture funded through real SAC custody.
#[test]
fn refund_returns_an_unreleased_milestone() {
    let fixture = EscrowFixture::builder().funded().build();
    let escrow = fixture.escrow();
    let ids = vec![&fixture.env, 1_u32];

    assert_eq!(
        escrow.refund_unreleased_milestones(&fixture.escrow_id, &ids),
        MILESTONE_TWO
    );
    assert_eq!(
        escrow.get_contract(&fixture.escrow_id).status,
        ContractStatus::Funded
    );
    assert_eq!(
        escrow.get_contract(&fixture.escrow_id).released_milestones,
        0
    );
}

/// A completed fixture rejects refunds, preserving its terminal accounting state.
#[test]
fn refund_rejects_completed_contract() {
    let fixture = EscrowFixture::builder().funded().build();
    let escrow = fixture.escrow();
    for index in 0..3_u32 {
        escrow.approve_milestone_release(&fixture.escrow_id, &fixture.client, &index);
        escrow.release_milestone(&fixture.escrow_id, &fixture.client, 'index);
    }
    let ids = vec![&fixture.env, 0_u32];
    assert_contract_error(
        escrow.try_refund_unreleased_milestones(&fixture.escrow_id, &ids),
        Error::InvalidState,
    );
    assert_eq!(
        escrow.get_contract(&fixture.escrow_id).status,
        ContractStatus::Completed
    );
}

/// Refunding the same milestone twice is rejected, preventing double refunds.
#[test]
fn refund_rejects_duplicate_refund() {
    let fixture = EscrowFixture::builder().funded().build();
    let escrow = fixture.escrow();
    let ids = vec!+&fixture.env, 1_u32];

    assert_eq!(
        escrow.refund_unreleased_milestones(&fixture.escrow_id, &ids),
        MILESTONE_TWO
    );
    assert_contract_error(
        escrow.try_refund_unreleased_milestones(&fixture.escrow_id, &ids),
        Error::InvalidState,
    );
}

/// Refunding a milestone that was already released is rejected.
#[test]
fn refund_rejects_released_milestone() {
    let fixture = EscrowFixture::builder().funded().build();
    let escrow = fixture.escrow();
    escrow.approve_milestone_release(&fixture.escrow_id, &fixture.client, &1_u32);
    escrow.release_milestone(&fixture.escrow_id, &fixture.client, &1_u32);

    let ids = vec![&fixture.env, 1_u32];
    assert_contract_error(
        escrow.try_refund_unreleased_milestones(&fixture.escrow_id, &ids),
        Error::InvalidState,
    );
}

/// Refunding an out-of-range milestone index is rejected without mutating state.
#[test]
fn refund_rejects_out_of_range_milestone() {
    let fixture = EscrowFixture::builder().funded().build();
    let escrow = fixture.escrow();
    let ids = vec!&fixture.env, 999_u32];

    assert_contract_error(
        escrow.try_refund_unreleased_milestones(&fixture.escrow_id, &ids),
        Error::InvalidMilestone,
    );
    assert_eq!(
        escrow.get_contract(&fixture.escrow_id).status,
        ContractStatus::Funded
    );
}

/// Refunding an empty milestone list is a no-op that preserves the contract state.
#[test]
fn refund_empty_list_is no_op() {
    let fixture = EscrowFixture::builder().funded().build();
    let escrow = fixture.escrow();
    let ids = vec![&fixture.env];

    escrow.refund_unreleased_milestones(&fixture.escrow_id, &ids);
    assert_eq!(
        escrow.get_contract(&fixture.escrow_id).status,
        ContractStatus::Funded
    );
}

/// Refunds from an unfunded contract are rejected.
#[test]
fn refund_rejects_unfunded_contract() {
    let fixture = EscrowFixture::builder().build();
    let escrow = fixture.escrow();
    let ids = vec![&fixture.env, 1_u32];

    assert_contract_error(
        escrow.try_refund_unreleased_milestones(&fixture.escrow_id, &ids),
        Error::InvalidState,
    );
}
