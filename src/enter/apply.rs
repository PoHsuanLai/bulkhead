//! Applies an [`EnterPlan`] to the calling process with the `landlock` crate (nothing here is
//! `unsafe`). Best effort by the kernel's ABI, and it says how far it got.

use super::plan::{EnterPlan, LandlockLevel, NetRule};
use landlock::{
    ABI, Access, AccessFs, AccessNet, LandlockStatus, NetPort, RestrictionStatus, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetError, RulesetStatus, path_beneath_rules,
};

/// The newest ABI the crate knows; the kernel gives what it has.
const ABI_TOP: ABI = ABI::V9;
/// The first ABI with TCP rules.
const ABI_NET: ABI = ABI::V4;

/// Restricts this process (and what it execs) to `plan`, and says how far the kernel went.
pub fn apply(plan: &EnterPlan) -> Result<LandlockLevel, RulesetError> {
    let all = AccessFs::from_all(ABI_TOP);
    let device = AccessFs::from_read(ABI_TOP) | AccessFs::WriteFile | AccessFs::IoctlDev;
    let mut ruleset = Ruleset::default().handle_access(all)?;
    if plan.net != NetRule::Unfiltered {
        ruleset = ruleset.handle_access(AccessNet::from_all(ABI_TOP))?;
    }
    let mut created = ruleset
        .create()?
        .add_rules(path_beneath_rules(
            plan.read.iter().map(|p| p.as_str()),
            AccessFs::from_read(ABI_TOP),
        ))?
        .add_rules(path_beneath_rules(
            plan.write.iter().map(|p| p.as_str()),
            all,
        ))?
        .add_rules(path_beneath_rules(
            plan.device.iter().map(|p| p.as_str()),
            device,
        ))?;
    if let NetRule::ConnectTo(port) = plan.net {
        created = created.add_rule(NetPort::new(port, AccessNet::ConnectTcp))?;
    }
    let status = created.restrict_self()?;
    Ok(level_of(&status, plan.net))
}

/// What the kernel's answer means for the plan that was asked.
fn level_of(status: &RestrictionStatus, net: NetRule) -> LandlockLevel {
    let net_rules = matches!(
        status.landlock,
        LandlockStatus::Available { effective_abi, .. } if effective_abi >= ABI_NET
    );
    match (&status.ruleset, net) {
        (RulesetStatus::NotEnforced, _) => LandlockLevel::None,
        (_, NetRule::Unfiltered) => LandlockLevel::Full,
        _ if net_rules => LandlockLevel::Full,
        _ => LandlockLevel::FilesOnly,
    }
}
