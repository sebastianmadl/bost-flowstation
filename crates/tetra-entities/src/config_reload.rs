//! Live configuration reload: apply a changed `config.toml` to the running station without a
//! restart. Every cell's [`SharedConfig`] is swapped for the new snapshot; entities that read the
//! config per use see it at once, the ones that cache derived values (UMAC broadcast PDUs and
//! cipher) rebuild when [`SharedConfig::config_generation`] changes.
//!
//! What cannot change at run time is listed by [`restart_reasons`]: the SDR and everything that
//! retunes it, the set of cells, and the
//! network connections opened at start-up (Brew, LST) and the dashboard listener. A change in any of those is not applied at all
//! (all or nothing), so the running station never ends up half on the old file and half on the
//! new one; the caller then restarts as before.

use tetra_config::bluestation::{debug_with_secrets, SharedConfig, StackConfig};
use tetra_core::CellId;

/// Set by the start-up code when the Asterisk entity exists. With it, Asterisk settings (including
/// switching it off and on again) apply live; without it, switching it on needs a restart because
/// there is nothing to switch on.
pub static ASTERISK_RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set by the start-up code when the LST dispatch entity exists. Like [`ASTERISK_RUNNING`]: with it
/// the console's settings apply live, without it switching it on needs a restart.
pub static LST_RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Result of [`reload`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReloadReport {
    /// Cells whose configuration was swapped.
    pub cells: usize,
    /// Settings that need a restart; when non-empty nothing was applied.
    pub restart: Vec<String>,
}

/// Compares the full values, secrets included (a changed password or key is a change).
fn differs<T: std::fmt::Debug>(a: &T, b: &T) -> bool {
    debug_with_secrets(a) != debug_with_secrets(b)
}

/// The SDR settings that cannot change live: everything but the gains, the antennas (while
/// set) and the ppm correction; on an SDR of its own (`own`) also the frequencies, which follow
/// the cell's carrier.
fn soapy_fixed_for(s: &tetra_config::bluestation::sec_phy_soapy::CfgSoapySdr, own: bool) -> String {
    let mut s = s.clone();
    if own {
        s.ul_freq = 0.0;
        s.dl_freq = 0.0;
        s.rx_center_freq = None;
        s.tx_center_freq = None;
    }
    s.rx_gains.clear();
    s.tx_gains.clear();
    s.rx_ant = s.rx_ant.as_ref().map(|_| String::new());
    s.tx_ant = s.tx_ant.as_ref().map(|_| String::new());
    s.ppm_err = 0.0;
    debug_with_secrets(&s)
}

/// A gain that is no longer set would go back to a device default the station does not know.
fn gain_removed(old: Option<&tetra_config::bluestation::sec_phy_soapy::CfgSoapySdr>, new: Option<&tetra_config::bluestation::sec_phy_soapy::CfgSoapySdr>) -> bool {
    match (old, new) {
        (Some(o), Some(n)) => o.rx_gains.keys().any(|k| !n.rx_gains.contains_key(k)) || o.tx_gains.keys().any(|k| !n.tx_gains.contains_key(k)),
        _ => false,
    }
}

fn soapy_fixed(s: &tetra_config::bluestation::sec_phy_soapy::CfgSoapySdr) -> String {
    soapy_fixed_for(s, false)
}

fn sdr_fixed(p: &tetra_config::bluestation::CfgPhyIo, own: bool) -> String {
    let mut p = p.clone();
    let soapy = p.soapysdr.take();
    format!("{} {:?}", debug_with_secrets(&p), soapy.as_ref().map(|s| soapy_fixed_for(s, own)))
}

/// Cells that share their SDR with another cell (same `device`), as `open_shared_sdrs` groups
/// them at start-up.
fn shared_sdr_cells(c: &StackConfig) -> std::collections::HashSet<CellId> {
    let device = |s: Option<&tetra_config::bluestation::sec_phy_soapy::CfgSoapySdr>| {
        s.and_then(|s| s.device.as_deref()).map(|d| d.trim().to_string()).filter(|d| !d.is_empty())
    };
    let cells: Vec<(CellId, Option<String>)> = std::iter::once((CellId::PRIMARY, device(c.phy_io.soapysdr.as_ref())))
        .chain(c.extra_cells.iter().map(|x| (x.id, device(x.soapysdr.as_ref()))))
        .collect();
    cells
        .iter()
        .filter(|(id, d)| d.is_some() && cells.iter().any(|(o, od)| o != id && od == d))
        .map(|(id, _)| *id)
        .collect()
}

/// Why `new` cannot replace `old` without a restart (empty = it can).
pub fn restart_reasons(old: &StackConfig, new: &StackConfig) -> Vec<String> {
    let mut r = Vec::new();
    let mut check = |changed: bool, what: &str| {
        if changed {
            r.push(what.to_string());
        }
    };
    // The SDR and its settings. Gains, antennas and the ppm correction follow live on the
    // running SDR (`RxTxDevSoapySdr::follow_config`); a gain or antenna that is removed would go
    // back to a device default the station does not know, so that restarts.
    // A cell on an SDR of its own may also move to another carrier (the SDR retunes, the cell
    // rebuilds as for a new colour code); cells sharing an SDR keep theirs.
    let shared = {
        let mut s = shared_sdr_cells(old);
        s.extend(shared_sdr_cells(new));
        s
    };
    let own = |id: CellId| !shared.contains(&id);
    check(differs(&sdr_fixed(&old.phy_io, own(CellId::PRIMARY)), &sdr_fixed(&new.phy_io, own(CellId::PRIMARY))), "SDR / hardware (phy_io)");
    let removed = gain_removed(old.phy_io.soapysdr.as_ref(), new.phy_io.soapysdr.as_ref())
        || old.extra_cells.iter().any(|o| gain_removed(o.soapysdr.as_ref(), new.extra_cells.iter().find(|n| n.id == o.id).and_then(|n| n.soapysdr.as_ref())));
    check(removed, "an SDR gain removed (back to the device default)");
    check(differs(&old.stack_mode, &new.stack_mode), "stack_mode");
    // Radio parameters of every cell that retune the SDR or seed the scrambling code.
    let rf = |c: &StackConfig| {
        c.cells()
            .iter()
            .map(|(id, cell, _)| {
                if own(*id) {
                    // Retuned live: only whether there is a second carrier must stay.
                    return format!("{id:?} own SDR, secondary {}", cell.secondary_carrier.is_some());
                }
                format!(
                    "{:?}",
                    (
                        *id,
                        cell.main_carrier,
                        cell.secondary_carrier,
                        cell.freq_band,
                        cell.freq_offset_hz,
                        cell.duplex_spacing_id,
                        cell.custom_duplex_spacing,
                        cell.reverse_operation,
                    )
                )
            })
            .collect::<Vec<_>>()
    };
    check(differs(&rf(old), &rf(new)), "carrier or frequency plan of a cell on a shared SDR, or a second carrier added or removed");
    // The cell's identity on air (colour code, MCC/MNC) follows live: every radio loses the
    // cell and registers anew (TS 100 392-2 clauses 8.2.5.2, 16.4.1.0), so each cell rebuilds its
    // registrations and calls in place (MM `reset_registrations`, CMCE `follow_cell_identity`)
    // while the other cells and the station keep running.
    // Air interface encryption. Changing the security class or the cell's keys while radios are
    // registered needs the change to be announced to them first with D-CK CHANGE DEMAND at an
    // agreed slot, with SYSINFO changing in step (EN 300 392-7 clauses 4.5.5.6 and 4.5.6); a
    // silent switch leaves registered radios on the old class and key. Until that procedure is
    // driven from a reload, these settings restart the station (every radio registers again).
    // Who may register (whitelist, limits) and the subscriber keys K stay live: K is only used at
    // the next authentication (clause 4.4).
    let air = |sec: &tetra_config::bluestation::CfgSecurity| {
        sec.aie.as_ref().map(|a| (a.security_class(), a.ksg, a.sckn, a.sck_vn, a.sck.clone(), a.class3.as_ref().map(|c| (c.cck_id, c.cck.clone()))))
    };
    let cell_air = |c: &StackConfig| {
        (
            air(&c.security),
            c.extra_cells.iter().map(|x| (x.id, x.security.as_ref().map(air))).collect::<Vec<_>>(),
        )
    };
    check(differs(&cell_air(old), &cell_air(new)), "air interface encryption: security class or cipher keys");
    check(
        differs(
            &old.extra_cells.iter().map(|c| (c.id, c.soapysdr.as_ref().map(|s| soapy_fixed_for(s, own(c.id))))).collect::<Vec<_>>(),
            &new.extra_cells.iter().map(|c| (c.id, c.soapysdr.as_ref().map(|s| soapy_fixed_for(s, own(c.id))))).collect::<Vec<_>>(),
        ),
        "additional cells or their SDRs",
    );
    // Connections and listeners opened once at start-up.
    // The dashboard's login, public overview and private-HTTP allowlist follow live; the sockets
    // it listens on do not (a wrong port would cut off the only management channel).
    let listener = |c: &StackConfig| c.dashboard.as_ref().map(|d| (d.port, d.https_port, d.bind.clone(), d.source_dir.clone()));
    check(differs(&listener(old), &listener(new)), "dashboard listener (bind address, ports, source_dir)");
    // Brew settings follow live. The network layout is live on a station of one cell: networks no
    // cell serves are only configuration, and the primary's core link is attached or dropped
    // through the router. With several cells the links between them (site switch, cell links) are
    // built once at start-up, so any change of layout restarts.
    let lst_on = |c: &StackConfig| c.lst_dispatch.as_ref().is_some_and(|l| l.enabled);
    let single = old.extra_cells.is_empty() && new.extra_cells.is_empty();
    let link_change = old.brew.is_some() != new.brew.is_some();
    let layout = |c: &StackConfig| (c.networks_explicit, c.network.clone(), c.networks.iter().map(|n| (n.name.clone(), n.brew.is_some(), n.via.clone())).collect::<Vec<_>>(), c.extra_cells.iter().map(|x| (x.id, x.network.clone())).collect::<Vec<_>>());
    if single {
        check(old.network != new.network, "the network the cell serves");
        check(link_change && (lst_on(old) || lst_on(new)), "core link and LST dispatch exchange the Brew slot");
        check(link_change && !crate::network_swap::available(), "core link gained or lost (not available on this station)");
    } else {
        check(differs(&layout(old), &layout(new)), "networks: added, removed, or a network gaining or losing its Brew link (several cells)");
    }
    check(
        new.lst_dispatch.as_ref().is_some_and(|l| l.enabled)
            && differs(&old.lst_dispatch, &new.lst_dispatch)
            && !LST_RUNNING.load(std::sync::atomic::Ordering::Relaxed),
        "LST dispatch (not running: it was off at start-up)",
    );
    check(
        new.asterisk.enabled && differs(&old.asterisk, &new.asterisk) && !ASTERISK_RUNNING.load(std::sync::atomic::Ordering::Relaxed),
        "Asterisk bridge (not running: it was off at start-up)",
    );
    r
}

/// Apply `new` (already parsed, validated and given its sibling neighbours) to the primary cell
/// and to every additional cell. Returns the settings that block a live reload without applying
/// anything, or the number of cells swapped.
pub fn reload(primary: &SharedConfig, extra: &[(CellId, SharedConfig)], new: StackConfig) -> Result<ReloadReport, String> {
    reload_with(primary, extra, new, &|_| {})
}

/// [`reload`] with a hook that completes each additional cell's derived config before it is
/// validated and swapped (key management gives every cell the server key of its own LA, the
/// same as at start-up).
pub fn reload_with(
    primary: &SharedConfig,
    extra: &[(CellId, SharedConfig)],
    new: StackConfig,
    prepare_cell: &dyn Fn(&mut StackConfig),
) -> Result<ReloadReport, String> {
    let old = primary.config();
    let single_cell = old.extra_cells.is_empty() && new.extra_cells.is_empty();
    let restart = restart_reasons(&old, &new);
    if !restart.is_empty() {
        return Ok(ReloadReport { cells: 0, restart });
    }
    // Build every cell's config first so a bad one fails before anything is swapped.
    let mut derived = Vec::new();
    for (id, shared) in extra {
        let mut cell = new.for_extra_cell(*id).ok_or_else(|| format!("cell {id:?} is not in the new configuration"))?;
        prepare_cell(&mut cell);
        cell.validate()?;
        derived.push((shared, cell));
    }
    new.validate()?;
    if differs(&old.security, &new.security) || differs(&old.extra_cells.iter().map(|c| &c.security).collect::<Vec<_>>(), &new.extra_cells.iter().map(|c| &c.security).collect::<Vec<_>>()) {
        tracing::info!("Registration rules or subscriber keys changed live; they apply from each radio's next registration");
    }
    let (log_changed, name_changed) = (differs(&old.debug_log, &new.debug_log), differs(&old.service_name, &new.service_name));
    let (log_file, service_name) = (new.debug_log.clone(), new.service_name.clone());
    let dashboard = new.dashboard.clone();
    let link = (old.brew.is_some(), new.brew.is_some());
    primary.replace_config(new)?;
    match link {
        (false, true) if single_cell => {
            tracing::info!("Core link gained: starting the Brew entity");
            crate::network_swap::attach(primary);
        }
        (true, false) if single_cell => {
            tracing::info!("Core link removed: stopping the Brew entity");
            crate::network_swap::detach(primary);
            crate::health::registry().set_brew_configured(false);
        }
        _ => {}
    }
    if link == (false, true) {
        crate::health::registry().set_brew_configured(true);
    }
    crate::net_dashboard::server::apply_live_credentials(dashboard.as_ref());
    if log_changed && let Err(e) = tetra_core::debug::set_log_file(log_file.as_deref()) {
        tracing::warn!("debug_log: {e}; keeping the previous log file");
    }
    if name_changed {
        match service_name.as_deref() {
            Some(name) => crate::service_control::set_configured_service_unit(name),
            None => crate::service_control::clear_configured_service_unit(),
        }
    }
    let cells = 1 + derived.len();
    for (shared, cell) in derived {
        shared.replace_config(cell)?;
    }
    tracing::info!("Configuration reloaded live ({cells} cell(s))");
    Ok(ReloadReport { cells, restart: Vec::new() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tetra_config::bluestation::parsing;

    fn base() -> StackConfig {
        parsing::from_toml_str(include_str!("../../../example_config/config.toml")).expect("example config parses")
    }

    #[test]
    fn identical_config_needs_no_restart() {
        assert!(restart_reasons(&base(), &base()).is_empty());
    }

    #[test]
    fn rf_change_that_cannot_retune_needs_restart_and_is_not_applied() {
        let shared = SharedConfig::from_parts(base(), None);
        let mut new = base();
        new.cell.secondary_carrier = Some(new.cell.main_carrier + 2);
        let report = reload(&shared, &[], new).unwrap();
        assert!(!report.restart.is_empty(), "a second carrier needs another channelizer");
        assert_eq!(shared.config_generation(), 0);
        let mut fs = base();
        fs.phy_io.soapysdr.as_mut().unwrap().fs = Some(2_000_000.0);
        assert!(!restart_reasons(&base(), &fs).is_empty(), "sample rate");
    }

    #[test]
    fn a_cell_on_its_own_sdr_moves_to_another_carrier_live() {
        let mut new = base();
        new.cell.main_carrier += 2;
        let (_, dl, ul) = new.bs_phase_mod_carriers().unwrap()[0];
        let s = new.phy_io.soapysdr.as_mut().unwrap();
        s.dl_freq = dl as f64;
        s.ul_freq = ul as f64;
        new.validate().unwrap();
        assert!(restart_reasons(&base(), &new).is_empty(), "{:?}", restart_reasons(&base(), &new));
    }

    fn aie(class: u8, key: u8) -> tetra_config::bluestation::CfgAie {
        tetra_config::bluestation::CfgAie {
            class3: (class == 3).then(|| tetra_config::bluestation::CfgClass3 { cck: tetra_config::bluestation::CipherKey([key; 10]), cck_id: 1 }),
            enabled: class >= 2,
            ksg: 1,
            sckn: 0,
            sck: tetra_config::bluestation::CipherKey([key; 10]),
            sck_vn: 1,
            clear_groups: Vec::new(),
        }
    }

    #[test]
    fn colour_code_and_network_code_apply_live_as_a_cell_rebuild() {
        let mut cc = base();
        cc.cell.colour_code = (cc.cell.colour_code + 1) % 64;
        assert!(restart_reasons(&base(), &cc).is_empty(), "{:?}", restart_reasons(&base(), &cc));
        let mut mcc = base();
        mcc.net.mcc = (mcc.net.mcc + 1) & 0x3FF;
        assert!(restart_reasons(&base(), &mcc).is_empty());
        let mut mnc = base();
        mnc.net.mnc = (mnc.net.mnc + 1) & 0x3FFF;
        let shared = SharedConfig::from_parts(base(), None);
        let report = reload(&shared, &[], mnc).unwrap();
        assert!(report.restart.is_empty());
        assert_eq!(shared.config().net.mnc, (base().net.mnc + 1) & 0x3FFF);
    }

    #[test]
    fn security_class_and_cipher_keys_need_a_restart_registration_rules_do_not() {
        let mut old = base();
        old.security.aie = Some(aie(2, 1));
        for (what, new_aie) in [("class 2 -> 3", Some(aie(3, 1))), ("class 2 -> 1", None), ("new SCK", Some(aie(2, 2)))] {
            let mut new = old.clone();
            new.security.aie = new_aie;
            assert!(!restart_reasons(&old, &new).is_empty(), "{what} must not switch silently");
        }
        let mut rules = old.clone();
        rules.security.issi_whitelist.push(1234567);
        rules.security.max_registered_clients += 1;
        assert!(restart_reasons(&old, &rules).is_empty(), "{:?}", restart_reasons(&old, &rules));
    }

    #[test]
    fn gains_antennas_and_ppm_apply_live_other_sdr_settings_restart() {
        let mut old = base();
        let soapy = old.phy_io.soapysdr.get_or_insert_with(|| panic!("example config has an SDR"));
        soapy.rx_gains.insert("LNA".into(), 20.0);
        soapy.rx_ant = Some("LNAL".into());
        let mut live = old.clone();
        {
            let s = live.phy_io.soapysdr.as_mut().unwrap();
            s.rx_gains.insert("LNA".into(), 30.0);
            s.tx_gains.insert("PAD".into(), 40.0);
            s.rx_ant = Some("LNAW".into());
            s.ppm_err += 1.5;
        }
        assert!(restart_reasons(&old, &live).is_empty(), "{:?}", restart_reasons(&old, &live));
        let mut removed = old.clone();
        removed.phy_io.soapysdr.as_mut().unwrap().rx_ant = None;
        assert!(!restart_reasons(&old, &removed).is_empty(), "back to an unknown device default");
        let mut gone = old.clone();
        gone.phy_io.soapysdr.as_mut().unwrap().rx_gains.clear();
        assert!(!restart_reasons(&old, &gone).is_empty());
        let mut device = old.clone();
        device.phy_io.soapysdr.as_mut().unwrap().device = Some("driver=other".into());
        assert!(!restart_reasons(&old, &device).is_empty());
    }

    #[test]
    fn a_changed_password_is_a_change() {
        let mut new = base();
        new.asterisk.password = tetra_config::bluestation::SecretField::from("other".to_string());
        assert!(differs(&base().asterisk, &new.asterisk), "the redacted Debug form hides the password");
        assert!(!format!("{:?}", new.asterisk).contains("other"), "plain Debug still redacts");
    }

    #[test]
    fn services_apply_live() {
        let mut new = base();
        new.telemetry = None;
        new.control = None;
        new.telegram = None;
        new.health.enabled = !new.health.enabled;
        assert!(restart_reasons(&base(), &new).is_empty(), "{:?}", restart_reasons(&base(), &new));
    }

    #[test]
    fn log_file_service_name_and_dashboard_login_apply_live() {
        let mut new = base();
        new.debug_log = Some("/tmp/flowstation-test.log".into());
        new.service_name = Some("tetra".into());
        if let Some(d) = new.dashboard.as_mut() {
            d.username = Some("op".into());
            d.password = Some("secret".into());
            d.public_overview = !d.public_overview;
        }
        assert!(restart_reasons(&base(), &new).is_empty(), "{:?}", restart_reasons(&base(), &new));
    }

    #[test]
    fn dashboard_ports_and_a_brew_link_appearing_still_need_a_restart() {
        let mut ports = base();
        if let Some(d) = ports.dashboard.as_mut() {
            d.https_port += 1;
            assert!(!restart_reasons(&base(), &ports).is_empty());
        }
        let mut brew = base();
        if brew.brew.is_some() {
            brew.brew = None;
            assert!(!restart_reasons(&base(), &brew).is_empty(), "removing the core link changes which entities exist");
        }
    }

    #[test]
    fn a_network_no_cell_serves_is_only_configuration_on_one_cell() {
        let mut new = base();
        new.networks.push(tetra_config::bluestation::CfgNetwork {
            name: "spare".into(),
            net: new.net.clone(),
            brew: None,
            via: None,
        });
        assert!(restart_reasons(&base(), &new).is_empty(), "{:?}", restart_reasons(&base(), &new));
    }

    #[test]
    fn plain_setting_applies_live_and_bumps_generation() {
        let shared = SharedConfig::from_parts(base(), None);
        let clone = shared.clone();
        let mut new = base();
        new.cell.location_area = new.cell.location_area.wrapping_add(1) & 0x3FFF;
        let la = new.cell.location_area;
        let report = reload(&shared, &[], new).unwrap();
        assert_eq!(report, ReloadReport { cells: 1, restart: Vec::new() });
        assert_eq!(clone.config().cell.location_area, la, "every clone sees the new snapshot");
        assert_eq!(clone.config_generation(), 1);
    }
}
