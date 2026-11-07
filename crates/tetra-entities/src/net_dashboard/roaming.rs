//! Dashboard "Roaming" page: cell reselection parameters, location areas, presence checks and
//! the neighbour cell list of every cell of the station.
//!
//! Reads the config file (what is configured) and the running config (effective values, sibling
//! cells added at boot). Saving edits the config file: the prospective config is parsed and
//! validated before it is written, and the station restarts to apply it (as the Cells card does).

use serde_json::{Map, Value as JsonValue, json};
use tetra_config::bluestation::{SharedConfig, parsing};
use tetra_core::CellId;
use toml::{Table, Value as TomlValue};

/// Brew extensions shown as server features: the ones this station uses (FlowStation ↔ brew-server, opt-in), plus `issi-check`, which a brew-server answers for another server's Multi Network link.
const HANDOVER_EXTENSIONS: &[&str] = &["bts-info", "handover-v1", "ms-cell", "ms-moved", "ms-reselection", "call-restore", "call-handoff", "cell-directory", "group-access", "issi-check"];

/// Integer neighbour keys with their maximum (field widths, TS 100 392-2 table 18.64).
const NEIGHBOUR_INT_KEYS: &[(&str, i64)] = &[
    ("cell_identifier_ca", 31),
    ("cell_reselection_types_supported", 3),
    ("cell_load_ca", 3),
    ("main_carrier_number", 4095),
    ("main_carrier_number_extension", 1023),
    ("mcc", 1023),
    ("mnc", 16383),
    ("location_area", 16383),
    ("maximum_ms_transmit_power", 7),
    ("minimum_rx_access_level", 15),
    ("subscriber_class", 65535),
    ("timeshare_cell_information_or_security_parameters", 31),
    ("tdma_frame_offset", 63),
];
/// Neighbour keys a radio must have; the others are optional (absent = not broadcast).
const NEIGHBOUR_REQUIRED: &[&str] = &["cell_identifier_ca", "cell_reselection_types_supported", "cell_load_ca", "main_carrier_number"];
/// BS service details flags (table 18.26), all booleans.
const SERVICE_DETAILS: &[&str] = &[
    "registration",
    "deregistration",
    "priority_cell",
    "no_minimum_mode",
    "migration",
    "system_wide_services",
    "voice_service",
    "circuit_mode_data_service",
    "sndcp_service",
    "aie_service",
    "advanced_link",
];
/// `[cell_info.cell_reselect]` keys (dB, 0-30 in 2 dB steps; clause 18.5.4).
const RESELECT_KEYS: &[&str] = &["slow_threshold_db", "fast_threshold_db", "slow_hysteresis_db", "fast_hysteresis_db"];

fn toml_to_json(v: &TomlValue) -> JsonValue {
    match v {
        TomlValue::String(s) => json!(s),
        TomlValue::Integer(i) => json!(i),
        TomlValue::Float(f) => json!(f),
        TomlValue::Boolean(b) => json!(b),
        TomlValue::Datetime(d) => json!(d.to_string()),
        TomlValue::Array(a) => JsonValue::Array(a.iter().map(toml_to_json).collect()),
        TomlValue::Table(t) => JsonValue::Object(t.iter().map(|(k, v)| (k.clone(), toml_to_json(v))).collect()),
    }
}

fn cell_info_table(table: &Table) -> Option<&Table> {
    table.get("cell_info").and_then(|v| v.as_table())
}

/// The `[[cells]]` entry with `id` in the file.
fn extra_cell_entry(table: &Table, id: u8) -> Option<&Table> {
    table
        .get("cells")?
        .as_array()?
        .iter()
        .filter_map(|c| c.as_table())
        .find(|c| c.get("id").and_then(|v| v.as_integer()) == Some(id as i64))
}

fn neighbours_in(cell_info: Option<&Table>) -> Option<JsonValue> {
    cell_info.and_then(|t| t.get("neighbor_cells_ca")).map(toml_to_json)
}

/// GET /api/roaming payload.
pub fn roaming_json(config_path: &str, shared: Option<&SharedConfig>) -> Result<JsonValue, String> {
    let text = std::fs::read_to_string(config_path).map_err(|e| format!("cannot read config: {e}"))?;
    let table: Table = toml::from_str(&text).map_err(|e| format!("config does not parse: {e}"))?;
    let mut cfg = parsing::from_toml_str(&text).map_err(|e| format!("config does not parse: {e}"))?;
    let configured: Vec<(CellId, Option<JsonValue>)> = std::iter::once((CellId::PRIMARY, neighbours_in(cell_info_table(&table))))
        .chain(cfg.extra_cells.iter().map(|c| {
            let own = extra_cell_entry(&table, c.id.0).and_then(|e| e.get("cell_info")).and_then(|v| v.as_table());
            (c.id, neighbours_in(own))
        }))
        .collect();
    // Sibling entries as the cells broadcast them (added at boot).
    cfg.add_sibling_neighbours();
    let carriers: Vec<u16> = cfg.cells().iter().map(|(_, c, _)| c.main_carrier).collect();

    let brew_login = cfg.brew.as_ref().and_then(|b| b.username.clone());
    let cells: Vec<JsonValue> = cfg
        .cells()
        .iter()
        .map(|(id, c, _)| {
            let own = configured.iter().find(|(i, _)| i == id).and_then(|(_, n)| n.clone());
            let la_own = if id.is_primary() {
                true
            } else {
                extra_cell_entry(&table, id.0)
                    .and_then(|e| e.get("cell_info"))
                    .and_then(|v| v.as_table())
                    .is_some_and(|ci| ci.contains_key("location_area"))
            };
            let siblings: Vec<JsonValue> = c
                .neighbor_cells_ca
                .iter()
                .filter(|n| carriers.contains(&n.main_carrier_number))
                .map(|n| json!({"cell_identifier_ca": n.cell_identifier_ca, "main_carrier_number": n.main_carrier_number, "location_area": n.location_area}))
                .collect();
            json!({
                "id": id.0,
                "primary": id.is_primary(),
                "global_id": brew_login.as_ref().map(|login| format!("{login}/{}", id.0)),
                "main_carrier": c.main_carrier,
                // Absolute band plan, to match this cell in the server's cell directory.
                "carrier_ext": tetra_config::bluestation::carrier_band_plan(c),
                "rxlev_access_min_dbm": c.rxlev_access_min_dbm,
                // MS_TXPWR_MAX_CELL code 1-7 = 15-45 dBm (table 18.57), 0 reserved.
                "ms_txpwr_max_dbm": (1..=7).contains(&c.ms_txpwr_max_cell).then(|| 10 + 5 * c.ms_txpwr_max_cell as u16),
                "colour_code": c.colour_code,
                "location_area": c.location_area,
                "location_area_own": la_own,
                "own_list": own.is_some(),
                "neighbours": own.unwrap_or_else(|| json!([])),
                "siblings": siblings,
            })
        })
        .collect();

    let ci = cell_info_table(&table);
    let service_details: Map<String, JsonValue> = {
        let c = &cfg.cell;
        let flags = [
            c.registration,
            c.deregistration,
            c.priority_cell,
            c.no_minimum_mode,
            c.migration,
            // Broadcast while the network link is up (site trunking otherwise).
            c.system_wide_services || cfg.has_network_link(),
            c.voice_service,
            c.circuit_mode_data_service,
            c.sndcp_service,
            c.aie_service,
            c.advanced_link,
        ];
        SERVICE_DETAILS.iter().zip(flags).map(|(k, v)| (k.to_string(), json!(v))).collect()
    };
    let offered: Vec<String> = shared.map(|s| s.state_read().brew_server_extensions.clone()).unwrap_or_default();
    let link_up = shared.is_some_and(|s| s.state_read().brew_link_up);
    let directory = shared.and_then(|s| s.state_read().brew_cell_directory.clone());
    Ok(json!({
        "cells": cells,
        "mcc": cfg.net.mcc,
        "mnc": cfg.net.mnc,
        // The Brew server's cell list (extension `cell-directory`), `null` until one arrived.
        "directory": directory,
        "max_cells": CellId::MAX as usize + 1,
        "reselect": {
            "slow_threshold_db": cfg.cell.cell_reselect.slow_threshold_db,
            "fast_threshold_db": cfg.cell.cell_reselect.fast_threshold_db,
            "slow_hysteresis_db": cfg.cell.cell_reselect.slow_hysteresis_db,
            "fast_hysteresis_db": cfg.cell.cell_reselect.fast_hysteresis_db,
        },
        "rxlev_access_min_dbm": ci.and_then(|t| t.get("rxlev_access_min_dbm")).and_then(|v| v.as_integer()),
        "migration": cfg.cell.migration,
        "presence_check_secs": cfg.cell.presence_check_secs,
        "presence_response_secs": cfg.cell.presence_response_secs,
        "service_details": service_details,
        "brew": {
            "configured": cfg.brew.is_some(),
            "login": brew_login,
            "link_up": link_up,
            "extensions": HANDOVER_EXTENSIONS.iter().map(|e| json!({"name": e, "offered": offered.iter().any(|o| o == e)})).collect::<Vec<_>>(),
        },
    }))
}

fn int_in(v: &JsonValue, what: &str, min: i64, max: i64) -> Result<i64, String> {
    v.as_i64()
        .filter(|n| (min..=max).contains(n))
        .ok_or_else(|| format!("{what} must be {min}-{max}"))
}

/// One neighbour entry from the page, checked key by key.
fn neighbour_to_toml(v: &JsonValue, what: &str) -> Result<TomlValue, String> {
    let obj = v.as_object().ok_or_else(|| format!("{what} must be an object"))?;
    let mut t = Table::new();
    for (key, val) in obj {
        if val.is_null() {
            continue;
        }
        if let Some((_, max)) = NEIGHBOUR_INT_KEYS.iter().find(|(k, _)| k == key) {
            t.insert(key.clone(), TomlValue::Integer(int_in(val, &format!("{what}.{key}"), 0, *max)?));
        } else if key == "neighbor_cell_synchronized" {
            let b = val.as_bool().ok_or_else(|| format!("{what}.{key} must be true/false"))?;
            t.insert(key.clone(), TomlValue::Boolean(b));
        } else if key == "bs_service_details" {
            let flags = val.as_object().ok_or_else(|| format!("{what}.bs_service_details must be an object"))?;
            let mut d = Table::new();
            for (flag, on) in flags {
                if !SERVICE_DETAILS.contains(&flag.as_str()) {
                    return Err(format!("{what}.bs_service_details: unknown flag {flag}"));
                }
                let on = on.as_bool().ok_or_else(|| format!("{what}.bs_service_details.{flag} must be true/false"))?;
                d.insert(flag.clone(), TomlValue::Boolean(on));
            }
            t.insert(key.clone(), TomlValue::Table(d));
        } else {
            return Err(format!("{what}: unknown field {key}"));
        }
    }
    for key in NEIGHBOUR_REQUIRED {
        if !t.contains_key(*key) {
            return Err(format!("{what}.{key} is required"));
        }
    }
    t.entry("neighbor_cell_synchronized").or_insert(TomlValue::Boolean(false));
    Ok(TomlValue::Table(t))
}

fn neighbour_list(v: &JsonValue, what: &str) -> Result<TomlValue, String> {
    let list = v.as_array().ok_or_else(|| format!("{what} must be a list"))?;
    if list.len() > 7 {
        return Err(format!("{what}: at most 7 neighbours (D-NWRK-BROADCAST)"));
    }
    let entries = list
        .iter()
        .enumerate()
        .map(|(i, n)| neighbour_to_toml(n, &format!("{what}[{i}]")))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TomlValue::Array(entries))
}

fn table_mut<'a>(parent: &'a mut Table, key: &str) -> Result<&'a mut Table, String> {
    parent
        .entry(key.to_string())
        .or_insert_with(|| TomlValue::Table(Table::new()))
        .as_table_mut()
        .ok_or_else(|| format!("{key} is not a table"))
}

/// Apply a POST /api/roaming body to the config text. Returns the new text (validated).
///
/// Body: `{"reselect": {4 × dB}, "rxlev_access_min_dbm": N|null, "migration": bool,
/// "presence_check_secs": N, "cells": [{"id": N, "location_area": N|null, "neighbours": [..]|null}]}`.
/// Every key is optional; for a cell, `location_area: null` (extra cells only) inherits the
/// primary's and `neighbours: null` (extra cells only) drops the cell's own list.
pub fn apply_roaming(original: &str, body: &JsonValue) -> Result<String, String> {
    let obj = body.as_object().ok_or_else(|| "body must be a JSON object".to_string())?;
    let mut table: Table = toml::from_str(original).map_err(|e| format!("config does not parse: {e}"))?;
    {
        let cell_info = table_mut(&mut table, "cell_info")?;
        if let Some(r) = obj.get("reselect") {
            let r = r.as_object().ok_or_else(|| "reselect must be an object".to_string())?;
            let section = table_mut(cell_info, "cell_reselect")?;
            for key in RESELECT_KEYS {
                if let Some(v) = r.get(*key) {
                    let db = int_in(v, key, 0, 30)?;
                    if db % 2 != 0 {
                        return Err(format!("{key} must be a multiple of 2 dB"));
                    }
                    section.insert(key.to_string(), TomlValue::Integer(db));
                }
            }
        }
        if let Some(v) = obj.get("rxlev_access_min_dbm") {
            if v.is_null() {
                cell_info.remove("rxlev_access_min_dbm");
            } else {
                let dbm = int_in(v, "rxlev_access_min_dbm", -125, -50)?;
                if dbm % 5 != 0 {
                    return Err("rxlev_access_min_dbm must be in 5 dB steps".into());
                }
                cell_info.insert("rxlev_access_min_dbm".into(), TomlValue::Integer(dbm));
            }
        }
        if let Some(v) = obj.get("migration") {
            let on = v.as_bool().ok_or_else(|| "migration must be true/false".to_string())?;
            if on {
                cell_info.insert("migration".into(), TomlValue::Boolean(true));
            } else {
                cell_info.remove("migration");
            }
        }
        if let Some(v) = obj.get("presence_check_secs") {
            cell_info.insert("presence_check_secs".into(), TomlValue::Integer(int_in(v, "presence_check_secs", 0, 86_400)?));
        }
    }

    for c in obj.get("cells").and_then(|v| v.as_array()).map(Vec::as_slice).unwrap_or_default() {
        let id = c
            .get("id")
            .and_then(|v| v.as_u64())
            .and_then(|v| u8::try_from(v).ok())
            .ok_or_else(|| "cells[].id is required".to_string())?;
        let what = format!("cell {id}");
        let cell_info = if id == 0 {
            table_mut(&mut table, "cell_info")?
        } else {
            let entry = table
                .get_mut("cells")
                .and_then(|v| v.as_array_mut())
                .and_then(|a| a.iter_mut().filter_map(|c| c.as_table_mut()).find(|c| c.get("id").and_then(|v| v.as_integer()) == Some(id as i64)))
                .ok_or_else(|| format!("{what} is not in the config"))?;
            table_mut(entry, "cell_info")?
        };
        if let Some(v) = c.get("location_area") {
            if v.is_null() {
                if id == 0 {
                    return Err("the primary cell needs a location_area".into());
                }
                cell_info.remove("location_area");
            } else {
                cell_info.insert("location_area".into(), TomlValue::Integer(int_in(v, &format!("{what} location_area"), 0, 16383)?));
            }
        }
        if let Some(v) = c.get("neighbours") {
            if v.is_null() || (id == 0 && v.as_array().is_some_and(|a| a.is_empty())) {
                cell_info.remove("neighbor_cells_ca");
            } else {
                cell_info.insert("neighbor_cells_ca".into(), neighbour_list(v, &format!("{what} neighbours"))?);
            }
        }
    }

    let text = toml::to_string_pretty(&table).map_err(|e| e.to_string())?;
    let mut cfg = parsing::from_toml_str(&text).map_err(|e| format!("resulting config does not parse: {e}"))?;
    cfg.validate().map_err(|e| format!("resulting config is invalid: {e}"))?;
    // What the cells will broadcast: own list plus siblings must still fit and stay unique.
    cfg.add_sibling_neighbours();
    for (id, c, _) in cfg.cells() {
        if c.neighbor_cells_ca.iter().any(|n| n.main_carrier_number == c.main_carrier) {
            return Err(format!("cell {}: a neighbour uses the cell's own carrier", id.0));
        }
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
config_version = "0.6"
stack_mode = "Bs"

[phy_io]
backend = "None"

[net_info]
mcc = 901
mnc = 9999

[cell_info]
main_carrier = 1521
freq_band = 4
freq_offset = 0
duplex_spacing = 4
reverse_operation = false
location_area = 1

[brew]
host = "brew.example"
port = 3000
tls = false
username = 1000001
password = "x"

[[cells]]
id = 1

[cells.cell_info]
main_carrier = 1525
"#;

    fn write(text: &str) -> tempfile_path::Path {
        tempfile_path::Path::new(text)
    }

    mod tempfile_path {
        pub struct Path(pub std::path::PathBuf);
        impl Path {
            pub fn new(text: &str) -> Self {
                let p = std::env::temp_dir().join(format!("roaming-test-{}-{}.toml", std::process::id(), rand_suffix()));
                std::fs::write(&p, text).unwrap();
                Path(p)
            }
            pub fn str(&self) -> &str {
                self.0.to_str().unwrap()
            }
        }
        impl Drop for Path {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        fn rand_suffix() -> u128 {
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        }
    }

    fn neighbour(id: u8, carrier: u16) -> JsonValue {
        json!({
            "cell_identifier_ca": id,
            "cell_reselection_types_supported": 3,
            "cell_load_ca": 0,
            "main_carrier_number": carrier,
            "location_area": 2,
            "minimum_rx_access_level": 5,
            "bs_service_details": {"registration": true, "deregistration": true, "system_wide_services": true, "voice_service": true},
        })
    }

    #[test]
    fn get_shows_cells_siblings_and_effective_values() {
        let f = write(BASE);
        let v = roaming_json(f.str(), None).unwrap();
        let cells = v["cells"].as_array().unwrap();
        assert_eq!(cells.len(), 2);
        assert_eq!(cells[0]["global_id"], "1000001/0");
        assert_eq!(cells[1]["global_id"], "1000001/1");
        assert_eq!(cells[1]["location_area"], 1, "inherited");
        assert_eq!(cells[1]["location_area_own"], false);
        assert_eq!(cells[0]["siblings"][0]["main_carrier_number"], 1525);
        assert_eq!(cells[1]["siblings"][0]["main_carrier_number"], 1521);
        assert_eq!(cells[0]["own_list"], false);
        assert_eq!(v["reselect"]["slow_threshold_db"], 20, "default");
        assert_eq!(v["rxlev_access_min_dbm"], JsonValue::Null);
        assert_eq!(v["brew"]["configured"], true);
    }

    #[test]
    fn get_carries_the_servers_cell_directory_and_what_matching_needs() {
        let f = write(BASE);
        let cfg = parsing::from_toml_str(BASE).unwrap();
        let shared = SharedConfig::from_parts(cfg, None);
        let v = roaming_json(f.str(), Some(&shared)).unwrap();
        assert_eq!(v["directory"], JsonValue::Null, "nothing from the server yet");
        assert_eq!((v["mcc"].as_u64(), v["mnc"].as_u64()), (Some(901), Some(9999)));
        // band 4, offset 0, duplex spacing 4: (4 << 6) | (4 << 1)
        assert_eq!(v["cells"][0]["carrier_ext"], 264);
        assert_eq!(v["cells"][0]["rxlev_access_min_dbm"], -110, "effective value");
        assert!(v["brew"]["extensions"].as_array().unwrap().iter().any(|e| e["name"] == "cell-directory"));
        assert!(v["brew"]["extensions"].as_array().unwrap().iter().any(|e| e["name"] == "group-access"), "shown as a server feature");
        assert!(v["brew"]["extensions"].as_array().unwrap().iter().any(|e| e["name"] == "issi-check"), "Multi Network ISSI check shown too");

        shared.state_write().brew_cell_directory = Some(vec![tetra_config::bluestation::BrewDirectoryCell {
            id: "1000002/0".into(),
            station: "1000002".into(),
            cell: 0,
            online: true,
            last_seen_ms: None,
            mcc: 901,
            mnc: 9999,
            carrier: 1530,
            carrier_ext: 264,
            location_area: 2,
            ms_txpwr_max_dbm: Some(30),
            rxlev_access_min_dbm: Some(-100),
            service_details: None,
            neighbours: Some(vec![]),
        }]);
        let v = roaming_json(f.str(), Some(&shared)).unwrap();
        assert_eq!(v["directory"][0]["id"], "1000002/0");
        assert_eq!(v["directory"][0]["rxlev_access_min_dbm"], -100);
        assert_eq!(v["directory"][0]["neighbours"], json!([]));
    }

    #[test]
    fn save_writes_every_roaming_setting_and_reads_back() {
        let body = json!({
            "reselect": {"slow_threshold_db": 10, "fast_threshold_db": 30, "slow_hysteresis_db": 8, "fast_hysteresis_db": 4},
            "rxlev_access_min_dbm": -100,
            "migration": true,
            "presence_check_secs": 45,
            "cells": [
                {"id": 0, "location_area": 3, "neighbours": [neighbour(5, 1530)]},
                {"id": 1, "location_area": 4, "neighbours": [neighbour(6, 1540), neighbour(7, 1541)]},
            ],
        });
        let text = apply_roaming(BASE, &body).unwrap();
        let mut cfg = parsing::from_toml_str(&text).unwrap();
        cfg.add_sibling_neighbours();
        cfg.validate().unwrap();
        let r = &cfg.cell.cell_reselect;
        assert_eq!((r.slow_threshold_db, r.fast_threshold_db, r.slow_hysteresis_db, r.fast_hysteresis_db), (10, 30, 8, 4));
        assert_eq!(cfg.cell.rxlev_access_min_dbm, -100);
        assert!(cfg.cell.migration);
        assert_eq!(cfg.cell.presence_check_secs, 45);
        assert_eq!(cfg.cell.location_area, 3);
        let carriers = |c: &tetra_config::bluestation::CfgCellInfo| c.neighbor_cells_ca.iter().map(|n| n.main_carrier_number).collect::<Vec<_>>();
        assert_eq!(carriers(&cfg.cell), vec![1530, 1525]);
        let cell1 = &cfg.extra_cells[0].cell;
        assert_eq!(cell1.location_area, 4);
        assert_eq!(carriers(cell1), vec![1540, 1541, 1521]);
        let n = &cfg.cell.neighbor_cells_ca[0];
        assert_eq!((n.cell_identifier_ca, n.cell_reselection_types_supported, n.location_area, n.minimum_rx_access_level), (5, 3, Some(2), Some(5)));
        let d = n.bs_service_details.as_ref().unwrap();
        assert!(d.registration && d.voice_service && d.system_wide_services && !d.migration);
        // The extra cell's sibling entry names the primary's other location area.
        assert_eq!(cell1.neighbor_cells_ca[2].location_area, Some(3));

        // Read back through the page's GET.
        let f = write(&text);
        let v = roaming_json(f.str(), None).unwrap();
        assert_eq!(v["cells"][1]["neighbours"][1]["main_carrier_number"], 1541);
        assert_eq!(v["cells"][1]["own_list"], true);
        assert_eq!(v["rxlev_access_min_dbm"], -100);

        // Back to defaults: inherited LA, no own lists, default access level, no migration.
        let reset = json!({
            "rxlev_access_min_dbm": null,
            "migration": false,
            "cells": [{"id": 0, "neighbours": []}, {"id": 1, "location_area": null, "neighbours": null}],
        });
        let text = apply_roaming(&text, &reset).unwrap();
        let cfg = parsing::from_toml_str(&text).unwrap();
        assert!(cfg.cell.neighbor_cells_ca.is_empty() && cfg.extra_cells[0].cell.neighbor_cells_ca.is_empty());
        assert_eq!(cfg.extra_cells[0].cell.location_area, 3);
        assert!(!text.contains("rxlev_access_min_dbm") && !text.contains("migration"));
    }

    #[test]
    fn bad_input_is_refused_and_nothing_is_written() {
        let bad = [
            json!({"reselect": {"slow_threshold_db": 31}}),
            json!({"reselect": {"fast_threshold_db": 5}}),
            json!({"rxlev_access_min_dbm": -103}),
            json!({"cells": [{"id": 0, "location_area": null}]}),
            json!({"cells": [{"id": 0, "location_area": 16384}]}),
            json!({"cells": [{"id": 9, "location_area": 2}]}),
            json!({"cells": [{"id": 0, "neighbours": [neighbour(1, 1530), neighbour(1, 1531)]}]}),
            json!({"cells": [{"id": 0, "neighbours": [neighbour(1, 1521)]}]}),
            json!({"cells": [{"id": 0, "neighbours": [{"main_carrier_number": 1530}]}]}),
            json!({"cells": [{"id": 0, "neighbours": [{"cell_identifier_ca": 1, "cell_reselection_types_supported": 4, "cell_load_ca": 0, "main_carrier_number": 1530}]}]}),
            json!({"cells": [{"id": 0, "neighbours": [{"cell_identifier_ca": 1, "cell_reselection_types_supported": 1, "cell_load_ca": 0, "main_carrier_number": 1530, "colour": 1}]}]}),
            json!({"cells": [{"id": 0, "neighbours": (0..8).map(|i| neighbour(i, 1530 + i as u16)).collect::<Vec<_>>()}]}),
        ];
        for body in bad {
            assert!(apply_roaming(BASE, &body).is_err(), "accepted {body}");
        }
    }
}
