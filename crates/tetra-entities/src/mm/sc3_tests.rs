use super::*;
use tetra_config::bluestation::sec_security::{CfgAie, CfgClass3, CipherKey, SubscriberKey};
use tetra_pdus::mm::pdus::otar_cck::AuthenticationUplink;
use tetra_security::auth::answer_ms_challenge;
use tetra_security::taa1::{ta11, ta12, ta32};

#[test]
fn r2_returning_radio_pins_registration_transport_and_replaces_dck_after_ack() {
    for encrypted in [false, true] {
        let mut mm = station();
        let mut q = MessageQueue::new();
        let old = [0x13; 10];
        mm.client_mgr.try_register_client(MS, true).unwrap();
        mm.config.state_write().subscribers.register(MS);
        mm.config.state_write().subscribers.set_encrypted(MS, true);
        mm.config.state_write().sc3_dcks.insert(MS, CipherKey(old));
        let obsolete = TxReporter::new();
        mm.dck.insert(MS, SecCipherKey([0x24; 10]));
        mm.replace_pending_ciphering(MS, Some(CipheringParameters::class3(2)), obsolete.clone());
        let mut request = registration(MS, None);
        if let SapMsgInner::LmmMleUnitdataInd(p) = &mut request.msg { p.encrypted = encrypted; }
        mm.rx_u_location_update_demand(&mut q, request);
        let SapMsgInner::LmmMleUnitdataReq(challenge) = q.pop_front().unwrap().msg else { panic!("challenge") };
        assert_eq!(challenge.encryption_override, Some(encrypted));
        obsolete.mark_transmitted();
        obsolete.mark_acknowledged();
        mm.process_pending_ciphering();
        assert_eq!(mm.config.state_read().sc3_dcks[&MS].0, old, "obsolete accept cannot activate its DCK");
        let (res1, new_dck) = answer(&mm, &K);
        mm.rx_u_authentication_response(&mut q, MS, 0, UAuthenticationResponse { res1, rand2: None, proprietary: None });
        let mut responses = MessageQueue::new();
        while let Some(message) = q.pop_front() {
            if let SapMsgInner::LmmMleUnitdataReq(p) = &message.msg { assert_eq!(p.encryption_override, Some(encrypted)); }
            responses.push_back(message);
        }
        let (_, receipt) = accept(&mut responses);
        assert_eq!(mm.config.state_read().sc3_dcks[&MS].0, old);
        assert_eq!(mm.config.state_read().subscribers.encrypted(MS), Some(true));
        receipt.mark_transmitted(); receipt.mark_acknowledged();
        mm.process_pending_ciphering();
        assert_eq!(mm.config.state_read().sc3_dcks[&MS].0, new_dck);
        assert!(!mm.registration_encryption.contains_key(&MS));
    }
}

fn group_report(groups: &[u32], replace: bool) -> SapMsg {
    let pdu = UAttachDetachGroupIdentity {
        group_identity_report: false, group_identity_attach_detach_mode: replace,
        group_report_response: Some(tetra_core::typed_pdu_fields::Type3FieldGeneric { field_id: 4, len: 1, data: 0 }),
        group_identity_uplink: if groups.is_empty() { None } else { Some(groups.iter().map(|&gssi| GroupIdentityUplink {
            class_of_usage: Some(4), group_identity_detachment_uplink: None,
            gssi: Some(gssi), address_extension: None, vgssi: None,
        }).collect()) },
        proprietary: None,
    };
    let mut message = registration(MS, None);
    if let SapMsgInner::LmmMleUnitdataInd(p) = &mut message.msg {
        p.sdu = BitBuffer::new_autoexpand(512); pdu.to_bitbuf(&mut p.sdu).unwrap(); p.sdu.seek(0);
    }
    message
}

#[test]
fn r2_group_replacement_preserves_unchanged_affiliations_and_removes_only_missing() {
    let mut mm = station();
    let mut q = MessageQueue::new();
    mm.client_mgr.try_register_client(MS, true).unwrap();
    mm.config.state_write().subscribers.register(MS);
    mm.config.state_write().subscribers.set_encrypted(MS, true);
    for g in [268, 269] {
        mm.client_mgr.client_group_attach(MS, g, true).unwrap();
        mm.config.state_write().subscribers.affiliate(MS, g);
    }
    for _ in 0..2 {
        mm.rx_u_attach_detach_group_identity(&mut q, group_report(&[268, 270], true));
        while let Some(m) = q.pop_front() {
            if let SapMsgInner::MmSubscriberUpdate(u) = m.msg {
                assert!(!u.groups.contains(&268), "unchanged group must never flap");
                if u.action == BrewSubscriberAction::Deaffiliate { assert_eq!(u.groups, vec![269]); }
            }
        }
        let mut groups = mm.config.state_read().subscribers.attached_groups_of(MS); groups.sort();
        assert_eq!(groups, vec![268, 270]);
    }
    mm.rx_u_attach_detach_group_identity(&mut q, group_report(&[], true));
    assert!(mm.config.state_read().subscribers.attached_groups_of(MS).is_empty());
}

#[test]
fn r2_group_report_cannot_register_unknown_radio_without_authentication() {
    for groups in [vec![], vec![268]] {
        let mut mm = station();
        let mut q = MessageQueue::new();
        mm.rx_u_attach_detach_group_identity(&mut q, group_report(&groups, true));
        assert!(!mm.client_mgr.client_is_known(MS));
        assert!(!mm.config.state_read().subscribers.is_registered(MS));
        assert!(mm.config.state_read().sc3_dcks.is_empty());
        let SapMsgInner::LmmMleUnitdataReq(mut p) = q.pop_front().unwrap().msg else { panic!("reject") };
        let ack = DAttachDetachGroupIdentityAcknowledgement::from_bitbuf(&mut p.sdu).unwrap();
        assert_eq!(ack.group_identity_accept_reject, 1);
    }
}

#[test]
fn r2_repeated_group_report_restores_registry_after_presence_timeout() {
    let mut mm = station();
    let mut q = MessageQueue::new();
    mm.client_mgr.try_register_client(MS, true).unwrap();
    mm.client_mgr.client_group_attach(MS, 268, true).unwrap();
    mm.config.state_write().subscribers.register(MS);
    mm.config.state_write().subscribers.set_encrypted(MS, true);
    mm.rx_u_attach_detach_group_identity(&mut q, group_report(&[268], true));
    assert_eq!(mm.config.state_read().subscribers.attached_groups_of(MS), vec![268]);
    let mut restored = false;
    while let Some(m) = q.pop_front() {
        restored |= matches!(&m.msg, SapMsgInner::MmSubscriberUpdate(u) if u.action == BrewSubscriberAction::Affiliate && u.groups == vec![268]);
    }
    assert!(restored);
}

const MS: u32 = 100;
const K: [u8; 16] = [0x57; 16];
const CCK: [u8; 10] = [0x62; 10];

#[test]
fn r3_recovery_command_cannot_hold_new_itsi_attach_dck_after_accept_ack() {
    let mut mm = station();
    let mut q = MessageQueue::new();
    // Log 10:21:10: an old encrypted detach is retried after the DCK was removed.
    // Reactive recovery requests a group report before the radio starts its new attach.
    mm.send_d_location_update_command(&mut q, MS, 0);
    assert!(mm.group_report_in_flight.contains_key(&MS));
    mm.rx_u_location_update_demand(&mut q, registration(MS, None));
    let (res1, dck) = answer(&mm, &K);
    mm.rx_u_authentication_response(&mut q, MS, 0, UAuthenticationResponse { res1, rand2: None, proprietary: None });
    let (_, receipt) = accept(&mut q);
    receipt.mark_transmitted();
    receipt.mark_acknowledged();
    mm.process_pending_ciphering();
    assert_eq!(mm.config.state_read().sc3_dcks.get(&MS).map(|k| k.0), Some(dck));
    assert_eq!(mm.config.state_read().subscribers.encrypted(MS), Some(true));
}

#[test]
fn r3_sc3_group_report_cannot_replace_the_authentication_result_receipt() {
    let mut mm = station();
    let mut q = MessageQueue::new();
    mm.rx_u_location_update_demand(&mut q, registration(MS, None));
    let (res1, dck) = answer(&mm, &K);
    mm.rx_u_authentication_response(&mut q, MS, 0, UAuthenticationResponse { res1, rand2: None, proprietary: None });
    let (_, receipt) = accept(&mut q);
    mm.mark_group_report_pending(MS);
    assert!(!mm.pending_ciphering[&MS].awaiting_group_report);
    assert!(mm.prepare_group_report_completion(MS).is_none());
    receipt.mark_transmitted(); receipt.mark_acknowledged();
    mm.process_pending_ciphering();
    assert_eq!(mm.config.state_read().sc3_dcks[&MS].0, dck);
}

#[test]
fn r3_each_return_authenticates_fresh_duplicates_keep_the_current_challenge() {
    let mut mm = station();
    let mut q = MessageQueue::new();
    let mut previous_challenge = None;
    let mut previous_dck = None;
    // Repeat the actual mutual-authentication path, including a DMO detach.
    for _ in 0..3 {
        mm.send_d_location_update_command(&mut q, MS, 0);
        mm.rx_u_location_update_demand(&mut q, registration(MS, None));
        let challenge = mm.auth_pending[&MS].challenge.rand1;
        assert_ne!(Some(challenge), previous_challenge);
        mm.rx_u_location_update_demand(&mut q, registration(MS, None));
        assert_eq!(mm.auth_pending[&MS].challenge.rand1, challenge);
        let (res1, _) = answer(&mm, &K);
        mm.rx_u_authentication_response(&mut q, MS, 0, UAuthenticationResponse {
            res1, rand2: Some([0x35; 10]), proprietary: None,
        });
        assert!(mm.config.state_read().sc3_dcks.is_empty());
        mm.rx_u_authentication_result(&mut q, MS, 0, transmitted_ack(), UAuthenticationResult { r2: true, res1: None, proprietary: None });
        let (pdu, receipt) = accept(&mut q);
        let dck = mm.pending_ciphering[&MS].dck.as_ref().unwrap().0;
        assert_ne!(Some(dck), previous_dck);
        let cck = pdu.authentication_downlink.unwrap().cck.unwrap();
        assert_eq!(ta32(&cck.sealed, cck.cck_id, &dck), Ok(CCK));
        receipt.mark_transmitted(); mm.process_pending_ciphering();
        assert!(mm.config.state_read().sc3_dcks.is_empty());
        receipt.mark_acknowledged(); mm.process_pending_ciphering();
        assert_eq!(mm.config.state_read().sc3_dcks[&MS].0, dck);
        assert_eq!(mm.config.state_read().sc3_status[&MS].phase, "active");
        let mut detach = registration(MS, None);
        if let SapMsgInner::LmmMleUnitdataInd(p) = &mut detach.msg {
            p.encrypted = true;
            p.sdu = BitBuffer::new_autoexpand(32);
            UItsiDetach { address_extension: None, proprietary: None }.to_bitbuf(&mut p.sdu).unwrap();
            p.sdu.seek(0);
        }
        mm.rx_u_itsi_detach(&mut q, detach);
        assert!(!mm.config.state_read().subscribers.is_registered(MS));
        assert!(mm.config.state_read().sc3_dcks.is_empty());
        assert!(!mm.auth_passed.contains_key(&MS));
        previous_challenge = Some(challenge); previous_dck = Some(dck);
    }
}

#[test]
fn r3_standalone_authentication_cannot_bypass_the_next_registration_challenge() {
    let mut mm = station();
    let mut q = MessageQueue::new();
    mm.rx_u_authentication_demand(&mut q, MS, 0, UAuthenticationDemand { rand2: [0x42; 10], proprietary: None });
    let (res1, _) = answer(&mm, &K);
    mm.rx_u_authentication_result(&mut q, MS, 0, transmitted_ack(), UAuthenticationResult { r2: true, res1: Some(res1), proprietary: None });
    let receipt = mm.auth_ack_pending[&MS].1.clone();
    receipt.mark_transmitted(); receipt.mark_acknowledged();
    mm.process_authentication_acks(&mut q);
    assert!(mm.config.state_read().sc3_dcks.contains_key(&MS));
    mm.rx_u_location_update_demand(&mut q, registration(MS, None));
    assert!(mm.auth_pending.contains_key(&MS), "each new registration must prove K again");
    assert!(!mm.pending_ciphering.contains_key(&MS));
}

fn station() -> MmBs {
    let mut cfg = tetra_config::bluestation::from_toml_str(include_str!("../../../../example_config/config.toml")).unwrap();
    cfg.security.authentication = AuthenticationMode::Required;
    cfg.security.subscribers = vec![SubscriberKey { issi: MS, k: K }];
    cfg.security.issi_whitelist.clear();
    cfg.security.whitelist_mode = tetra_config::bluestation::sec_security::WhitelistMode::Open;
    cfg.security.aie = Some(CfgAie {
        enabled: true,
        ksg: 2,
        sck: CipherKey([0; 10]),
        sckn: 1,
        sck_vn: 0,
        clear_groups: vec![],
        class3: Some(CfgClass3 {
            cck: CipherKey(CCK),
            cck_id: 42,
        }),
    });
    MmBs::new(SharedConfig::from_parts(cfg, None), None, None)
}

fn registration(issi: u32, rand2: Option<[u8; 10]>) -> SapMsg {
    let pdu = ULocationUpdateDemand {
        location_update_type: LocationUpdateType::ItsiAttach,
        request_to_append_la: false,
        cipher_control: true,
        ciphering_parameters: Some(CipheringParameters::class3(2).to_bits()),
        class_of_ms: None,
        energy_saving_mode: None,
        la_information: None,
        ssi: Some(issi as u64),
        address_extension: None,
        group_identity_location_demand: None,
        group_report_response: None,
        authentication_uplink: Some(AuthenticationUplink { ck_request: true, rand2 }),
        extended_capabilities: None,
        proprietary: None,
    };
    let mut sdu = BitBuffer::new_autoexpand(512);
    pdu.to_bitbuf(&mut sdu).unwrap();
    sdu.seek(0);
    SapMsg {
        sap: Sap::LmmSap,
        src: TetraEntity::Mle,
        dest: TetraEntity::Mm,
        msg: SapMsgInner::LmmMleUnitdataInd(tetra_saps::lmm::LmmMleUnitdataInd {
            rx_ack: None,
            encrypted: false,
            sdu,
            handle: 0,
            received_address: TetraAddress::issi(issi),
        }),
    }
}

fn answer(mm: &MmBs, key: &[u8; 16]) -> ([u8; 4], [u8; 10]) {
    let p = mm.auth_pending.get(&MS).unwrap();
    let a = ta12(&ta11(key, &p.challenge.rs), &p.challenge.rand1);
    (a.res, a.dck)
}

fn accept(queue: &mut MessageQueue) -> (DLocationUpdateAccept, TxReporter) {
    while let Some(m) = queue.pop_front() {
        if let SapMsgInner::LmmMleUnitdataReq(mut req) = m.msg {
            if req.sdu.peek_bits(4) == Some(tetra_pdus::mm::enums::mm_pdu_type_dl::MmPduTypeDl::DLocationUpdateAccept.into_raw()) {
                return (DLocationUpdateAccept::from_bitbuf(&mut req.sdu).unwrap(), req.tx_reporter.unwrap());
            }
        }
    }
    panic!("no location update accept");
}

#[test]
fn sc3_registration_seals_cck_and_activates_dck_only_after_ack() {
    let mut mm = station();
    let mut q = MessageQueue::new();
    mm.rx_u_location_update_demand(&mut q, registration(MS, None));
    let (res1, dck) = answer(&mm, &K);
    mm.rx_u_authentication_response(
        &mut q,
        MS,
        0,
        UAuthenticationResponse {
            res1,
            rand2: None,
            proprietary: None,
        },
    );
    let (pdu, receipt) = accept(&mut q);
    let cck = pdu.authentication_downlink.unwrap().cck.unwrap();
    assert_eq!(cck.cck_id, 42);
    assert_eq!(ta32(&cck.sealed, cck.cck_id, &dck), Ok(CCK));
    assert!(mm.config.state_read().sc3_dcks.is_empty());
    receipt.mark_transmitted();
    mm.process_pending_ciphering();
    assert!(mm.config.state_read().sc3_dcks.is_empty());
    receipt.mark_acknowledged();
    mm.process_pending_ciphering();
    assert_eq!(mm.config.state_read().sc3_dcks.get(&MS).unwrap().0, dck);
    assert_eq!(mm.config.state_read().subscribers.encrypted(MS), Some(true));
    mm.clear_registration_transients(MS);
    assert!(mm.config.state_read().sc3_dcks.is_empty());
    assert!(!mm.dck.contains_key(&MS));
}

#[test]
fn sc3_embedded_rand2_is_answered_and_both_dck_halves_are_used() {
    let mut mm = station();
    let mut q = MessageQueue::new();
    let rand2 = [0x19; 10];
    mm.rx_u_location_update_demand(&mut q, registration(MS, Some(rand2)));
    let (res1, dck1) = answer(&mm, &K);
    let p = mm.auth_pending.get(&MS).unwrap();
    let dck2 = answer_ms_challenge(&AuthKey(K), &p.challenge.rs, &rand2).dck2;
    let expected = derive_dck(Some(&dck1), Some(&dck2));
    mm.rx_u_authentication_result(
        &mut q,
        MS,
        0, transmitted_ack(),
        UAuthenticationResult {
            r2: true,
            res1: Some(res1),
            proprietary: None,
        },
    );
    let (pdu, receipt) = accept(&mut q);
    let cck = pdu.authentication_downlink.unwrap().cck.unwrap();
    assert_eq!(ta32(&cck.sealed, cck.cck_id, &expected.0), Ok(CCK));
    receipt.mark_transmitted();
    receipt.mark_acknowledged();
    mm.process_pending_ciphering();
    assert_eq!(mm.config.state_read().sc3_dcks.get(&MS).unwrap().0, expected.0);
}

#[test]
fn sc3_wrong_key_unknown_subscriber_and_expired_response_never_publish_dck() {
    for expired in [false, true] {
        let mut mm = station();
        let mut q = MessageQueue::new();
        mm.rx_u_location_update_demand(&mut q, registration(MS, None));
        let (res1, _) = answer(&mm, if expired { &K } else { &[0x88; 16] });
        if expired {
            mm.auth_pending.get_mut(&MS).unwrap().started = Instant::now() - T354 - Duration::from_secs(1);
        }
        mm.rx_u_authentication_response(
            &mut q,
            MS,
            0,
            UAuthenticationResponse {
                res1,
                rand2: None,
                proprietary: None,
            },
        );
        assert!(mm.dck.is_empty());
        assert!(mm.config.state_read().sc3_dcks.is_empty());
        assert!(mm.pending_ciphering.is_empty());
    }
    let mut mm = station();
    let mut q = MessageQueue::new();
    mm.rx_u_location_update_demand(&mut q, registration(101, None));
    assert!(mm.auth_pending.is_empty());
    assert!(!mm.client_mgr.client_is_known(101));
}

#[test]
fn sc3_mutual_response_waits_for_positive_r2() {
    for r2 in [true, false] {
        let mut mm = station();
        let mut q = MessageQueue::new();
        mm.rx_u_location_update_demand(&mut q, registration(MS, None));
        let (res1, _) = answer(&mm, &K);
        mm.rx_u_authentication_response(
            &mut q,
            MS,
            0,
            UAuthenticationResponse {
                res1,
                rand2: Some([0x35; 10]),
                proprietary: None,
            },
        );
        assert!(mm.dck.is_empty());
        assert!(mm.auth_result_pending.contains_key(&MS));
        mm.rx_u_authentication_result(
            &mut q,
            MS,
            0, transmitted_ack(),
            UAuthenticationResult {
                r2,
                res1: None,
                proprietary: None,
            },
        );
        assert_eq!(mm.dck.contains_key(&MS), r2);
        assert_eq!(mm.pending_ciphering.contains_key(&MS), r2);
    }
}

#[test]
fn sc3_standalone_rekey_retains_old_dck_until_result_ack() {
    let mut mm = station();
    let mut q = MessageQueue::new();
    let old = [0x99; 10];
    mm.config.state_write().sc3_dcks.insert(MS, CipherKey(old));
    mm.rx_u_authentication_demand(
        &mut q,
        MS,
        0,
        UAuthenticationDemand {
            rand2: [0x42; 10],
            proprietary: None,
        },
    );
    let (res1, _) = answer(&mm, &K);
    mm.rx_u_authentication_result(
        &mut q,
        MS,
        0, transmitted_ack(),
        UAuthenticationResult {
            r2: true,
            res1: Some(res1),
            proprietary: None,
        },
    );
    let receipt = mm.auth_ack_pending.get(&MS).unwrap().1.clone();
    receipt.mark_transmitted();
    mm.process_authentication_acks(&mut q);
    assert_eq!(mm.config.state_read().sc3_dcks.get(&MS).unwrap().0, old);
    receipt.mark_acknowledged();
    mm.process_authentication_acks(&mut q);
    assert_ne!(mm.config.state_read().sc3_dcks.get(&MS).unwrap().0, old);
    assert!(mm.auth_ack_pending.is_empty());
}

#[test]
fn sc3_registration_ack_is_bound_to_its_own_dck_and_expired_ack_cannot_activate() {
    for expired in [false, true] {
        let mut mm = station();
        let mut q = MessageQueue::new();
        mm.rx_u_location_update_demand(&mut q, registration(MS, None));
        let (res1, registered_dck) = answer(&mm, &K);
        mm.rx_u_authentication_response(&mut q, MS, 0, UAuthenticationResponse { res1, rand2: None, proprietary: None });
        let (_, receipt) = accept(&mut q);
        // A later exchange must not supply the key for an earlier ACK.
        mm.dck.insert(MS, SecCipherKey([0xE1; 10]));
        if expired {
            mm.pending_ciphering.get_mut(&MS).unwrap().started = Instant::now() - CIPHERING_ACK_TIMEOUT;
        }
        receipt.mark_transmitted();
        receipt.mark_acknowledged();
        mm.process_pending_ciphering();
        let state = mm.config.state_read();
        if expired {
            assert!(!state.sc3_dcks.contains_key(&MS));
            assert_eq!(state.sc3_status[&MS].phase, "timeout");
        } else {
            assert_eq!(state.sc3_dcks[&MS].0, registered_dck);
            assert_eq!(state.sc3_status[&MS].phase, "active");
        }
    }
}

#[test]
fn sc3_rejection_while_waiting_for_r2_cancels_registration_and_keeps_active_key() {
    let mut mm = station();
    let mut q = MessageQueue::new();
    let old = [0x39; 10];
    mm.config.state_write().sc3_dcks.insert(MS, CipherKey(old));
    mm.rx_u_location_update_demand(&mut q, registration(MS, None));
    let (res1, _) = answer(&mm, &K);
    mm.rx_u_authentication_response(&mut q, MS, 0, UAuthenticationResponse {
        res1, rand2: Some([0x25; 10]), proprietary: None,
    });
    assert!(mm.auth_result_pending.contains_key(&MS));
    mm.rx_u_authentication_reject(&mut q, MS, 0, UAuthenticationReject {
        reject_reason: AuthenticationRejectReason::AuthenticationNotSupported,
    });
    assert!(mm.auth_result_pending.is_empty());
    assert!(mm.pending_ciphering.is_empty());
    assert_eq!(mm.config.state_read().sc3_dcks[&MS].0, old);
    assert_eq!(mm.config.state_read().sc3_status[&MS].phase, "failed");
}

#[test]
fn sc3_registration_blocks_overlapping_standalone_authentication() {
    let mut mm = station();
    let mut q = MessageQueue::new();
    mm.rx_u_location_update_demand(&mut q, registration(MS, None));
    let (res1, _) = answer(&mm, &K);
    mm.rx_u_authentication_response(&mut q, MS, 0, UAuthenticationResponse { res1, rand2: None, proprietary: None });
    let (_, receipt) = accept(&mut q);
    mm.rx_u_authentication_demand(&mut q, MS, 0, UAuthenticationDemand { rand2: [0x41; 10], proprietary: None });
    assert!(mm.auth_pending.is_empty());
    receipt.mark_transmitted();
    receipt.mark_acknowledged();
    mm.rx_u_authentication_demand(&mut q, MS, 0, UAuthenticationDemand { rand2: [0x41; 10], proprietary: None });
    assert!(mm.auth_pending.contains_key(&MS));
    assert!(mm.config.state_read().sc3_dcks.contains_key(&MS));
}

fn otar_message(sub_type: OtarSubType, fields: &[(u64, usize)]) -> SapMsg {
    let mut msg = registration(MS, None);
    if let SapMsgInner::LmmMleUnitdataInd(prim) = &mut msg.msg {
        let mut b = BitBuffer::new_autoexpand(128);
        b.write_bits(tetra_pdus::mm::enums::mm_pdu_type_ul::MmPduTypeUl::UOtar.into_raw(), 4);
        b.write_bits(sub_type.into_raw(), 4);
        for &(value, bits) in fields { b.write_bits(value, bits); }
        b.write_bit(0); // no optional elements
        b.seek(0);
        prim.sdu = b;
        prim.encrypted = true;
    }
    msg
}

#[test]
fn sc3_cck_demand_uses_active_dck_and_never_an_unconfirmed_candidate() {
    for active in [false, true] {
        let mut mm = station();
        let mut q = MessageQueue::new();
        let old = [0x13; 10];
        let candidate = [0xF1; 10];
        mm.dck.insert(MS, SecCipherKey(candidate));
        if active {
            mm.config.state_write().sc3_dcks.insert(MS, CipherKey(old));
            mm.config.state_write().subscribers.register(MS);
            mm.config.state_write().subscribers.set_encrypted(MS,true);
            mm.sc3_phase(MS,"active");
        }
        let la = mm.config.config().cell.location_area;
        mm.rx_u_otar(&mut q, otar_message(OtarSubType::CckDemandProvide, &[(la as u64, 14)]));
        let SapMsgInner::LmmMleUnitdataReq(mut response) = q.pop_front().unwrap().msg else { panic!("no OTAR response") };
        response.sdu.read_field(8, "OTAR header").unwrap();
        assert_eq!(response.sdu.read_field(1, "CCK supplied").unwrap(), active as u64);
        if active {
            let cck = CckInformation::from_bitbuf(&mut response.sdu).unwrap();
            assert_eq!(ta32(&cck.sealed, cck.cck_id, &old), Ok(CCK));
            assert!(ta32(&cck.sealed, cck.cck_id, &candidate).is_err());
            assert_eq!(mm.config.state_read().sc3_status[&MS].cck, "sent");
        } else { assert!(mm.cck_pending.is_empty()); }
    }
}

#[test]
fn sc3_cck_result_reports_radio_verdict_and_rejection_clears_active_key() {
    for accepted in [false, true] {
        let mut mm = station();
        let mut q = MessageQueue::new();
        mm.config.state_write().subscribers.register(MS);
        mm.config.state_write().subscribers.set_encrypted(MS, true);
        mm.config.state_write().sc3_dcks.insert(MS, CipherKey([0x13; 10]));
        mm.sc3_phase(MS,"active");
        mm.cck_pending.insert(MS, Instant::now());
        mm.rx_u_otar(&mut q, otar_message(OtarSubType::CckResultReject, &[(if accepted { 0 } else { 1 }, 3), (0, 1)]));
        let state = mm.config.state_read();
        assert_eq!(state.sc3_dcks.contains_key(&MS), accepted);
        assert_eq!(state.sc3_status[&MS].cck, if accepted { "accepted" } else { "rejected" });
        if !accepted { assert!(!state.subscribers.is_registered(MS)); }
    }
}

#[test]
fn r4_operator_cck_otar_is_sealed_encrypted_and_waits_for_radio_verdict() {
    let mut mm=station(); let mut q=MessageQueue::new(); let active=[0x17;10];
    mm.otar_cck_provide(&mut q,MS); assert!(q.pop_front().is_none());
    mm.config.state_write().subscribers.register(MS);
    mm.config.state_write().subscribers.set_encrypted(MS,true);
    mm.config.state_write().sc3_dcks.insert(MS,CipherKey(active));
    mm.sc3_phase(MS,"active");
    mm.dck.insert(MS,SecCipherKey([0x19;10])); // candidate is deliberately different
    mm.registration_encryption.insert(MS,false); // stale override must not expose delivery
    mm.otar_cck_provide(&mut q,MS);
    let SapMsgInner::LmmMleUnitdataReq(mut tx)=q.pop_front().unwrap().msg else {panic!("CCK provide")};
    assert_eq!(tx.encryption_override,Some(true));
    tx.sdu.read_field(8,"header").unwrap(); assert_eq!(tx.sdu.read_field(1,"present").unwrap(),1);
    let cck=CckInformation::from_bitbuf(&mut tx.sdu).unwrap();
    assert_eq!(ta32(&cck.sealed,cck.cck_id,&active),Ok(CCK));
    assert_eq!(mm.config.state_read().sc3_status[&MS].cck,"sent");
    mm.otar_cck_provide(&mut q,MS); assert!(q.pop_front().is_none(),"deduplicate clicks");
    let mut clear=otar_message(OtarSubType::CckResultReject,&[(1,3),(0,1)]);
    if let SapMsgInner::LmmMleUnitdataInd(p)=&mut clear.msg {p.encrypted=false;}
    mm.rx_u_otar(&mut q,clear);
    assert!(mm.config.state_read().sc3_dcks.contains_key(&MS),"clear rejection must not erase an active DCK");
    assert!(mm.cck_pending.contains_key(&MS));
    mm.rx_u_otar(&mut q,otar_message(OtarSubType::CckResultReject,&[(0,3),(0,1)]));
    assert_eq!(mm.config.state_read().sc3_status[&MS].cck,"accepted");
    assert!(!mm.cck_pending.contains_key(&MS));
    mm.sc3_phase(MS,"timeout"); mm.otar_cck_provide(&mut q,MS);
    assert!(q.pop_front().is_none(),"old retained DCK is not a healthy new session");
}

#[test]
fn r4_cck_missing_result_never_claims_acceptance_or_expires_dck() {
    for registration in [true,false] {
        let mut mm=station();
        mm.config.state_write().sc3_dcks.insert(MS,CipherKey([0x13;10]));
        mm.sc3_phase(MS,"active");
        mm.sc3_cck(MS,if registration {"registration_sent"} else {"sent"});
        mm.cck_pending.insert(MS,Instant::now()-T_OTAR_RESULT-Duration::from_secs(1));
        mm.expire_authentication();
        let state=mm.config.state_read();
        assert_eq!(state.sc3_status[&MS].cck,if registration {"registration_unconfirmed"} else {"unconfirmed"});
        assert!(state.sc3_dcks.contains_key(&MS));
    }
}

fn transmitted_ack() -> Option<tetra_core::tx_receipt::RxAck> {
    let ack=tetra_core::tx_receipt::RxAck::default(); ack.transmitted.mark_transmitted(); Some(ack)
}

#[test]
fn r4_encrypted_periodic_registration_switches_dck_at_result_ack_before_lu_accept() {
    for delivered in [true,false] {
        let mut mm=station(); let mut q=MessageQueue::new(); let old=[0x51;10];
        mm.config.state_write().subscribers.register(MS);
        mm.config.state_write().subscribers.set_encrypted(MS,true);
        mm.config.state_write().sc3_dcks.insert(MS,CipherKey(old));
        mm.client_mgr.try_register_client(MS,true).unwrap();
        let mut reg=registration(MS,None);
        if let SapMsgInner::LmmMleUnitdataInd(p)=&mut reg.msg {
            p.encrypted=true;
            let mut lu=ULocationUpdateDemand::from_bitbuf(&mut p.sdu).unwrap();
            lu.location_update_type=LocationUpdateType::PeriodicLocationUpdating;
            p.sdu=BitBuffer::new_autoexpand(512); lu.to_bitbuf(&mut p.sdu).unwrap(); p.sdu.seek(0);
        }
        mm.rx_u_location_update_demand(&mut q,reg);
        let (res1,_)=answer(&mm,&K);
        mm.rx_u_authentication_response(&mut q,MS,0,UAuthenticationResponse{res1,rand2:Some([0x35;10]),proprietary:None});
        let new=mm.auth_result_pending[&MS].dck.0;
        let ack=tetra_core::tx_receipt::RxAck::default();
        while q.pop_front().is_some() {}
        mm.rx_u_authentication_result(&mut q,MS,0,Some(ack.clone()),UAuthenticationResult{r2:true,res1:None,proprietary:None});
        assert!(ack.is_standalone(),"final result must get an independently tracked ACK");
        assert_eq!(mm.config.state_read().sc3_dcks[&MS].0,old);
        assert!(q.pop_front().is_none(),"do not queue LU accept before old-key ACK transmission");
        assert!(!mm.pending_ciphering.contains_key(&MS));
        if delivered {ack.transmitted.mark_transmitted();} else {ack.transmitted.mark_discarded();}
        mm.process_authentication_acks(&mut q);
        if delivered {
            assert_eq!(mm.config.state_read().sc3_dcks[&MS].0,new,"encrypted LU accept must already use NEW DCK");
            let (accept,receipt)=accept(&mut q);
            let cck=accept.authentication_downlink.unwrap().cck.unwrap();
            assert_eq!(ta32(&cck.sealed,cck.cck_id,&new),Ok(CCK));
            receipt.mark_transmitted();receipt.mark_acknowledged();mm.process_pending_ciphering();
            assert_eq!(mm.config.state_read().sc3_status[&MS].phase,"active");
        } else {
            assert_eq!(mm.config.state_read().sc3_dcks[&MS].0,old);
            assert!(q.pop_front().is_none());
            assert_eq!(mm.config.state_read().sc3_status[&MS].phase,"timeout");
        }
    }
}

// ───────────── Key management: authentication data from the server (`keys-v1`) ─────────────

use crate::net_control::auc::{AucStore, Handle};
use crate::net_control::commands::{AuthVectorWire, ControlResponse};

/// A class 3 station with `key_source = "server"`: no K in its config, sets from `auc`.
fn server_station(known: &[u32], sets: &[[u8; 10]]) -> (MmBs, Handle) {
    let mut mm = station();
    {
        let mut cfg = (*mm.config.config()).clone();
        cfg.security.subscribers.clear();
        cfg.security.key_source = tetra_config::bluestation::KeySource::Server;
        mm.config = SharedConfig::from_parts(cfg, None);
    }
    let auc: Handle = std::sync::Arc::new(std::sync::Mutex::new(AucStore::default()));
    {
        let mut s = auc.lock().unwrap();
        s.set_link(true);
        s.subscribers(known, &[]);
        let wire: Vec<_> = sets.iter().map(|rs| AuthVectorWire::from_vector(&AuthVector::from_k(&AuthKey(K), *rs))).collect();
        if !wire.is_empty() {
            s.add(MS, &wire);
        }
        s.take_arrived();
    }
    (mm.with_auc(auc.clone()), auc)
}

fn reject_cause(q: &mut MessageQueue) -> Option<u8> {
    while let Some(m) = q.pop_front() {
        if let SapMsgInner::LmmMleUnitdataReq(mut req) = m.msg
            && req.sdu.peek_bits(4) == Some(tetra_pdus::mm::enums::mm_pdu_type_dl::MmPduTypeDl::DLocationUpdateReject.into_raw())
        {
            req.sdu.read_field(4, "pdu_type").unwrap();
            req.sdu.read_field(3, "location_update_type").unwrap();
            return Some(req.sdu.read_field(5, "reject_cause").unwrap() as u8);
        }
    }
    None
}

#[test]
fn keys_server_registration_authenticates_with_one_stock_set_and_reports_it() {
    let (mut mm, auc) = server_station(&[MS], &[[0x31; 10], [0x32; 10]]);
    let mut q = MessageQueue::new();
    mm.rx_u_location_update_demand(&mut q, registration(MS, None));
    // EN 300 392-7 clause 4.1.1: RS of the set goes to the radio, RAND1 is the station's own.
    assert_eq!(mm.auth_pending[&MS].challenge.rs, [0x31; 10]);
    assert_eq!(auc.lock().unwrap().count(MS), 1, "the set is taken from the stock");
    let (res1, dck) = answer(&mm, &K);
    mm.rx_u_authentication_response(&mut q, MS, 0, UAuthenticationResponse { res1, rand2: None, proprietary: None });
    let (_, receipt) = accept(&mut q);
    receipt.mark_transmitted();
    receipt.mark_acknowledged();
    mm.process_pending_ciphering();
    assert_eq!(mm.config.state_read().sc3_dcks.get(&MS).unwrap().0, dck);
    let out = auc.lock().unwrap().drain_outbox();
    assert!(matches!(&out[..], [ControlResponse::AuthReport { issi: MS, ok: true, mutual: false, left: Some(1), rs }, ControlResponse::DckReport { key }]
        if rs == "31313131313131313131" && key.issi == MS && key.dck == crate::net_control::auc::hex(&dck)), "{out:?}");
}

#[test]
fn keys_server_wrong_res_is_rejected_and_reported_as_failed() {
    let (mut mm, auc) = server_station(&[MS], &[[0x31; 10]]);
    let mut q = MessageQueue::new();
    mm.rx_u_location_update_demand(&mut q, registration(MS, None));
    let (res1, _) = answer(&mm, &[0x88; 16]);
    mm.rx_u_authentication_response(&mut q, MS, 0, UAuthenticationResponse { res1, rand2: None, proprietary: None });
    assert!(mm.config.state_read().sc3_dcks.is_empty());
    let out = auc.lock().unwrap().drain_outbox();
    assert!(matches!(&out[..], [ControlResponse::AuthReport { issi: MS, ok: false, .. }]));
}

#[test]
fn keys_server_embedded_rand2_is_answered_from_ks_prime() {
    let (mut mm, _auc) = server_station(&[MS], &[[0x41; 10]]);
    let mut q = MessageQueue::new();
    let rand2 = [0x19; 10];
    mm.rx_u_location_update_demand(&mut q, registration(MS, Some(rand2)));
    let (res1, dck1) = answer(&mm, &K);
    // The station holds no K: RES2 / DCK2 come from KS' of the set (TA22) and match the radio's.
    let dck2 = answer_ms_challenge(&AuthKey(K), &[0x41; 10], &rand2).dck2;
    let expected = derive_dck(Some(&dck1), Some(&dck2));
    mm.rx_u_authentication_result(&mut q, MS, 0, transmitted_ack(), UAuthenticationResult { r2: true, res1: Some(res1), proprietary: None });
    let (_, receipt) = accept(&mut q);
    receipt.mark_transmitted();
    receipt.mark_acknowledged();
    mm.process_pending_ciphering();
    assert_eq!(mm.config.state_read().sc3_dcks.get(&MS).unwrap().0, expected.0);
}

#[test]
fn keys_server_empty_stock_holds_the_registration_until_sets_arrive() {
    let (mut mm, auc) = server_station(&[MS], &[]);
    let mut q = MessageQueue::new();
    mm.rx_u_location_update_demand(&mut q, registration(MS, None));
    assert!(q.pop_front().is_none(), "nothing on air while the sets are requested");
    assert!(matches!(&auc.lock().unwrap().drain_outbox()[..], [ControlResponse::AuthVectorRequest { issi: MS }]));
    // A repeat of the registration only replaces the held one.
    mm.rx_u_location_update_demand(&mut q, registration(MS, None));
    assert!(q.pop_front().is_none() && auc.lock().unwrap().drain_outbox().is_empty());
    mm.process_auth_waiting(&mut q);
    assert!(q.pop_front().is_none() && !mm.auth_pending.contains_key(&MS));
    auc.lock().unwrap().add(MS, &[AuthVectorWire::from_vector(&AuthVector::from_k(&AuthKey(K), [0x51; 10]))]);
    mm.process_auth_waiting(&mut q);
    assert_eq!(mm.auth_pending[&MS].challenge.rs, [0x51; 10], "challenge goes out with the new set");
    assert!(!mm.auth_waiting.contains_key(&MS));
}

#[test]
fn keys_server_no_sets_within_the_wait_rejects_when_required() {
    let (mut mm, _auc) = server_station(&[MS], &[]);
    let mut q = MessageQueue::new();
    mm.rx_u_location_update_demand(&mut q, registration(MS, None));
    mm.auth_waiting.get_mut(&MS).unwrap().since = Instant::now() - AUC_WAIT - Duration::from_millis(1);
    mm.process_auth_waiting(&mut q);
    assert_eq!(reject_cause(&mut q), Some(RejectCause::IllegalMs as u8));
    assert!(!mm.auth_waiting.contains_key(&MS) && !mm.auth_pending.contains_key(&MS));
}

#[test]
fn keys_server_radio_without_k_at_the_server_is_not_asked_for() {
    let (mut mm, auc) = server_station(&[], &[]);
    let mut q = MessageQueue::new();
    mm.rx_u_location_update_demand(&mut q, registration(MS, None));
    assert_eq!(reject_cause(&mut q), Some(RejectCause::IllegalMs as u8));
    assert!(auc.lock().unwrap().drain_outbox().is_empty());
}

#[test]
fn keys_server_otar_sck_is_refused_without_local_k() {
    let (mut mm, _auc) = server_station(&[MS], &[[0x61; 10]]);
    let mut q = MessageQueue::new();
    mm.otar_sck_provide(&mut q, MS, "test");
    assert!(q.pop_front().is_none() && mm.otar_pending.is_empty());
}

/// Simulation (project rule: 10 stations, 25 radios): a test authentication centre holds K of 25
/// radios and serves 10 stations with `key_source = "server"` over the control channel's JSON.
/// Radios register and move between stations; then the server goes away and the stations go on
/// from their stock until it runs out.
#[test]
fn keys_server_simulation_10_stations_25_radios() {
    use crate::net_control::codec::ControlCodecJson;
    use crate::net_control::commands::ControlCommand;
    const STATIONS: usize = 10;
    const RADIOS: u32 = 25;
    const STOCK: usize = 3;
    let k_of = |issi: u32| -> [u8; 16] { std::array::from_fn(|i| (issi as u8).wrapping_mul(31).wrapping_add(i as u8 * 7)) };
    let issis: Vec<u32> = (0..RADIOS).map(|i| 2_320_000 + i).collect();
    let mut rs_counter: u64 = 0;
    // The test AuC: fresh RS per set, KS / KS' from K (clause 4.1.1), sent as JSON like brew-server.
    let mut auc_vectors = |issi: u32, n: usize| -> Vec<u8> {
        let vectors: Vec<serde_json::Value> = (0..n)
            .map(|_| {
                rs_counter += 1;
                let mut rs = [0u8; 10];
                rs[..8].copy_from_slice(&rs_counter.to_be_bytes());
                let w = AuthVectorWire::from_vector(&AuthVector::from_k(&AuthKey(k_of(issi)), rs));
                serde_json::json!({"rs": w.rs, "ks": w.ks, "ks_p": w.ks_p})
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({"AuthVectors": {"issi": issi, "vectors": vectors}})).unwrap()
    };
    let deliver = |auc: &Handle, json: &[u8]| match ControlCodecJson.decode_command(json).unwrap() {
        ControlCommand::AuthVectors { issi, vectors } => auc.lock().unwrap().add(issi, &vectors),
        ControlCommand::AuthSubscribers { issis, drop } => {
            auc.lock().unwrap().subscribers(&issis, &drop);
        }
        other => panic!("{other:?}"),
    };
    let subscribers = serde_json::to_vec(&serde_json::json!({"AuthSubscribers": {"issis": issis}})).unwrap();
    let mut stations: Vec<(MmBs, Handle)> = (0..STATIONS)
        .map(|_| {
            let (mm, auc) = server_station(&[], &[]);
            deliver(&auc, &subscribers);
            (mm, auc)
        })
        .collect();

    // One registration of `issi` at station `s`; `online`: the AuC answers requests.
    let mut sent: Vec<ControlResponse> = Vec::new();
    let mut register = |stations: &mut Vec<(MmBs, Handle)>, sent: &mut Vec<ControlResponse>, s: usize, issi: u32, online: bool| -> bool {
        let (mm, auc) = &mut stations[s];
        let mut q = MessageQueue::new();
        mm.rx_u_location_update_demand(&mut q, registration(issi, None));
        if mm.auth_waiting.contains_key(&issi) {
            let out = auc.lock().unwrap().drain_outbox();
            assert!(out.iter().any(|r| matches!(r, ControlResponse::AuthVectorRequest { issi: i } if *i == issi)));
            sent.extend(out);
            if online {
                deliver(auc, &auc_vectors(issi, STOCK));
            } else {
                mm.auth_waiting.get_mut(&issi).unwrap().since = Instant::now() - AUC_WAIT - Duration::from_millis(1);
            }
            mm.process_auth_waiting(&mut q);
        }
        let Some(p) = mm.auth_pending.get(&issi) else { return false };
        // The radio answers with its own K.
        let res1 = ta12(&ta11(&k_of(issi), &p.challenge.rs), &p.challenge.rand1).res;
        mm.rx_u_authentication_response(&mut q, issi, 0, UAuthenticationResponse { res1, rand2: None, proprietary: None });
        let (_, receipt) = accept(&mut q);
        receipt.mark_transmitted();
        receipt.mark_acknowledged();
        mm.process_pending_ciphering();
        let ok = mm.config.state_read().sc3_dcks.contains_key(&issi);
        sent.extend(auc.lock().unwrap().drain_outbox());
        mm.clear_registration_transients(issi);
        mm.config.state_write().sc3_dcks.remove(&issi);
        ok
    };

    // Phase 1, server online: every radio registers at three stations in turn.
    let mut ok = 0;
    for (n, &issi) in issis.iter().enumerate() {
        for hop in 0..3 {
            ok += register(&mut stations, &mut sent, (n + hop * 3) % STATIONS, issi, true) as usize;
        }
    }
    assert_eq!(ok, RADIOS as usize * 3, "every registration authenticated");
    let reports = sent.iter().filter(|r| matches!(r, ControlResponse::AuthReport { ok: true, .. })).count();
    assert_eq!(reports, RADIOS as usize * 3, "every set reported once");

    // Phase 2, server gone: radio 0 comes back to station 0, which has STOCK - 1 sets left.
    let issi = issis[0];
    let left = stations[0].1.lock().unwrap().count(issi) as usize;
    assert_eq!(left, STOCK - 1);
    for _ in 0..left {
        assert!(register(&mut stations, &mut sent, 0, issi, false), "authenticated from the stock while the server is away");
    }
    assert!(!register(&mut stations, &mut sent, 0, issi, false), "stock used up: no authentication (8d adds the fallback)");
    // The stock file of every station keeps no K.
    for (_, auc) in &stations {
        let s = auc.lock().unwrap();
        assert!(s.total() <= RADIOS * STOCK as u32);
    }
}

// ───────────── phase 8b: class 2 SCKs from the server (`sck-v1`) ─────────────

use crate::net_control::commands::{SckWire, SealedSckWire};
use tetra_pdus::mm::pdus::ck_change::{ChangeTime, DCkChangeDemand, KeyChange};
use tetra_security::taa1::otar::{ta51, ta52};

const SCK_CONFIG: [u8; 10] = [0x11; 10];

/// A class 2 cell with `key_source = "server"`: config SCK 1 v1, K at the server only.
fn sc2_server_station() -> (MmBs, Handle) {
    let (mut mm, auc) = server_station(&[MS], &[]);
    let mut cfg = (*mm.config.config()).clone();
    cfg.security.aie = Some(CfgAie { enabled: true, ksg: 1, sck: CipherKey(SCK_CONFIG), sckn: 1, sck_vn: 1, clear_groups: vec![], class3: None });
    cfg.security.authentication = AuthenticationMode::Optional;
    mm.config = SharedConfig::from_parts(cfg, None);
    (mm, auc)
}

fn wire(sckn: u8, vn: u16, key: [u8; 10], next: bool) -> SckWire {
    SckWire { sckn, vn, key: crate::net_control::auc::hex(&key), next }
}

/// What the server does for one radio (EN 300 392-7 clause 4.5.2.2): KSO = TA41(K, RSO),
/// SSCK = TA51(SCK, SCK-VN, KSO, SCKN with SCKN zero-based).
fn seal(k: &[u8; 16], rso: [u8; 10], keys: &[(u8, u16, [u8; 10])]) -> (String, Vec<SealedSckWire>) {
    let kso = tetra_security::taa1::ta41(k, &rso);
    let sealed = keys
        .iter()
        .map(|&(n, vn, sck)| SealedSckWire { sckn: n, vn, ssck: crate::net_control::auc::hex(&ta51(&sck, vn, &kso, n - 1)) })
        .collect();
    (crate::net_control::auc::hex(&rso), sealed)
}

fn sent_pdus(q: &mut MessageQueue) -> Vec<(u32, BitBuffer)> {
    let mut out = Vec::new();
    while let Some(m) = q.pop_front() {
        if let SapMsgInner::LmmMleUnitdataReq(req) = m.msg {
            out.push((req.address.ssi, req.sdu));
        }
    }
    out
}

#[test]
fn sck_server_sealed_keys_reach_the_radio_and_its_result_goes_back() {
    let (mut mm, auc) = sc2_server_station();
    mm.client_mgr.try_register_client(MS, true).unwrap();
    let current = [0x21; 10];
    let next = [0x22; 10];
    let (rso, sealed) = seal(&K, [0x5A; 10], &[(1, 7, current), (2, 8, next)]);
    auc.lock().unwrap().push_sealed(MS, rso, sealed);
    let mut q = MessageQueue::new();
    mm.process_sck_sealed(&mut q);
    let mut pdus = sent_pdus(&mut q);
    assert_eq!(pdus.len(), 1);
    let (to, sdu) = &mut pdus[0];
    assert_eq!(*to, MS);
    let pdu = DOtarSckProvide::from_bitbuf(sdu).unwrap();
    let OtarSessionKey::Individual { rso } = pdu.session_key else { panic!("individual delivery") };
    assert_eq!(rso, [0x5A; 10], "the server's RSO goes to the radio");
    // The radio unseals with KSO from its own K (TA52): the station never saw K.
    let kso = tetra_security::taa1::ta41(&K, &rso);
    let got: Vec<_> = pdu.keys.iter().map(|k| (k.sckn, k.sck_vn, ta52(&k.ssck, &kso, k.sck_vn).unwrap())).collect();
    assert_eq!(got, vec![(0, 7, (current, 0)), (1, 8, (next, 1))]);
    assert_eq!(mm.otar_pending[&MS].keys, vec![(1, 7), (2, 8)]);

    // The radio accepts SCK 1 and rejects SCK 2: one report per key to the server.
    use tetra_pdus::mm::pdus::otar_sck::SckNumberAndResult;
    let results = vec![
        SckNumberAndResult { sckn: 0, result: ProvisionResult::Accepted, current_sck_vn: None },
        SckNumberAndResult { sckn: 1, result: ProvisionResult::IncorrectKeyVersion, current_sck_vn: Some(3) },
    ];
    mm.rx_u_otar_sck_result(MS, UOtarSckResult { results, address_extension: None, proprietary: None });
    let out = auc.lock().unwrap().drain_outbox();
    assert!(matches!(&out[0], ControlResponse::SckResult { issi: MS, sckn: 1, vn: 7, ok: true, .. }));
    assert!(matches!(&out[1], ControlResponse::SckResult { issi: MS, sckn: 2, vn: 8, ok: false, detail: Some(d) } if d.contains("version 3")));
    assert!(mm.otar_pending.is_empty());
}

#[test]
fn sck_server_demand_is_forwarded_and_an_empty_answer_rejects_it() {
    let (mut mm, auc) = sc2_server_station();
    mm.client_mgr.try_register_client(MS, true).unwrap();
    let mut q = MessageQueue::new();
    // U-OTAR SCK DEMAND: KSG 0 (TEA1), one SCK, number 2 (on air 1).
    mm.rx_u_otar(&mut q, otar_message(OtarSubType::SckDemandProvide, &[(0, 4), (1, 3), (1, 5)]));
    assert!(sent_pdus(&mut q).is_empty(), "the station has no K: it asks the server");
    let out = auc.lock().unwrap().drain_outbox();
    assert!(matches!(&out[..], [ControlResponse::SckDemand { issi: MS, sckns }] if sckns == &[2]));
    auc.lock().unwrap().push_sealed(MS, crate::net_control::auc::hex(&[0; 10]), vec![]);
    mm.process_sck_sealed(&mut q);
    let mut pdus = sent_pdus(&mut q);
    assert_eq!(pdus.len(), 1);
    let reject = DOtarSckReject::from_bitbuf(&mut pdus[0].1).unwrap();
    assert_eq!(reject.rejected, vec![(1, OtarRejectReason::KeyNotAvailable)], "each requested number");
}

#[test]
fn sck_server_delivery_for_a_radio_elsewhere_goes_back_as_not_delivered() {
    let (mut mm, auc) = sc2_server_station();
    let (rso, sealed) = seal(&K, [1; 10], &[(1, 7, [0x21; 10])]);
    auc.lock().unwrap().push_sealed(MS, rso, sealed);
    let mut q = MessageQueue::new();
    mm.process_sck_sealed(&mut q);
    assert!(sent_pdus(&mut q).is_empty());
    auc.lock().unwrap().drop_stale_sealed(Duration::ZERO);
    let out = auc.lock().unwrap().drain_outbox();
    assert!(matches!(&out[..], [ControlResponse::SckResult { ok: false, detail: Some(d), .. }] if d == "radio not registered"));
}

#[test]
fn sck_change_slot_is_the_next_multiframe_start_at_or_after_the_time() {
    let ts = TdmaTime { t: 3, f: 7, m: 10, h: 2 };
    let at = super::sck_change_slot(ts, 1_000_000 + 60_000, 1_000_000);
    assert_eq!((at.t, at.f), (1, 1), "a multiframe start");
    let slots = at.diff(ts);
    // 60 s = 4235.3 slots of 255/18 ms; the next multiframe start is less than 72 slots later.
    assert!((4236..4236 + 72).contains(&slots), "{slots}");
    let past = super::sck_change_slot(ts, 1_000, 1_000_000);
    assert_eq!((past.t, past.f), (1, 1));
    assert!(past.diff(ts) > 0 && past.diff(ts) <= 72, "a past time: the next multiframe (immediate)");
}

#[test]
fn sck_server_change_is_announced_switched_on_its_slot_and_committed() {
    let (mut mm, auc) = sc2_server_station();
    mm.client_mgr.try_register_client(MS, true).unwrap();
    mm.client_mgr.try_register_client(MS + 1, true).unwrap();
    mm.registration_encryption.insert(MS, true);
    mm.registration_encryption.insert(MS + 1, false);
    let new = [0x33; 10];
    {
        let mut s = auc.lock().unwrap();
        s.set_sck_keys(&[wire(1, 1, SCK_CONFIG, false), wire(2, 2, new, true)]);
        s.sck_activate(2, 2, super::now_ms() + 10_000).unwrap();
    }
    let ts = TdmaTime { t: 2, f: 5, m: 30, h: 100 };
    let mut q = MessageQueue::new();
    mm.sync_sck(&mut q, ts);
    let (at, key) = mm.config.state_read().sck_run.as_ref().and_then(|r| r.switch.clone()).expect("change planned");
    assert_eq!((key.sckn, key.vn, key.key.0), (2, 2, new));
    // One D-CK CHANGE DEMAND, to the radio registered encrypted, with the absolute IV.
    let mut pdus = sent_pdus(&mut q);
    assert_eq!(pdus.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![MS]);
    let d = DCkChangeDemand::from_bitbuf(&mut pdus[0].1).unwrap();
    assert_eq!(d.key, KeyChange::Sck(vec![(1, 2)]), "SCKN zero-based on air");
    assert_eq!(d.time, ChangeTime::AbsoluteIv { t: at.t, f: at.f, m: at.m, h: at.h });
    // Seen again: no second announcement.
    mm.sync_sck(&mut q, ts.add_timeslots(4));
    assert!(sent_pdus(&mut q).is_empty());
    // A registration asking for the new SCKN is accepted once the change took place.
    assert_eq!(mm.aie_now().unwrap().sckn, 1);
    mm.sync_sck(&mut q, at.add_timeslots(super::SCK_COMMIT_AFTER_SLOTS + 1));
    assert_eq!(auc.lock().unwrap().sck_active().map(|k| (k.sckn, k.vn)), Some((2, 2)));
    let run = mm.config.state_read().sck_run.clone().unwrap();
    assert!(run.switch.is_none());
    assert_eq!(run.active.map(|k| k.key.0), Some(new));
    assert_eq!((mm.aie_now().unwrap().sckn, mm.aie_now().unwrap().sck_vn), (2, 2));
    let out = auc.lock().unwrap().drain_outbox();
    assert!(
        matches!(&out[..], [ControlResponse::SckState { active: Some(a), from_config: false, switch_at_ms: None, .. }] if a.sckn == 2 && a.check == crate::net_control::auc::check_value(&new)),
        "{out:?}"
    );
}

#[test]
fn sck_server_keys_are_ignored_on_a_station_with_local_keys() {
    let mut mm = station();
    let auc: Handle = std::sync::Arc::new(std::sync::Mutex::new(AucStore::default()));
    auc.lock().unwrap().set_sck_keys(&[wire(2, 2, [0x33; 10], false)]);
    auc.lock().unwrap().sck_activate(2, 2, 0).unwrap();
    let mut mm2 = std::mem::replace(&mut mm, station()).with_auc(auc);
    let mut q = MessageQueue::new();
    mm2.sync_sck(&mut q, TdmaTime::default());
    assert!(mm2.config.state_read().sck_run.is_none() && q.pop_front().is_none());
}

/// Simulation (project rule: 10 stations, 25 radios) of an SCK change run by the server: the
/// stations get the key set as JSON, every radio gets current + next sealed under its own K at
/// the station it is registered at and confirms them, then one activation time switches every
/// station (each on its own timebase) and each reports the new key.
#[test]
fn sck_server_simulation_10_stations_25_radios() {
    use crate::net_control::codec::ControlCodecJson;
    use crate::net_control::commands::ControlCommand;
    const STATIONS: usize = 10;
    const RADIOS: u32 = 25;
    let k_of = |issi: u32| -> [u8; 16] { std::array::from_fn(|i| (issi as u8).wrapping_mul(13).wrapping_add(i as u8 * 3)) };
    let issis: Vec<u32> = (0..RADIOS).map(|i| 2_330_000 + i).collect();
    let current = [0x41; 10];
    let next = [0x42; 10];
    let set_json = serde_json::json!({"SckKeys": {"keys": [
        {"sckn": 1, "vn": 5, "key": crate::net_control::auc::hex(&current), "next": false},
        {"sckn": 2, "vn": 6, "key": crate::net_control::auc::hex(&next), "next": true},
    ]}});
    let mut stations: Vec<(MmBs, Handle, TdmaTime)> = (0..STATIONS)
        .map(|s| {
            let (mm, auc) = sc2_server_station();
            let ControlCommand::SckKeys { keys } = ControlCodecJson.decode_command(set_json.to_string().as_bytes()).unwrap() else { panic!() };
            auc.lock().unwrap().set_sck_keys(&keys);
            // Unsynchronised stations: each its own TDMA time.
            (mm, auc, TdmaTime::from_int(s as i32 * 7919 + 13))
        })
        .collect();
    let home = |n: usize| n % STATIONS;
    for (n, &issi) in issis.iter().enumerate() {
        let (mm, _, _) = &mut stations[home(n)];
        mm.client_mgr.try_register_client(issi, true).unwrap();
        mm.registration_encryption.insert(issi, true);
    }

    // Delivery: the server seals for each radio and sends it to every station; only the
    // station the radio is registered at sends it, the radio confirms both keys.
    let mut confirmed = 0;
    for (n, &issi) in issis.iter().enumerate() {
        let rso: [u8; 10] = std::array::from_fn(|i| (n as u8) ^ (i as u8 * 17));
        let (rso_hex, sealed) = seal(&k_of(issi), rso, &[(1, 5, current), (2, 6, next)]);
        for (s, (mm, auc, _)) in stations.iter_mut().enumerate() {
            auc.lock().unwrap().push_sealed(issi, rso_hex.clone(), sealed.clone());
            let mut q = MessageQueue::new();
            mm.process_sck_sealed(&mut q);
            let pdus = sent_pdus(&mut q);
            if s != home(n) {
                assert!(pdus.is_empty(), "only the radio's station sends");
                auc.lock().unwrap().drop_stale_sealed(Duration::ZERO);
                auc.lock().unwrap().drain_outbox();
                continue;
            }
            let (to, mut sdu) = pdus.into_iter().next().expect("provide sent");
            assert_eq!(to, issi);
            let pdu = DOtarSckProvide::from_bitbuf(&mut sdu).unwrap();
            let OtarSessionKey::Individual { rso } = pdu.session_key else { panic!() };
            let kso = tetra_security::taa1::ta41(&k_of(issi), &rso);
            use tetra_pdus::mm::pdus::otar_sck::SckNumberAndResult;
            let results = pdu
                .keys
                .iter()
                .map(|k| {
                    let (sck, n) = ta52(&k.ssck, &kso, k.sck_vn).expect("the radio unseals with its own K");
                    assert_eq!(sck, if n == 0 { current } else { next });
                    SckNumberAndResult { sckn: n, result: ProvisionResult::Accepted, current_sck_vn: None }
                })
                .collect();
            mm.rx_u_otar_sck_result(issi, UOtarSckResult { results, address_extension: None, proprietary: None });
            confirmed += auc.lock().unwrap().drain_outbox().iter().filter(|r| matches!(r, ControlResponse::SckResult { ok: true, .. })).count();
        }
    }
    assert_eq!(confirmed, RADIOS as usize * 2, "every radio confirmed current and next");

    // Activation: one server time for all stations.
    let at_ms = super::now_ms() + 30_000;
    let activate = serde_json::json!({"SckActivate": {"sckn": 2, "vn": 6, "at_ms": at_ms}}).to_string();
    let mut announced = 0;
    for (mm, auc, ts) in stations.iter_mut() {
        let ControlCommand::SckActivate { sckn, vn, at_ms } = ControlCodecJson.decode_command(activate.as_bytes()).unwrap() else { panic!() };
        auc.lock().unwrap().sck_activate(sckn, vn, at_ms).unwrap();
        let mut q = MessageQueue::new();
        mm.sync_sck(&mut q, *ts);
        announced += sent_pdus(&mut q).len();
        let (at, _) = mm.config.state_read().sck_run.as_ref().and_then(|r| r.switch.clone()).unwrap();
        // ~30 s ahead on this station's own timebase, on a multiframe start.
        assert!((2117..2117 + 73).contains(&at.diff(*ts)), "{}", at.diff(*ts));
        *ts = at;
    }
    assert_eq!(announced, RADIOS as usize, "each registered radio told once");
    for (mm, auc, ts) in stations.iter_mut() {
        let mut q = MessageQueue::new();
        mm.sync_sck(&mut q, ts.add_timeslots(super::SCK_COMMIT_AFTER_SLOTS + 1));
        assert_eq!(auc.lock().unwrap().sck_active().map(|k| (k.sckn, k.vn, k.key.0)), Some((2, 6, next)));
        let out = auc.lock().unwrap().drain_outbox();
        assert!(matches!(&out[..], [ControlResponse::SckState { active: Some(a), .. }] if a.sckn == 2 && a.vn == 6));
    }
}

// ───────────── server CCKs (`cck-v1`, Fleet Control phase 8c) ─────────────

use crate::net_control::commands::CckWire;

fn cck_wire(cck_id: u16, key: [u8; 10], next: bool) -> CckWire {
    CckWire { la: None, cck_id, key: crate::net_control::auc::hex(&key), next }
}

/// A class 3 station with server keys and one radio with an active class 3 session.
fn sc3_server_station_with(issis: &[u32]) -> (MmBs, Handle) {
    let (mut mm, auc) = server_station(issis, &[]);
    for (n, &issi) in issis.iter().enumerate() {
        mm.client_mgr.try_register_client(issi, true).unwrap();
        let mut st = mm.config.state_write();
        st.subscribers.register(issi);
        st.subscribers.set_encrypted(issi, true);
        st.sc3_dcks.insert(issi, CipherKey([0x60 + n as u8; 10]));
        drop(st);
        mm.sc3_phase(issi, "active");
    }
    (mm, auc)
}

fn cck_provides(q: &mut MessageQueue) -> Vec<(u32, CckInformation)> {
    sent_pdus(q)
        .into_iter()
        .filter_map(|(to, mut sdu)| {
            (sdu.peek_bits(4) == Some(tetra_pdus::mm::enums::mm_pdu_type_dl::MmPduTypeDl::DOtar.into_raw()))
                .then(|| {
                    // D-OTAR CCK PROVIDE: PDU type + OTAR sub-type, CCK provision flag, CCK information.
                    sdu.read_field(8, "header").ok()?;
                    (sdu.read_field(1, "present").ok()? == 1).then(|| CckInformation::from_bitbuf(&mut sdu).ok()).flatten().map(|c| (to, c))
                })
                .flatten()
        })
        .collect()
}

#[test]
fn cck_server_next_key_goes_to_class3_radios_as_future_and_their_result_goes_back() {
    let (mut mm, auc) = sc3_server_station_with(&[MS]);
    let next = [0x44; 10];
    auc.lock().unwrap().set_cck_keys(&[cck_wire(42, CCK, false), cck_wire(43, next, true)]);
    let mut q = MessageQueue::new();
    mm.sync_cck(&mut q, TdmaTime::default());
    let sent = cck_provides(&mut q);
    assert_eq!(sent.len(), 1);
    let (to, info) = &sent[0];
    assert_eq!(*to, MS);
    assert!(info.future, "key type flag future (Table A.42)");
    assert_eq!(info.cck_id, 43);
    assert_eq!(ta32(&info.sealed, 43, &[0x60; 10]), Ok(next), "sealed with the radio's DCK (TA31, clause 4.5.1.1)");
    // The radio accepts: the server hears of it, and the key is not offered again.
    mm.rx_u_otar(&mut q, otar_message(OtarSubType::CckResultReject, &[(0, 3), (0, 1)]));
    let out = auc.lock().unwrap().drain_outbox();
    assert!(matches!(&out[..], [ControlResponse::CckResult { issi: MS, cck_id: 43, ok: true, .. }]), "{out:?}");
    assert!(mm.config.state_read().sc3_dcks.contains_key(&MS), "a future-key answer never touches the session");
    mm.cck_offered.clear();
    mm.sync_cck(&mut q, TdmaTime::default());
    assert!(cck_provides(&mut q).is_empty());
}

#[test]
fn cck_server_rejected_future_key_keeps_the_radio_registered() {
    let (mut mm, auc) = sc3_server_station_with(&[MS]);
    auc.lock().unwrap().set_cck_keys(&[cck_wire(42, CCK, false), cck_wire(43, [0x44; 10], true)]);
    let mut q = MessageQueue::new();
    mm.sync_cck(&mut q, TdmaTime::default());
    mm.rx_u_otar(&mut q, otar_message(OtarSubType::CckResultReject, &[(1, 3), (0, 1)]));
    assert!(mm.config.state_read().subscribers.is_registered(MS));
    let out = auc.lock().unwrap().drain_outbox();
    assert!(matches!(&out[..], [ControlResponse::CckResult { cck_id: 43, ok: false, .. }]), "{out:?}");
}

#[test]
fn cck_server_change_is_announced_switched_and_the_old_key_kept_for_the_overlap() {
    let (mut mm, auc) = sc3_server_station_with(&[MS]);
    let next = [0x44; 10];
    {
        let mut s = auc.lock().unwrap();
        s.set_cck_keys(&[cck_wire(42, CCK, false), cck_wire(43, next, true)]);
        assert_eq!(s.cck_activate(mm.config.config().cell.location_area, None, 43, super::now_ms() + 10_000, 600), Ok(true));
        assert_eq!(s.cck_activate(mm.config.config().cell.location_area, Some(9999), 43, 0, 0), Ok(false), "another LA's change");
    }
    let ts = TdmaTime { t: 1, f: 3, m: 10, h: 7 };
    let mut q = MessageQueue::new();
    mm.cck_offered.insert(MS, Instant::now()); // no delivery in this test
    mm.sync_cck(&mut q, ts);
    let (at, key) = mm.config.state_read().cck_run.as_ref().and_then(|r| r.switch.clone()).expect("planned");
    assert_eq!((key.vn, key.key.0), (43, next));
    let mut pdus = sent_pdus(&mut q);
    assert_eq!(pdus.len(), 1);
    let d = DCkChangeDemand::from_bitbuf(&mut pdus[0].1).unwrap();
    assert_eq!(d.key, KeyChange::Cck(43));
    assert_eq!(d.time, ChangeTime::AbsoluteIv { t: at.t, f: at.f, m: at.m, h: at.h });
    assert_eq!(mm.current_cck().map(|c| c.0), Some(42), "the old key until the commit");
    mm.sync_cck(&mut q, at.add_timeslots(super::SCK_COMMIT_AFTER_SLOTS + 1));
    assert_eq!(mm.current_cck().map(|c| (c.0, c.1.0)), Some((43, next)));
    let (old, until) = mm.config.state_read().cck_overlap.clone().expect("overlap");
    assert_eq!((old.vn, old.key.0), (42, CCK));
    assert!(until.diff(at) >= 600 * 18 * 1000 / 255 - 1, "600 s of overlap from the switch");
    let out = auc.lock().unwrap().drain_outbox();
    assert!(matches!(&out[..], [ControlResponse::CckState { active: Some(a), from_config: false, .. }] if a.cck_id == 43), "{out:?}");
    // After the overlap the old key goes.
    mm.sync_cck(&mut q, until.add_timeslots(1));
    assert!(mm.config.state_read().cck_overlap.is_none());
}

#[test]
fn cck_server_radio_that_missed_the_change_gets_the_current_key() {
    let (mut mm, auc) = sc3_server_station_with(&[MS]);
    let new = [0x44; 10];
    auc.lock().unwrap().set_cck_keys(&[cck_wire(43, new, false)]);
    mm.config.state_write().cck_run = Some(tetra_config::bluestation::SckRun { active: Some(tetra_config::bluestation::SckKey { sckn: 0, vn: 43, key: CipherKey(new) }), switch: None });
    auc.lock().unwrap().commit_cck(mm.config.config().cell.location_area, &tetra_config::bluestation::SckKey { sckn: 0, vn: 43, key: CipherKey(new) }, None);
    mm.cck_held.entry(MS).or_default().insert(42); // it held the old one only
    let mut q = MessageQueue::new();
    mm.sync_cck(&mut q, TdmaTime::default());
    let sent = cck_provides(&mut q);
    assert_eq!(sent.len(), 1);
    assert!(!sent[0].1.future);
    assert_eq!(ta32(&sent[0].1.sealed, 43, &[0x60; 10]), Ok(new));
}

#[test]
fn cck_server_keys_are_ignored_on_a_station_with_local_keys() {
    let auc: Handle = std::sync::Arc::new(std::sync::Mutex::new(AucStore::default()));
    auc.lock().unwrap().set_cck_keys(&[cck_wire(43, [0x44; 10], false)]);
    let mut mm = station().with_auc(auc);
    let mut q = MessageQueue::new();
    mm.sync_cck(&mut q, TdmaTime::default());
    assert!(mm.config.state_read().cck_run.is_none() && q.pop_front().is_none());
}

/// Simulation (10 stations, 25 radios) of a CCK change run by the server: every station gets the
/// set as JSON, hands the next CCK to its class 3 radios sealed with each radio's DCK, the radios
/// confirm, one activation switches every station on its own timebase, and each reports it.
#[test]
fn cck_server_simulation_10_stations_25_radios() {
    use crate::net_control::codec::ControlCodecJson;
    use crate::net_control::commands::ControlCommand;
    const STATIONS: usize = 10;
    const RADIOS: u32 = 25;
    let next = [0x45; 10];
    let set_json = serde_json::json!({"CckKeys": {"keys": [
        {"cck_id": 42, "key": crate::net_control::auc::hex(&CCK)},
        {"cck_id": 43, "key": crate::net_control::auc::hex(&next), "next": true},
    ]}});
    let issis: Vec<u32> = (0..RADIOS).map(|i| 2_340_000 + i).collect();
    let mut stations: Vec<(MmBs, Handle, TdmaTime)> = (0..STATIONS)
        .map(|s| {
            let mine: Vec<u32> = issis.iter().copied().enumerate().filter(|(n, _)| n % STATIONS == s).map(|(_, i)| i).collect();
            let (mm, auc) = sc3_server_station_with(&mine);
            let ControlCommand::CckKeys { keys } = ControlCodecJson.decode_command(set_json.to_string().as_bytes()).unwrap() else { panic!() };
            auc.lock().unwrap().set_cck_keys(&keys);
            (mm, auc, TdmaTime::from_int(s as i32 * 6151 + 29))
        })
        .collect();
    let mut confirmed = 0;
    for (mm, auc, ts) in stations.iter_mut() {
        let mut q = MessageQueue::new();
        mm.sync_cck(&mut q, *ts);
        let sent = cck_provides(&mut q);
        for (issi, info) in sent {
            let dck = mm.config.state_read().sc3_dcks[&issi].0;
            assert_eq!(ta32(&info.sealed, info.cck_id, &dck), Ok(next));
            let mut msg = otar_message(OtarSubType::CckResultReject, &[(0, 3), (0, 1)]);
            if let SapMsgInner::LmmMleUnitdataInd(p) = &mut msg.msg {
                p.received_address = TetraAddress::issi(issi);
            }
            mm.rx_u_otar(&mut q, msg);
        }
        confirmed += auc.lock().unwrap().drain_outbox().iter().filter(|r| matches!(r, ControlResponse::CckResult { cck_id: 43, ok: true, .. })).count();
    }
    assert_eq!(confirmed, RADIOS as usize);
    let at_ms = super::now_ms() + 20_000;
    let activate = serde_json::json!({"CckActivate": {"cck_id": 43, "at_ms": at_ms, "overlap_s": 1800}}).to_string();
    let mut announced = 0;
    for (mm, auc, ts) in stations.iter_mut() {
        let ControlCommand::CckActivate { la, cck_id, at_ms, overlap_s } = ControlCodecJson.decode_command(activate.as_bytes()).unwrap() else { panic!() };
        assert_eq!(auc.lock().unwrap().cck_activate(mm.config.config().cell.location_area, la, cck_id, at_ms, overlap_s), Ok(true));
        let mut q = MessageQueue::new();
        mm.sync_cck(&mut q, *ts);
        announced += sent_pdus(&mut q).len();
        let (at, _) = mm.config.state_read().cck_run.as_ref().and_then(|r| r.switch.clone()).unwrap();
        *ts = at;
    }
    assert_eq!(announced, RADIOS as usize);
    for (mm, auc, ts) in stations.iter_mut() {
        let mut q = MessageQueue::new();
        mm.sync_cck(&mut q, ts.add_timeslots(super::SCK_COMMIT_AFTER_SLOTS + 1));
        assert_eq!(mm.current_cck().map(|c| c.0), Some(43));
        let out = auc.lock().unwrap().drain_outbox();
        assert!(out.iter().any(|r| matches!(r, ControlResponse::CckState { active: Some(a), .. } if a.cck_id == 43)), "{out:?}");
    }
}

// ───────────── class 3 roaming between stations (`dck-v1`, Fleet Control phase 8e) ─────────────

#[test]
fn dck_server_new_dck_goes_to_the_server_once_and_replaces_a_forwarded_one() {
    let (mut mm, auc) = sc3_server_station_with(&[]);
    mm.config.state_write().dck_roam.insert(MS, CipherKey([0x99; 10]));
    mm.set_sc3_dck(MS, &SecCipherKey([0x77; 10]));
    mm.set_sc3_dck(MS, &SecCipherKey([0x77; 10]));
    let out = auc.lock().unwrap().drain_outbox();
    assert!(
        matches!(&out[..], [ControlResponse::DckReport { key }] if key.issi == MS && key.dck == crate::net_control::auc::hex(&[0x77; 10])),
        "one report per new DCK: {out:?}"
    );
    assert!(!mm.config.state_read().dck_roam.contains_key(&MS), "the forwarded DCK is no longer needed");
    // A new authentication gives a new DCK: reported again.
    mm.set_sc3_dck(MS, &SecCipherKey([0x78; 10]));
    assert_eq!(auc.lock().unwrap().drain_outbox().len(), 1);
}

#[test]
fn dck_local_keys_station_reports_no_dck() {
    let auc = crate::net_control::auc::Handle::default();
    let mut mm = station().with_auc(auc.clone());
    mm.set_sc3_dck(MS, &SecCipherKey([0x77; 10]));
    assert!(auc.lock().unwrap().drain_outbox().is_empty());
}

#[test]
fn cck_demand_for_a_neighbour_la_gets_that_las_server_cck_sealed_with_the_dck() {
    let (mut mm, _auc) = sc3_server_station_with(&[MS]);
    let own = mm.config.config().cell.location_area;
    let neighbour = own + 5;
    let key = [0x5A; 10];
    mm.config.state_write().cck_server = vec![(Some(neighbour), tetra_config::bluestation::SckKey { sckn: 0, vn: 55, key: CipherKey(key) })];
    let mut q = MessageQueue::new();
    mm.rx_u_otar(&mut q, otar_message(OtarSubType::CckDemandProvide, &[(neighbour as u64, 14)]));
    let sent = cck_provides(&mut q);
    assert_eq!(sent.len(), 1, "D-OTAR CCK PROVIDE (clause 4.5.1.3 case 2)");
    let (to, info) = &sent[0];
    assert_eq!(*to, MS);
    assert_eq!(info.cck_id, 55);
    assert_eq!(info.locations, CckLocations::List(vec![neighbour]));
    assert_eq!(ta32(&info.sealed, 55, &[0x60; 10]), Ok(key), "sealed with this radio's DCK (TA31)");
    // An LA the server sent no CCK for: "provision not possible" (no CCK information).
    mm.rx_u_otar(&mut q, otar_message(OtarSubType::CckDemandProvide, &[((neighbour + 1) as u64, 14)]));
    let pdus = sent_pdus(&mut q);
    assert_eq!(pdus.len(), 1);
    assert!(cck_provides(&mut q).is_empty());
}

#[test]
fn cck_for_a_prepare_needs_an_active_class3_session() {
    let (mm, _auc) = sc3_server_station_with(&[MS]);
    let own = mm.config.config().cell.location_area;
    let sdu = super::cck_provide_for_prepare(&mm.config, MS, own).expect("active session");
    let mut b = sdu.clone();
    b.read_field(8, "header").unwrap();
    assert_eq!(b.read_field(1, "present").unwrap(), 1);
    let info = CckInformation::from_bitbuf(&mut b).unwrap();
    assert_eq!(info.cck_id, mm.current_cck().unwrap().0);
    assert!(super::cck_provide_for_prepare(&mm.config, MS + 1, own).is_none(), "no DCK, nothing to seal with");
}

/// Ten class 3 stations with server keys, 25 radios. Each radio authenticates at its station,
/// which reports the DCK; the server (simulated here as the JSON it sends) forwards it to the
/// next station; there the cipher finds the radio's DCK before the radio authenticated there,
/// and a fresh authentication there replaces the forwarded key and is reported in turn.
#[test]
fn dck_server_simulation_10_stations_25_radios() {
    use crate::net_control::codec::ControlCodecJson;
    use crate::net_control::commands::ControlCommand;
    const STATIONS: usize = 10;
    const RADIOS: u32 = 25;
    let issis: Vec<u32> = (0..RADIOS).map(|i| 2_350_000 + i).collect();
    let mut stations: Vec<(MmBs, Handle)> = (0..STATIONS).map(|_| sc3_server_station_with(&[])).collect();
    let mut reports: Vec<(usize, crate::net_control::commands::DckWire)> = Vec::new();
    for (n, &issi) in issis.iter().enumerate() {
        let s = n % STATIONS;
        let (mm, auc) = &mut stations[s];
        mm.set_sc3_dck(issi, &SecCipherKey([n as u8 + 1; 10]));
        for r in auc.lock().unwrap().drain_outbox() {
            let ControlResponse::DckReport { key } = r else { panic!("{r:?}") };
            reports.push((s, key));
        }
    }
    assert_eq!(reports.len(), RADIOS as usize);
    for (from, key) in &reports {
        let to = (from + 1) % STATIONS;
        let json = serde_json::json!({"DckKeys": {"keys": [{"issi": key.issi, "dck": key.dck}]}}).to_string();
        let ControlCommand::DckKeys { keys, drop } = ControlCodecJson.decode_command(json.as_bytes()).unwrap() else { panic!() };
        assert!(drop.is_empty());
        let (mm, _) = &stations[to];
        let mut st = mm.config.state_write();
        for (issi, dck) in crate::net_control::auc::AucStore::dck_keys(&keys) {
            st.dck_roam.insert(issi, dck);
        }
    }
    for (n, &issi) in issis.iter().enumerate() {
        let to = (n % STATIONS + 1) % STATIONS;
        let (mm, auc) = &mut stations[to];
        let cfg = mm.config.config();
        let cipher = crate::aie::cipher::CellCipher::new(cfg.security.aie.as_ref().unwrap(), &[cfg.cell.main_carrier], cfg.cell.location_area, 1)
            .with_config(mm.config.clone());
        drop(cfg);
        let addr = TetraAddress::issi(issi);
        assert_eq!(cipher.dck_for_address(addr).map(|k| k.0), Some([n as u8 + 1; 10]), "forwarded DCK used before the radio authenticates here");
        mm.set_sc3_dck(issi, &SecCipherKey([0xA0 + n as u8; 10]));
        assert_eq!(cipher.dck_for_address(addr).map(|k| k.0), Some([0xA0 + n as u8; 10]), "own DCK after authenticating here");
        assert!(!mm.config.state_read().dck_roam.contains_key(&issi));
        assert_eq!(auc.lock().unwrap().drain_outbox().len(), 1, "new DCK reported");
    }
}

// ───────────── phase 8d: key fallback while the key server is away (`fallback-v1`) ─────────────

const FB_SCK: [u8; 10] = [0x5A; 10];

/// A registration of `issi` on a cell running class 2 with TEA`tea` and SCK `sckn`.
fn registration_sc2(issi: u32, tea: u8, sckn: u8) -> SapMsg {
    let mut m = registration(issi, None);
    if let SapMsgInner::LmmMleUnitdataInd(p) = &mut m.msg {
        let mut pdu = ULocationUpdateDemand::from_bitbuf(&mut p.sdu).unwrap();
        pdu.ciphering_parameters = Some(CipheringParameters::class2(tea, sckn).to_bits());
        pdu.authentication_uplink = None;
        p.sdu = BitBuffer::new_autoexpand(512);
        pdu.to_bitbuf(&mut p.sdu).unwrap();
        p.sdu.seek(0);
    }
    m
}

/// The location update accept type of the first D-LOCATION UPDATE ACCEPT in `q`.
fn accept_type(q: &mut MessageQueue) -> Option<LocationUpdateType> {
    while let Some(m) = q.pop_front() {
        if let SapMsgInner::LmmMleUnitdataReq(mut req) = m.msg
            && req.sdu.peek_bits(4) == Some(tetra_pdus::mm::enums::mm_pdu_type_dl::MmPduTypeDl::DLocationUpdateAccept.into_raw())
        {
            return Some(DLocationUpdateAccept::from_bitbuf(&mut req.sdu).unwrap().location_update_accept_type);
        }
    }
    None
}

fn ck_changes(q: &mut MessageQueue) -> Vec<(u32, DCkChangeDemand)> {
    sent_pdus(q)
        .into_iter()
        .filter_map(|(to, mut sdu)| DCkChangeDemand::from_bitbuf(&mut sdu).ok().map(|d| (to, d)))
        .collect()
}

fn fallback_states(auc: &Handle) -> Vec<(String, Vec<crate::net_control::commands::FallbackEpisode>)> {
    auc.lock()
        .unwrap()
        .drain_outbox()
        .into_iter()
        .filter_map(|r| match r {
            ControlResponse::FallbackState { phase, episodes, .. } => Some((phase, episodes)),
            _ => None,
        })
        .collect()
}

/// A class 3 station with server keys, `registered` radios on it (encrypted, with DCK), every
/// radio in `known` known to the server, the fallback SCK 31 v7, and the server gone.
fn sc3_fallback_station(registered: &[u32], known: &[u32]) -> (MmBs, Handle) {
    let (mut mm, auc) = sc3_server_station_with(registered);
    for &issi in registered {
        mm.registration_encryption.insert(issi, true);
    }
    {
        let mut s = auc.lock().unwrap();
        s.subscribers(known, &[]);
        s.set_fallback(Some(wire(31, 7, FB_SCK, false)), 300, 2);
        s.drain_outbox();
        s.set_link(false);
    }
    (mm, auc)
}

#[test]
fn fallback_class3_cell_runs_class2_on_the_fallback_sck_and_returns() {
    let r2 = MS + 1;
    let (mut mm, auc) = sc3_fallback_station(&[MS], &[MS, r2]);
    let mut q = MessageQueue::new();
    let ts = TdmaTime { t: 1, f: 3, m: 10, h: 7 };
    mm.process_key_fallback(&mut q, ts);
    assert!(mm.key_fallback.server_lost());
    // A radio without sets while the server is away: no 2 s wait, rejected (required, class 3).
    mm.rx_u_location_update_demand(&mut q, registration(r2, None));
    assert!(!mm.auth_waiting.contains_key(&r2), "no wait for sets from a server that is away");
    assert!(reject_cause(&mut q).is_some());
    mm.process_key_fallback(&mut q, ts);
    assert!(mm.config.state_read().key_fallback.is_none(), "not before the time");
    mm.key_fallback.skip(Duration::from_secs(300));
    mm.process_key_fallback(&mut q, ts);

    // EN 300 392-7 clause 4.5.6.2: D-CK CHANGE DEMAND "transition to security class 2" with the
    // fallback SCK (SCKN 31, zero-based 30 on air) on the first slot of a multiframe.
    let (at, key) = mm.config.state_read().key_fallback.clone().unwrap().sck.unwrap();
    assert_eq!((key.sckn, key.vn, key.key.0), (31, 7, FB_SCK));
    assert_eq!(at.to_int().rem_euclid(72), 0, "multiframe start");
    let changes = ck_changes(&mut q);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].0, MS);
    assert_eq!(changes[0].1.change_of_class, 0b10);
    assert_eq!(changes[0].1.key, KeyChange::Sck(vec![(30, 7)]));
    assert_eq!(changes[0].1.time, ChangeTime::AbsoluteIv { t: at.t, f: at.f, m: at.m, h: at.h });
    let st = fallback_states(&auc);
    assert!(matches!(&st[..], [(p, e)] if p == "fallback" && e.len() == 1 && e[0].class2 && e[0].to_ms.is_none()), "{st:?}");

    // The cipher follows on that slot, the uplink two slots later (clause 4.5.5.4).
    let cfg = mm.config.config();
    let cipher = crate::aie::cipher::CellCipher::new(cfg.security.aie.as_ref().unwrap(), &[cfg.cell.main_carrier], cfg.cell.location_area, 1)
        .with_config(mm.config.clone());
    drop(cfg);
    assert!(cipher.class3_at(at.add_timeslots(-1), false));
    assert!(!cipher.class3_at(at, false));
    assert_eq!((cipher.sckn_at(at), cipher.sck_vn_at(at)), (31, 7));
    assert!(cipher.class3_at(at.add_timeslots(1), true));
    assert!(!cipher.class3_at(at.add_timeslots(2), true));

    // MM negotiates class 2 with the fallback SCK; the radio without sets gets a temporary
    // registration (TS 100 392-2 clause 16.4.8, table 16.68 value 001).
    mm.process_key_fallback(&mut q, at);
    assert!(mm.sc2_fallback && !mm.is_class3());
    let aie = mm.aie_now().unwrap();
    assert!(aie.class3.is_none());
    assert_eq!((aie.sckn, aie.sck_vn), (31, 7));
    mm.rx_u_location_update_demand(&mut q, registration_sc2(r2, 2, 31));
    assert_eq!(accept_type(&mut q), Some(LocationUpdateType::MigratingLocationUpdating), "001 = temporary registration");
    assert!(mm.key_fallback.is_temporary(r2));

    // Server back: data sets first, then back to class 3 with the CCK-id (clause 4.5.6.3).
    {
        let mut s = auc.lock().unwrap();
        s.set_link(true);
        s.subscribers(&[MS, r2], &[]);
    }
    mm.process_key_fallback(&mut q, at.add_timeslots(100));
    assert!(matches!(&fallback_states(&auc)[..], [(p, _)] if p == "returning"));
    assert!(mm.config.state_read().key_fallback.as_ref().unwrap().back_at.is_none());
    mm.process_key_fallback(&mut q, at.add_timeslots(101));
    let back = mm.config.state_read().key_fallback.as_ref().unwrap().back_at.expect("return planned");
    let changes = ck_changes(&mut q);
    let to_ms: Vec<_> = changes.iter().filter(|(i, _)| *i == MS).collect();
    assert_eq!(to_ms.len(), 1);
    assert_eq!(to_ms[0].1.change_of_class, 0b11);
    assert_eq!(to_ms[0].1.key, KeyChange::Cck(mm.config.config().security.aie.as_ref().unwrap().class3.as_ref().unwrap().cck_id));
    assert!(!cipher.class3_at(back.add_timeslots(-1), false));
    assert!(cipher.class3_at(back, false));
    assert!(cipher.dck_for_address(TetraAddress::issi(MS)).is_some(), "the DCK from before the fallback is still there");
    let st = fallback_states(&auc);
    assert!(matches!(&st[..], [(p, e)] if p == "normal" && e[0].to_ms.is_some() && e[0].temporary == 1), "{st:?}");
    // A few slots later: normal mode ("system wide services" back).
    mm.process_key_fallback(&mut q, back.add_timeslots(super::KEY_FALLBACK_CLEAR_SLOTS + 1));
    assert!(mm.config.state_read().key_fallback.is_none());
    assert!(mm.is_class3());
}

#[test]
fn fallback_class3_without_fallback_sck_keeps_class3() {
    let r2 = MS + 1;
    let (mut mm, auc) = sc3_fallback_station(&[MS], &[MS, r2]);
    auc.lock().unwrap().set_fallback(None, 300, 2);
    let mut q = MessageQueue::new();
    let ts = TdmaTime { t: 1, f: 3, m: 10, h: 7 };
    mm.process_key_fallback(&mut q, ts);
    mm.rx_u_location_update_demand(&mut q, registration(r2, None));
    while q.pop_front().is_some() {}
    mm.key_fallback.skip(Duration::from_secs(300));
    mm.process_key_fallback(&mut q, ts);
    let run = mm.config.state_read().key_fallback.clone().expect("fallback");
    assert!(run.sck.is_none());
    assert!(ck_changes(&mut q).is_empty(), "no class change without the fallback SCK");
    mm.rx_u_location_update_demand(&mut q, registration(r2, None));
    assert!(reject_cause(&mut q).is_some(), "class 3 cannot register a radio without authentication");
    assert!(!mm.key_fallback.is_temporary(r2));
}

#[test]
fn fallback_unauthenticated_radios_are_authenticated_again_throttled() {
    let (mut mm, auc) = sc2_server_station();
    auc.lock().unwrap().set_link(false);
    let mut q = MessageQueue::new();
    let ts = TdmaTime { t: 1, f: 3, m: 10, h: 7 };
    mm.process_key_fallback(&mut q, ts);
    mm.rx_u_location_update_demand(&mut q, registration_sc2(MS, 1, 1));
    assert_eq!(accept_type(&mut q), Some(LocationUpdateType::ItsiAttach), "optional: registered unauthenticated, normal accept");
    while q.pop_front().is_some() {}
    // Server back within the 5 minutes: no fallback, but the radio is authenticated again.
    {
        let mut s = auc.lock().unwrap();
        s.set_link(true);
        s.subscribers(&[MS], &[]);
    }
    mm.process_key_fallback(&mut q, ts);
    mm.process_key_fallback(&mut q, ts);
    assert!(!mm.auth_pending.contains_key(&MS), "waits for data sets");
    let wire: Vec<_> = [[0x41; 10]].iter().map(|rs| AuthVectorWire::from_vector(&AuthVector::from_k(&AuthKey(K), *rs))).collect();
    auc.lock().unwrap().add(MS, &wire);
    mm.process_key_fallback(&mut q, ts);
    assert_eq!(mm.auth_pending.get(&MS).map(|p| p.challenge.rs), Some([0x41; 10]), "SwMI initiated authentication (clause 4.1.2)");
    assert!(mm.config.state_read().key_fallback.is_none(), "no fallback, normal mode all along");
}

#[test]
fn fallback_simulation_10_stations_25_radios() {
    const STATIONS: usize = 10;
    // Class 3: 20 radios registered (2 per station), 5 more come during the outage.
    let registered: Vec<u32> = (0..20).map(|i| 2_360_000 + i).collect();
    let late: Vec<u32> = (20..25).map(|i| 2_360_000 + i).collect();
    let all: Vec<u32> = registered.iter().chain(&late).copied().collect();
    let mut stations: Vec<(MmBs, Handle)> = (0..STATIONS).map(|s| sc3_fallback_station(&registered[s * 2..s * 2 + 2], &all)).collect();
    let mut q = MessageQueue::new();
    let ts = TdmaTime { t: 2, f: 9, m: 33, h: 1000 };
    for (mm, _) in &mut stations {
        mm.process_key_fallback(&mut q, ts);
    }
    // The late radios find no sets: each starves its station (5 of 10).
    for (n, &issi) in late.iter().enumerate() {
        stations[n].0.rx_u_location_update_demand(&mut q, registration(issi, None));
    }
    while q.pop_front().is_some() {}
    for (mm, _) in &mut stations {
        mm.key_fallback.skip(Duration::from_secs(300));
        mm.process_key_fallback(&mut q, ts);
    }
    let in_fallback = stations.iter().filter(|(mm, _)| mm.config.state_read().key_fallback.is_some()).count();
    assert_eq!(in_fallback, 5, "only stations where a radio could not be authenticated");
    let changes = ck_changes(&mut q);
    assert_eq!(changes.len(), 10, "the registered radios of those stations are told");
    assert!(changes.iter().all(|(_, d)| d.change_of_class == 0b10 && d.key == KeyChange::Sck(vec![(30, 7)])));
    // On the switch slot the late radios register again, now with a temporary registration.
    let mut temporary = 0;
    for (n, &issi) in late.iter().enumerate() {
        let (mm, _) = &mut stations[n];
        let at = mm.config.state_read().key_fallback.clone().unwrap().sck.unwrap().0;
        mm.process_key_fallback(&mut q, at);
        mm.rx_u_location_update_demand(&mut q, registration_sc2(issi, 2, 31));
        temporary += (accept_type(&mut q) == Some(LocationUpdateType::MigratingLocationUpdating)) as usize;
    }
    assert_eq!(temporary, 5);
    // Server back everywhere: every station returns, keeps its radios' DCKs.
    for (mm, auc) in &mut stations {
        {
            let mut s = auc.lock().unwrap();
            s.set_link(true);
            s.subscribers(&all, &[]);
        }
        let t = ts.add_timeslots(10_000);
        mm.process_key_fallback(&mut q, t);
        mm.process_key_fallback(&mut q, t.add_timeslots(1));
        let back = mm.config.state_read().key_fallback.as_ref().and_then(|r| r.back_at);
        if let Some(back) = back {
            mm.process_key_fallback(&mut q, back.add_timeslots(super::KEY_FALLBACK_CLEAR_SLOTS + 1));
        }
        mm.process_key_fallback(&mut q, t.add_timeslots(2000));
        assert!(mm.config.state_read().key_fallback.is_none());
        assert!(mm.is_class3());
    }
    let back = ck_changes(&mut q).into_iter().filter(|(i, d)| registered.contains(i) && d.change_of_class == 0b11).count();
    assert_eq!(back, 10);
    for (s, (mm, auc)) in stations.iter().enumerate() {
        for issi in &registered[s * 2..s * 2 + 2] {
            assert!(mm.config.state_read().sc3_dcks.contains_key(issi));
        }
        let eps: u32 = fallback_states(auc).iter().filter(|(p, _)| p == "normal").flat_map(|(_, e)| e.iter().map(|e| e.temporary)).sum();
        assert_eq!(eps, (s < 5) as u32, "station {s}");
    }

    // Class 2, optional: 25 radios register unauthenticated during a short outage and are
    // authenticated again at no more than 2 per second per station when the server is back.
    let mut stations: Vec<(MmBs, Handle)> = (0..STATIONS).map(|_| sc2_server_station()).collect();
    for (n, &issi) in all.iter().enumerate() {
        let (mm, auc) = &mut stations[n % STATIONS];
        {
            let mut a = auc.lock().unwrap();
            a.subscribers(&all, &[]);
            a.set_link(false);
        }
        mm.process_key_fallback(&mut q, ts);
        mm.rx_u_location_update_demand(&mut q, registration_sc2(issi, 1, 1));
    }
    while q.pop_front().is_some() {}
    let mut demands = 0;
    for (s, (mm, auc)) in stations.iter_mut().enumerate() {
        let mine: Vec<u32> = all.iter().copied().skip(s).step_by(STATIONS).collect();
        {
            let mut a = auc.lock().unwrap();
            a.set_link(true);
            a.subscribers(&all, &[]);
            for &issi in &mine {
                let k: [u8; 16] = [issi as u8; 16];
                let wire: Vec<_> = (0..3u8).map(|i| AuthVectorWire::from_vector(&AuthVector::from_k(&AuthKey(k), [i; 10]))).collect();
                a.add(issi, &wire);
            }
        }
        mm.process_key_fallback(&mut q, ts);
        // Within the first instant only one demand goes out (2/s: the next after 500 ms).
        for _ in 0..5 {
            mm.process_key_fallback(&mut q, ts);
        }
        assert_eq!(mm.auth_pending.len(), 1, "station {s}: throttled");
        for _ in 0..mine.len() {
            mm.key_fallback.skip(Duration::from_millis(500));
            mm.process_key_fallback(&mut q, ts);
        }
        demands += mine.iter().filter(|i| mm.auth_pending.contains_key(i)).count();
    }
    assert_eq!(demands, 25, "every radio authenticated again");
}
