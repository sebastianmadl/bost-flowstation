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
    assert!(matches!(&out[..], [ControlResponse::AuthReport { issi: MS, ok: true, mutual: false, left: Some(1), rs }] if rs == "31313131313131313131"));
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
