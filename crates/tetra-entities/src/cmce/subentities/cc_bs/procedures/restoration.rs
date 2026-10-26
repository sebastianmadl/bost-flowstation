use super::*;

/// How long a U-CALL RESTORE may wait for a Brew group call this cell only holds as pending
/// inbound (or has not been handed yet) to come up locally. Project value, not an ETSI timer:
/// the MS waits for D-CALL RESTORE with T307, min 2 s and max 8 s, the value chosen by the MS
/// (TS 100 392-2 clause 14.6, group calls); 5 s lies within that range. It stays below MLE's
/// `RESTORE_ANSWER_TIMEOUT` (10 s) so CMCE always answers first. (5 s × 72 timeslots/s.)
pub(in crate::cmce::subentities::cc_bs) const DEFERRED_RESTORE_TIMEOUT_TS: i32 = 5 * 18 * 4;

/// A U-CALL RESTORE for a group call that runs on the Brew network but not (yet) on this cell.
#[derive(Debug, Clone)]
pub(in crate::cmce::subentities::cc_bs) struct DeferredRestore {
    pub sender: TetraAddress,
    pub handle: u32,
    pub link_id: u32,
    pub endpoint_id: u32,
    /// The call identifier the MS restores with (the old cell's)
    pub call_id: u16,
    pub gssi: u32,
    pub request_to_transmit: bool,
    pub since: TdmaTime,
}

impl CcBsSubentity {
    /// A cell linked to other cells (site switch, or any Brew network) restores a group call by
    /// its GSSI when the MS brings another cell's call identifier: TS 100 392-2 clause 14.7.1.3
    /// lets D-CALL RESTORE give the call a new identifier. Only for groups the network shares
    /// with this cell; a local-only group call with the same GSSI is a different call.
    fn restores_group_by_gssi(&self, gssi: u32) -> bool {
        brew::is_site_linked(&self.config) || (brew::is_active(&self.config) && brew::is_network_group_inbound_allowed(&self.config, gssi))
    }

    pub(in crate::cmce::subentities::cc_bs) fn fsm_on_u_call_restore(
        &mut self,
        queue: &mut MessageQueue,
        sender: TetraAddress,
        handle: u32,
        link_id: u32,
        endpoint_id: u32,
        pdu: UCallRestore,
    ) {
        let restored_call_id = pdu.call_identifier;
        let mut call_id = restored_call_id;
        // The other party of a group call is its GSSI. The basic service information (note 3 to
        // clause 14.7.2.2) tells an individual call apart; without it, assume a group call as the
        // multi-cell lookup always did.
        let group_restore = pdu
            .basic_service_information
            .as_ref()
            .is_none_or(|b| b.communication_type != CommunicationType::P2p);
        let gssi = pdu.other_party_ssi.filter(|_| group_restore).map(|ssi| ssi as u32);
        self.request_registration_if_unknown(queue, sender.ssi);

        // A group call is the MS's only if it is to the group the MS names: call identifiers are
        // per cell, so another cell's identifier can equal a local call to a different group.
        let is_own_group_call = |call: &ActiveCall| gssi.is_none_or(|g| call.dest_gssi == g);
        let own_group_call = self.active_calls.get(&call_id).is_some_and(is_own_group_call);
        let own_individual_call = self
            .individual_calls
            .get(&call_id)
            .is_some_and(|c| sender.ssi == c.calling_addr.ssi || sender.ssi == c.called_addr.ssi);

        // The MS reselected from another cell and restores with that cell's call identifier.
        // Find the same group call here by its GSSI; D-CALL RESTORE gives our id as the new one.
        if !own_individual_call
            && !own_group_call
            && let Some(gssi) = gssi
            && self.restores_group_by_gssi(gssi)
        {
            if let Some((&id, _)) = self.active_calls.iter().find(|(_, c)| c.dest_gssi == gssi) {
                tracing::info!(
                    "CMCE: U-CALL RESTORE from ISSI {} for call_id={} (other cell) → local call_id={} gssi={}",
                    sender.ssi,
                    call_id,
                    id,
                    gssi
                );
                call_id = id;
            } else if !brew::is_site_linked(&self.config) {
                // Separate station on a Brew network: the call runs elsewhere and is at most
                // held here as pending inbound (no local listener yet). Wait for it.
                self.defer_call_restore(
                    queue,
                    DeferredRestore {
                        sender,
                        handle,
                        link_id,
                        endpoint_id,
                        call_id,
                        gssi,
                        request_to_transmit: pdu.request_to_transmit_send_data,
                        since: self.dltime,
                    },
                );
                return;
            }
        }

        if let Some(call) = self.individual_calls.get_mut(&call_id) {
            if !call.is_active() || (sender.ssi != call.calling_addr.ssi && sender.ssi != call.called_addr.ssi) {
                self.reject_call_restore(queue, sender, handle, link_id, endpoint_id, call_id);
                return;
            }

            if call.begin_restore().is_err() {
                self.reject_call_restore(queue, sender, handle, link_id, endpoint_id, call_id);
                return;
            }
            call.active_timer_started = Some(self.dltime);
            // Only grant when the floor is free or the sender already holds it (same decision as
            // the U-TX DEMAND path). Granting while the peer is talking gives two simultaneous
            // transmitters and a stale floor_holder the UL-inactivity watchdog never ceases.
            // Duplex calls keep floor_holder = None, so they still always grant.
            let grant = if !pdu.request_to_transmit_send_data {
                TransmissionGrant::NotGranted
            } else if call.floor_holder.is_none() || call.is_floor_held_by(sender.ssi) {
                if call.is_simplex() {
                    call.grant_floor(sender);
                }
                TransmissionGrant::Granted
            } else {
                TransmissionGrant::GrantedToOtherUser
            };
            call.complete_restore();
            self.send_d_call_restore(queue, sender, handle, link_id, endpoint_id, call_id, call_id, grant, None);
            return;
        }

        if self.active_calls.get(&call_id).is_some_and(is_own_group_call) {
            self.restore_group_call(
                queue,
                sender,
                handle,
                link_id,
                endpoint_id,
                restored_call_id,
                call_id,
                pdu.request_to_transmit_send_data,
            );
            return;
        }

        self.reject_call_restore(queue, sender, handle, link_id, endpoint_id, call_id);
    }

    /// Restore an MS into the local group call `call_id` (D-CALL RESTORE, floor if requested and
    /// free). `restored_call_id` is the identifier the MS sent (another cell's, possibly).
    #[allow(clippy::too_many_arguments)]
    fn restore_group_call(
        &mut self,
        queue: &mut MessageQueue,
        sender: TetraAddress,
        handle: u32,
        link_id: u32,
        endpoint_id: u32,
        restored_call_id: u16,
        call_id: u16,
        request_to_transmit: bool,
    ) {
        let Some(call) = self.active_calls.get_mut(&call_id) else {
            return;
        };
        if call.begin_restore().is_err() {
            self.reject_call_restore(queue, sender, handle, link_id, endpoint_id, call_id);
            return;
        }
        // Clause 14.5.2.2.4: "granted to another user" switches the MS's U-plane on to receive,
        // "not granted" leaves it off; a listener restored into a running over must hear it.
        let grant = if request_to_transmit && (!call.tx_active || call.source_issi == sender.ssi) {
            call.grant_floor(sender.ssi, Some(sender));
            TransmissionGrant::Granted
        } else if call.tx_active {
            TransmissionGrant::GrantedToOtherUser
        } else {
            TransmissionGrant::NotGranted
        };
        // Clause 14.5.2.2.4: a layer 2 channel allocation shall accompany D-CALL RESTORE when the
        // U-plane is switched on, and may when it stays off but a traffic channel is available.
        // The call has its traffic channel, so always send the MS there.
        let mut timeslots = [false; 4];
        timeslots[call.ts as usize - 1] = true;
        let chan_alloc = CmceChanAllocReq {
            usage: Some(call.usage),
            alloc_type: ChanAllocType::Replace,
            carrier: Some(call.carrier_num),
            timeslots,
            ul_dl_assigned: UlDlAssignment::Both,
        };

        call.complete_restore();
        let floor = (grant == TransmissionGrant::Granted).then_some(GroupFloorGrant {
            call_id,
            source_issi: sender.ssi,
            dest_gssi: call.dest_gssi,
            carrier_num: call.carrier_num,
            ts: call.ts,
            is_group: true,
        });
        self.send_d_call_restore(
            queue,
            sender,
            handle,
            link_id,
            endpoint_id,
            restored_call_id,
            call_id,
            grant,
            Some(chan_alloc),
        );

        // A restore that hands over the floor must arm UMAC's UL-inactivity timer exactly like
        // every other grant path (see setup.rs / U-TX DEMAND): without the FloorGranted a
        // restored talker that then goes silent pins the traffic slot until the absolute call
        // time-out — forever for a duplex/Infinite call, so repeats exhaust the cell.
        if let Some(floor) = floor {
            self.send_d_tx_granted_facch(queue, call_id, floor.source_issi, floor.dest_gssi, floor.carrier_num, floor.ts);
            self.notify_floor_granted(queue, floor, true, BrewNotification::IfGroupRoutable(floor.dest_gssi));
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn send_d_call_restore(
        &self,
        queue: &mut MessageQueue,
        sender: TetraAddress,
        handle: u32,
        link_id: u32,
        endpoint_id: u32,
        restored_call_id: u16,
        call_id: u16,
        grant: TransmissionGrant,
        chan_alloc: Option<CmceChanAllocReq>,
    ) {
        let new_call_id = (call_id != restored_call_id).then_some(call_id);
        let sdu = Self::build_d_call_restore(restored_call_id, new_call_id, grant, Some(CallStatus::Callcontinue));
        let mut msg = Self::build_sapmsg_direct(sdu, self.dltime, sender, handle, link_id, endpoint_id);
        if let SapMsgInner::LcmcMleUnitdataReq(prim) = &mut msg.msg {
            prim.chan_alloc = chan_alloc;
        }
        queue.push_back(msg);
    }

    fn reject_call_restore(
        &self,
        queue: &mut MessageQueue,
        sender: TetraAddress,
        handle: u32,
        link_id: u32,
        endpoint_id: u32,
        call_id: u16,
    ) {
        tracing::info!("CMCE: rejecting U-CALL RESTORE for unknown or inactive call_id={}", call_id);
        let sdu = Self::build_d_release(call_id, DisconnectCause::CallRestorationOfTheOtherUserFailed);
        let msg = Self::build_sapmsg_direct(sdu, self.dltime, sender, handle, link_id, endpoint_id);
        queue.push_back(msg);
    }

    /// Park a U-CALL RESTORE until the Brew group call comes up on this cell.
    ///
    /// The MS was in the call on another cell, so it listens to the group: count it as a local
    /// listener, which promotes a call Brew holds as pending inbound (`GroupListenersAvailable`).
    /// The count is the cell's own bookkeeping, nothing is sent on air; it is dropped again when
    /// the restore fails or the call ends, unless MM affiliates the MS to the group meanwhile.
    /// An MS without a registration here was asked to register (`request_registration_if_unknown`);
    /// its registration makes the network hand this cell the running call.
    pub(in crate::cmce::subentities::cc_bs) fn defer_call_restore(&mut self, queue: &mut MessageQueue, restore: DeferredRestore) {
        let (issi, gssi) = (restore.sender.ssi, restore.gssi);
        tracing::info!(
            "CMCE: U-CALL RESTORE from ISSI {} for call_id={} gssi={} — no local call yet, waiting for the network call",
            issi,
            restore.call_id,
            gssi
        );
        // A repeated U-CALL RESTORE replaces the parked one (fresh handle, same deadline).
        if let Some(old) = self.deferred_restores.iter_mut().find(|r| r.sender.ssi == issi) {
            let since = old.since;
            *old = DeferredRestore { since, ..restore };
        } else {
            self.deferred_restores.push(restore);
        }

        let affiliated = self.subscriber_groups.get(&issi).is_some_and(|groups| groups.contains(&gssi));
        if !affiliated && self.restore_listeners.insert((issi, gssi)) {
            let first_listener = !self.has_listener(gssi);
            self.inc_group_listener(gssi);
            if first_listener {
                Self::push_control(queue, TetraEntity::Brew, CallControl::GroupListenersAvailable { gssi });
            }
        }
    }

    /// An MS restoring a call on a separate Brew station without being registered there
    /// reselected within its registered location area, so it did not register (TS 100 392-2
    /// clause 16). Ask it to: infrastructure initiated registration, D-LOCATION UPDATE COMMAND with
    /// group report request (clauses 16.4.3 and 16.9.2.8: "The SwMI may initiate registration at
    /// any time"). Its
    /// registration moves the ISSI to this station on Brew, so the network routes the next calls,
    /// SDS and individual calls here. A linked multi-cell station tracks its radios itself.
    fn request_registration_if_unknown(&self, queue: &mut MessageQueue, issi: u32) {
        if !brew::is_active(&self.config) || brew::is_site_linked(&self.config) || self.is_locally_registered_issi(issi) {
            return;
        }
        tracing::info!(
            "CMCE: restoring ISSI {} is not registered on this cell — requesting a location update",
            issi
        );
        queue.push_back(SapMsg {
            sap: Sap::Control,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Mm,
            msg: SapMsgInner::MmRequestLocationUpdate { issi },
        });
    }

    /// Per tick: answer parked restores whose group call is now up, reject the ones that waited
    /// too long (D-RELEASE, which MLE turns into D-RESTORE-FAIL).
    pub(in crate::cmce::subentities::cc_bs) fn drive_deferred_restores(&mut self, queue: &mut MessageQueue) {
        if self.deferred_restores.is_empty() {
            return;
        }
        let parked = std::mem::take(&mut self.deferred_restores);
        for restore in parked {
            let live_call = self
                .active_calls
                .iter()
                .find(|(_, c)| c.dest_gssi == restore.gssi)
                .map(|(&id, _)| id);
            if let Some(call_id) = live_call {
                tracing::info!(
                    "CMCE: network call for gssi={} is up — restoring ISSI {} into call_id={}",
                    restore.gssi,
                    restore.sender.ssi,
                    call_id
                );
                self.restore_group_call(
                    queue,
                    restore.sender,
                    restore.handle,
                    restore.link_id,
                    restore.endpoint_id,
                    restore.call_id,
                    call_id,
                    restore.request_to_transmit,
                );
            } else if restore.since.age(self.dltime) >= DEFERRED_RESTORE_TIMEOUT_TS {
                tracing::info!(
                    "CMCE: no network call for gssi={} came up for ISSI {}'s restore",
                    restore.gssi,
                    restore.sender.ssi
                );
                self.reject_call_restore(
                    queue,
                    restore.sender,
                    restore.handle,
                    restore.link_id,
                    restore.endpoint_id,
                    restore.call_id,
                );
                self.drop_restore_listener(queue, restore.sender.ssi, restore.gssi);
            } else {
                self.deferred_restores.push(restore);
            }
        }
    }

    /// Undo the listener count a restore added for (issi, gssi), if MM did not affiliate since.
    pub(in crate::cmce::subentities::cc_bs) fn drop_restore_listener(&mut self, queue: &mut MessageQueue, issi: u32, gssi: u32) {
        if self.restore_listeners.remove(&(issi, gssi)) {
            self.dec_group_listener(gssi);
            self.drop_group_calls_if_unlistened(queue, gssi);
        }
    }

    /// The group call ended: listeners that only came from a restore are gone with it.
    pub(in crate::cmce::subentities::cc_bs) fn drop_restore_listeners_for_group(&mut self, gssi: u32) {
        let pairs: Vec<(u32, u32)> = self.restore_listeners.iter().filter(|(_, g)| *g == gssi).copied().collect();
        for pair in pairs {
            self.restore_listeners.remove(&pair);
            self.dec_group_listener(gssi);
        }
    }
}
