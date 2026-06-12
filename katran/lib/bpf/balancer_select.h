/* Copyright (C) 2018-present, Facebook, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 */

#ifndef __BALANCER_SELECT_H
#define __BALANCER_SELECT_H

/*
 * Real-server selection helpers (consistent hashing + LRU connection table +
 * the associated stats). These were originally defined as static-inline
 * functions directly inside balancer.bpf.c; they were relocated into this
 * header, unchanged, so the NPU pipeline's SELECT-stage core can reuse Katran's
 * exact selection logic in its own translation unit while PARSE/ENCAP run on
 * other cores. balancer.bpf.c #includes this header in their place, so the
 * monolithic build (CPU harness, single-core NPU) is byte-for-byte equivalent.
 */

#include <linux/in.h>
#include <string.h>

#include "katran/lib/linux_includes/bpf.h"
#include "katran/lib/linux_includes/bpf_helpers.h"
#include "katran/lib/linux_includes/jhash.h"

#include "katran/lib/bpf/balancer_consts.h"
#include "katran/lib/bpf/balancer_maps.h"
#include "katran/lib/bpf/balancer_structs.h"

__attribute__((__always_inline__)) static inline __u32 get_packet_hash(
    struct packet_description* pckt,
    bool hash_16bytes) {
  if (hash_16bytes) {
    return jhash_2words(
        jhash(pckt->flow.srcv6, 16, INIT_JHASH_SEED_V6),
        pckt->flow.ports,
        INIT_JHASH_SEED);
  } else {
    return jhash_2words(pckt->flow.src, pckt->flow.ports, INIT_JHASH_SEED);
  }
}

__attribute__((__always_inline__)) static inline bool is_under_flood(
    __u64* cur_time) {
  __u32 conn_rate_key = MAX_VIPS + NEW_CONN_RATE_CNTR;
  struct lb_stats* conn_rate_stats =
      bpf_map_lookup_elem(&stats, &conn_rate_key);
  if (!conn_rate_stats) {
    return true;
  }
  *cur_time = bpf_ktime_get_ns();
  // we are going to check that new connections rate is less than predefined
  // value; conn_rate_stats.v1 contains number of new connections for the last
  // second, v2 - when last time quanta started.
  if ((*cur_time - conn_rate_stats->v2) > ONE_SEC) {
    // new time quanta; reseting counters
    conn_rate_stats->v1 = 1;
    conn_rate_stats->v2 = *cur_time;
  } else {
    conn_rate_stats->v1 += 1;
    if (conn_rate_stats->v1 > MAX_CONN_RATE) {
      // we are exceding max connections rate. bypasing lru update and
      // source routing lookup
      return true;
    }
  }
  return false;
}

__attribute__((__always_inline__)) static inline void
increment_ch_drop_no_real() {
  __u32 ch_drop_stats_key = MAX_VIPS + CH_DROP_STATS;
  struct lb_stats* ch_drop_stats =
      bpf_map_lookup_elem(&stats, &ch_drop_stats_key);
  if (!ch_drop_stats) {
    return;
  }
  ch_drop_stats->v1 += 1;
}

__attribute__((__always_inline__)) static inline void
increment_ch_drop_real_0() {
  __u32 ch_drop_stats_key = MAX_VIPS + CH_DROP_STATS;
  struct lb_stats* ch_drop_stats =
      bpf_map_lookup_elem(&stats, &ch_drop_stats_key);
  if (!ch_drop_stats) {
    return;
  }
  ch_drop_stats->v2 += 1;
}

__attribute__((__always_inline__)) static inline bool get_packet_dst(
    struct real_definition** real,
    struct packet_description* pckt,
    struct vip_meta* vip_info,
    bool is_ipv6,
    void* lru_map) {
  // to update lru w/ new connection
  struct real_pos_lru new_dst_lru = {};
  bool under_flood = false;
  bool src_found = false;
  __u32* real_pos;
  __u64 cur_time = 0;
  __u32 hash;
  __u32 key;

  under_flood = is_under_flood(&cur_time);

#ifdef LPM_SRC_LOOKUP
  if ((vip_info->flags & F_SRC_ROUTING) && !under_flood) {
    __u32* lpm_val;
    if (is_ipv6) {
      struct v6_lpm_key lpm_key_v6 = {};
      lpm_key_v6.prefixlen = 128;
      memcpy(lpm_key_v6.addr, pckt->flow.srcv6, 16);
      lpm_val = bpf_map_lookup_elem(&lpm_src_v6, &lpm_key_v6);
    } else {
      struct v4_lpm_key lpm_key_v4 = {};
      lpm_key_v4.addr = pckt->flow.src;
      lpm_key_v4.prefixlen = 32;
      lpm_val = bpf_map_lookup_elem(&lpm_src_v4, &lpm_key_v4);
    }
    if (lpm_val) {
      src_found = true;
      key = *lpm_val;
    }
    __u32 stats_key = MAX_VIPS + LPM_SRC_CNTRS;
    struct lb_stats* data_stats = bpf_map_lookup_elem(&stats, &stats_key);
    if (data_stats) {
      if (src_found) {
        data_stats->v2 += 1;
      } else {
        data_stats->v1 += 1;
      }
    }
  }
#endif
  if (!src_found) {
    bool hash_16bytes = is_ipv6;

    if (vip_info->flags & F_HASH_DPORT_ONLY) {
      // service which only use dst port for hash calculation
      // e.g. if packets has same dst port -> they will go to the same real.
      // usually VoIP related services.
      pckt->flow.port16[0] = pckt->flow.port16[1];
      memset(pckt->flow.srcv6, 0, 16);
    }
    hash = get_packet_hash(pckt, hash_16bytes) % RING_SIZE;
    key = RING_SIZE * (vip_info->vip_num) + hash;

    real_pos = bpf_map_lookup_elem(&ch_rings, &key);
    if (!real_pos) {
      return false;
    }
    key = *real_pos;
    if (key == 0) {
      // Real ids start from 1, so we don't map the id 0 to any real. This
      // is likely to happen if the ch ring for a vip is uninitialized.
      increment_ch_drop_real_0();
      return false;
    }
  }
  pckt->real_index = key;
  *real = bpf_map_lookup_elem(&reals, &key);
  if (!(*real)) {
    // The id we retrieved from the hash ring is out of bounds in the reals
    // array.
    increment_ch_drop_no_real();
    return false;
  }
  if (lru_map && !(vip_info->flags & F_LRU_BYPASS) && !under_flood &&
      !(pckt->flags & F_RST_SET)) {
    if (pckt->flow.proto == IPPROTO_UDP) {
      new_dst_lru.atime = cur_time;
    }
    new_dst_lru.pos = key;
    bpf_map_update_elem(lru_map, &pckt->flow, &new_dst_lru, BPF_ANY);
  }
  return true;
}

__attribute__((__always_inline__)) static inline void connection_table_lookup(
    struct real_definition** real,
    struct packet_description* pckt,
    void* lru_map,
    bool isGlobalLru) {
  struct real_pos_lru* dst_lru;
  __u64 cur_time;
  __u32 key;
  dst_lru = bpf_map_lookup_elem(lru_map, &pckt->flow);
  if (!dst_lru) {
    return;
  }
  if (!isGlobalLru && pckt->flow.proto == IPPROTO_UDP) {
    cur_time = bpf_ktime_get_ns();
    if (cur_time - dst_lru->atime > LRU_UDP_TIMEOUT) {
      return;
    }
    dst_lru->atime = cur_time;
  }
  key = dst_lru->pos;
  pckt->real_index = key;
  *real = bpf_map_lookup_elem(&reals, &key);
  return;
}

__attribute__((__always_inline__)) static inline int update_vip_lru_miss_stats(
    struct vip_definition* vip,
    struct packet_description* pckt,
    struct vip_meta* vip_info,
    bool is_ipv6) {
  // track the lru miss counter of vip in vip_miss_stats
  __u32 vip_miss_stats_key = 0;
  struct vip_definition* lru_miss_stat_vip =
      bpf_map_lookup_elem(&vip_miss_stats, &vip_miss_stats_key);
  if (!lru_miss_stat_vip) {
    return XDP_DROP;
  }
  bool address_match = (is_ipv6 &&
                        (lru_miss_stat_vip->vipv6[0] == vip->vipv6[0] &&
                         lru_miss_stat_vip->vipv6[1] == vip->vipv6[1] &&
                         lru_miss_stat_vip->vipv6[2] == vip->vipv6[2] &&
                         lru_miss_stat_vip->vipv6[3] == vip->vipv6[3])) ||
      (!is_ipv6 && lru_miss_stat_vip->vip == vip->vip);
  bool port_match = lru_miss_stat_vip->port == vip->port;
  bool proto_match = lru_miss_stat_vip->proto = vip->proto;
  bool vip_match = address_match && port_match && proto_match;
  if (vip_match) {
    __u32 lru_stats_key = pckt->real_index;
    __u32* lru_miss_stat = bpf_map_lookup_elem(&lru_miss_stats, &lru_stats_key);
    if (!lru_miss_stat) {
      return XDP_DROP;
    }
    *lru_miss_stat += 1;
  }
  return FURTHER_PROCESSING;
}

// compare the real index stored in the pckt(from server id based routing)
// with the real index in lru_map
// update the existing value if they don't match and check_only is false
__attribute__((__always_inline__)) static inline int
check_and_update_real_index_in_lru(
    struct packet_description* pckt,
    void* lru_map) {
  struct real_pos_lru* dst_lru = bpf_map_lookup_elem(lru_map, &pckt->flow);
  if (dst_lru) {
    if (dst_lru->pos == pckt->real_index) {
      return DST_MATCH_IN_LRU;
    } else {
      dst_lru->pos = pckt->real_index;
      return DST_MISMATCH_IN_LRU;
    }
  }
  __u64 cur_time;
  if (is_under_flood(&cur_time)) {
    return DST_NOT_FOUND_IN_LRU;
  }
  struct real_pos_lru new_dst_lru = {};
  new_dst_lru.pos = pckt->real_index;
  bpf_map_update_elem(lru_map, &pckt->flow, &new_dst_lru, BPF_ANY);
  return DST_NOT_FOUND_IN_LRU;
}

__attribute__((__always_inline__)) static inline void
incr_server_id_routing_stats(__u32 vip_num, bool newConn, bool misMatchInLRU) {
  struct lb_stats* per_vip_stats =
      bpf_map_lookup_elem(&server_id_stats, &vip_num);
  if (!per_vip_stats) {
    return;
  }
  if (newConn) {
    per_vip_stats->v1 += 1;
  }
  if (misMatchInLRU) {
    per_vip_stats->v2 += 1;
  }
}

__attribute__((__always_inline__)) static inline int check_udp_flow_migration(
    struct real_definition** dst,
    struct packet_description* pckt,
    struct vip_meta* vip_info,
    struct vip_definition* vip) {
  __u64 cur_time;
  if (dst && pckt->flow.proto == IPPROTO_UDP &&
      vip_info->flags & F_UDP_FLOW_MIGRATION && !is_under_flood(&cur_time)) {
    // Check if the real is down using the vip_to_down_reals_map
    void* down_reals_map = bpf_map_lookup_elem(&vip_to_down_reals_map, vip);
    if (down_reals_map) {
      void* down_real = bpf_map_lookup_elem(down_reals_map, &pckt->real_index);
      if (down_real) {
        // If the real is in the map means is down, remove the destination so
        // it is re-hashed
        *dst = NULL;
        __u32 stats_key = MAX_VIPS + UDP_FLOW_MIGRATION_STATS;
        struct lb_stats* stats_data = bpf_map_lookup_elem(&stats, &stats_key);
        if (stats_data) {
          stats_data->v1 += 1;
        }
      }
    }
  }
  return FURTHER_PROCESSING;
}

#endif // of __BALANCER_SELECT_H
