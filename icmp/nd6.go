/*
MIT License

Copyright (c) 2017 Simon Schmidt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


package icmp

import "github.com/maxymania/ipsolution/ip"
import "github.com/google/gopacket/layers"
import "net"
import "time"
import "bytes"
import "encoding/binary"
import "math/rand"

/*
 * RFC-4861 10. Protocol Constants.
 * Router constants:
 *          MAX_INITIAL_RTR_ADVERT_INTERVAL  16 seconds
 *          MAX_INITIAL_RTR_ADVERTISEMENTS    3 transmissions
 *          MAX_FINAL_RTR_ADVERTISEMENTS      3 transmissions
 *          MIN_DELAY_BETWEEN_RAS             3 seconds
 *          MAX_RA_DELAY_TIME                 .5 seconds
 *
 * Host constants:
 *          MAX_RTR_SOLICITATION_DELAY        1 second
 *          RTR_SOLICITATION_INTERVAL         4 seconds
 *          MAX_RTR_SOLICITATIONS             3 transmissions
 *
 * Node constants:
 *          MAX_MULTICAST_SOLICIT             3 transmissions
 *          MAX_UNICAST_SOLICIT               3 transmissions
 *          MAX_ANYCAST_DELAY_TIME            1 second
 *          MAX_NEIGHBOR_ADVERTISEMENT        3 transmissions
 *          REACHABLE_TIME               30,000 milliseconds
 *          RETRANS_TIMER                 1,000 milliseconds
 *          DELAY_FIRST_PROBE_TIME            5 seconds
 *          MIN_RANDOM_FACTOR                 .5
 *          MAX_RANDOM_FACTOR                 1.5
 */

/*
 * Source Link-Layer Address                    1
 * Target Link-Layer Address                    2
 * Prefix Information                           3
 * Redirected Header                            4
 * MTU                                          5
 */

type nd6_option_prefix struct {
	Ignore        uint16
	PrefixLength  uint8
	Flags         uint8
	
	ValidLifetime uint32
	Reserved2     uint32
	Prefix        [16]byte
}
type nd6_option_mtu struct{
	Ignore        uint32
	MTU           uint32
}


func ipis0(ip net.IP) bool{
	for _,b := range ip {
		if b!=0 { return false }
	}
	return true
}

func (h *Host) nd6NeighborSolicitation(i *ip.IPLayerPart, cm *layers.ICMPv6, po PacketOutput) {
	/*
	 * RFC-4861 7.1.1.  Validation of Neighbor Solicitations
	 */
	
	
	/*
	 * - The IP Hop Limit field has a value of 255, i.e., the packet
	 *   could not possibly have been forwarded by a router.
	 */
	if i.V6.HopLimit != 255 { return }
	
	/* - ICMP Checksum is valid. */
	/* XXX Should be... */
	
	/* - ICMP Code is 0. */
	if cm.TypeCode.Code() !=0 { return }
	
	/* - ICMP length (derived from the IP length) is 24 or more octets. */
	
	/*
	 * The header is 8 bytes long, (ALWAYS!) and the payload is usually 16 bytes or more. (16+8 -> 24)
	 */
	if len(cm.Payload)<16 { return }
	
	/* - Target Address is not a multicast address. */
	target := net.IP(cm.Payload[:16])
	if target[0]==0xff { return }
	
	source_addr_is_unspecified := ipis0(i.SrcIP)
	
	if source_addr_is_unspecified {
		/*
		 * - If the IP source address is the unspecified address, the IP
	         *   destination address is a solicited-node multicast address.
		 */
		
		// XXX This is only a crappy check!
		if i.DstIP[0]!=0xff { return }
		if i.DstIP[1]&0x0f!=0x02 { return }
		
	}
	
	source_lla := net.HardwareAddr(nil)
	
	options := cm.Payload[16:]
	for len(options)>1 {
		ohtype   := options[0]
		ohlength := options[1]
		
		/* - All included options have a length that is greater than zero. */
		if ohlength==0 { return }
		
		skip := ohlength<<3;
		
		if ohtype==1 {
			/*
			 * - If the IP source address is the unspecified address, there is no
			 *   source link-layer address option in the message.
			 */
			if source_addr_is_unspecified { return }
			
			
			source_lla = copymac(net.HardwareAddr(options[2:skip]))
			
			// XXX Crappy fix: 64-bit mac addresses are a possibility.
			if len(source_lla)==14 { source_lla = source_lla[:8] }
		}
		options = options[skip:]
	}
	
	if len(source_lla)>0 {
		/*
		 * RFC-4861 7.2.3.  Receipt of Neighbor Solicitations:
		 *
		 * If the Source Address is not the unspecified
		 * address and, on link layers that have addresses, the solicitation
		 * includes a Source Link-Layer Address option, then the recipient
		 * SHOULD create or update the Neighbor Cache entry for the IP Source
		 * Address of the solicitation.
		 *
		 * First, check the neighbor cache, and create if necessary.
		 */
		
		ncache := h.NC6
restartCache:
		nce := ncache.LookupOrCreate(target)
		nce.Lock()
		
		/* This handles an extremely rare pathological case. */
		if nce.Entry.Parent()!=ncache {
			nce.Unlock()
			goto restartCache
		}
		defer nce.Unlock()
		
		
		/*
		 * If an entry does not already exist, the
		 * node SHOULD create a new one and set its reachability state to STALE
		 * as specified in Section 7.3.3.
		 *
		 * If an entry already exists, and the
		 * cached link-layer address differs from the one in the received Source
		 * Link-Layer option, the cached address should be replaced by the
		 * received address, and the entry's reachability state MUST be set to
		 * STALE.
		 */
		
		incomplete := nce.State == ND6_NC_INCOMPLETE
		nonExisting := nce.State == ND6_NC__PHANTOM_
		hwaddrUnEqual := !bytes.Equal([]byte(source_lla),nce.HWAddr)
		
		if incomplete||nonExisting||hwaddrUnEqual {
			nce.State = ND6_NC_STALE
			nce.Tstamp = time.Now()
			nce.HWAddr = source_lla
			nce.Entry.MoveToBack()
		}
		// TODO: send sendchain packets.
	}
	
	/* TODO: send Neighbor Advertisements. */
	
}

func (h *Host) nd6NeighborAdvertisement(i *ip.IPLayerPart, cm *layers.ICMPv6, po PacketOutput) {
	/*
	 * RFC-4861 7.1.1.  Validation of Neighbor Advertisements
	 */
	
	
	/*
	 * - The IP Hop Limit field has a value of 255, i.e., the packet
	 *   could not possibly have been forwarded by a router.
	 */
	if i.V6.HopLimit != 255 { return }
	
	/* - ICMP Checksum is valid. */
	/* XXX Should be... */
	
	/* - ICMP Code is 0. */
	if cm.TypeCode.Code() !=0 { return }
	
	/* - ICMP length (derived from the IP length) is 24 or more octets. */
	
	/*
	 * The header is 8 bytes long, (ALWAYS!) and the payload is usually 16 bytes or more. (16+8 -> 24)
	 */
	if len(cm.Payload)<16 { return }
	
	/* - Target Address is not a multicast address. */
	target := net.IP(cm.Payload[:16])
	if target[0]==0xff { return }
	
	flags := cm.TypeBytes[0]
	const (
		flag_router = 0x80
		flag_solicited = 0x40
		flag_override = 0x20
	)
	
	/*
	 * - If the IP Destination Address is a multicast address the
	 *   Solicited flag is zero.
	 */
	if i.DstIP[0]==0xff && (flags&flag_solicited)!=0 { return }
	
	target_lla := net.HardwareAddr(nil)
	
	options := cm.Payload[16:]
	for len(options)>1 {
		ohtype   := options[0]
		ohlength := options[1]
		
		/* - All included options have a length that is greater than zero. */
		if ohlength==0 { return }
		
		skip := ohlength<<3;
		
		if ohtype==2 {
			target_lla = copymac(net.HardwareAddr(options[2:skip]))
			
			// XXX Crappy fix: 64-bit mac addresses are a possibility.
			if len(target_lla)==14 { target_lla = target_lla[:8] }
		}
		options = options[skip:]
	}
	
	/*
	 * If the target's Neighbor Cache entry is in the INCOMPLETE state when
	 * the advertisement is received, one of two things happens.  If the
	 * link layer has addresses and no Target Link-Layer Address option is
	 * included, the receiving node SHOULD silently discard the received
	 * advertisement.
	 */
	
	if len(target_lla)==0 { return }
	
	ncache := h.NC6
restartCache:
	nce := ncache.LookupOrCreate(target)
	
	/*
	 * RFC-4861 7.2.5.  Receipt of Neighbor Advertisements
	 */
	
	if nce==nil {
		/*
		 * There is no need to create an entry if none exists, since the
		 * recipient has apparently not initiated any communication with the
		 * target.
		 */
	}
	nce.Lock()
	
	/* This handles an extremely rare pathological case. */
	if nce.Entry.Parent()!=ncache {
		nce.Unlock()
		goto restartCache
	}
	defer nce.Unlock()
	
	
	was_router := nce.IsRouter
	
	if nce.State == ND6_NC_INCOMPLETE {
		/*
		 * If the target's Neighbor Cache entry is in the INCOMPLETE [...] the
		 * receiving node performs the following steps:
		 *
		 *  - It records the link-layer address in the Neighbor Cache entry.
		 */
		nce.Tstamp = time.Now()
		nce.HWAddr = target_lla
		
		/*
		 *  - If the advertisement's Solicited flag is set, the state of the
		 *    entry is set to REACHABLE; otherwise, it is set to STALE.
		 */
		if (flags&flag_solicited)!=0 {
			nce.State = ND6_NC_REACHABLE
		}else{
			nce.State = ND6_NC_STALE
		}
		
		/*
		 *  - It sets the IsRouter flag in the cache entry based on the Router
		 *    flag in the received advertisement.
		 */
		nce.IsRouter = (flags&flag_router)!=0
		
		/*
		 *  - It sends any packets queued for the neighbor awaiting address
		 *    resolution.
		 */
		// TODO:
	}else{
		/*
		 * If the target's Neighbor Cache entry is in any state other than
		 * INCOMPLETE when the advertisement is received, the following actions
		 * take place:
		 */
		
		if (flags&flag_override)!=0 {
			/*
			 * I. If the Override flag is clear and the supplied link-layer address
			 *    differs from that in the cache, then one of two actions takes
			 *    place:
			 *
			 *    a. If the state of the entry is REACHABLE, set it to STALE, but
			 *       do not update the entry in any other way.
			 *    b. Otherwise, the received advertisement should be ignored and
			 *       MUST NOT update the cache.
			 */
			if bytes.Equal(target_lla,nce.HWAddr) {
				nce.State = ND6_NC_STALE
				nce.Tstamp = time.Now()
				nce.Entry.MoveToBack()
			}
		}else{
			/*
			 * II. If the Override flag is set, or the supplied link-layer address
			 *     is the same as that in the cache, or no Target Link-Layer Address
			 *     option was supplied, the received advertisement MUST update the
			 *     Neighbor Cache entry as follows:
			 *
			 *     - The link-layer address in the Target Link-Layer Address option
			 *       MUST be inserted in the cache (if one is supplied and differs
			 *       from the already recorded address).
			 */
			nce.HWAddr = target_lla
			nce.Tstamp = time.Now()
			nce.Entry.MoveToBack()
			
			/*
			 *     - If the Solicited flag is set, the state of the entry MUST be
			 *       set to REACHABLE.  If the Solicited flag is zero and the link-
			 *       layer address was updated with a different address, the state
			 *       MUST be set to STALE.  Otherwise, the entry's state remains
			 *       unchanged.
			 */
			
			if (flags&flag_solicited)!=0 {
				nce.State = ND6_NC_REACHABLE
			}else{
				nce.State = ND6_NC_STALE
			}
			
			/*
			 *     - The IsRouter flag in the cache entry MUST be set based on the
			 *       Router flag in the received advertisement.
			 */
			nce.IsRouter = (flags&flag_router)!=0
		}
	}
	
	/*
	 * If the IsRouter flag is set after Update, clear the WasRouter variable.
	 *
	 * After this, WasRouter is only TRUE if the IsRouter flag changed from TRUE to FALSE.
	 */
	if nce.IsRouter { was_router = false }
	
	/*
	 * In those cases
	 * where the IsRouter flag changes from TRUE to FALSE as a result
	 * of this update, the node MUST remove that router from the
	 * Default Router List and update the Destination Cache entries
	 * for all destinations using that neighbor as a router as
	 * specified in Section 7.3.3.
	 */
	if was_router {
		nce.RouterEntry.Remove()
	}
	
	/* TODO Send 'sendchain' packets. */
	
}

func (h *Host) nd6RouterAdvertisement(i *ip.IPLayerPart, cm *layers.ICMPv6, po PacketOutput) {
	prefixed := make([]*nd6_option_prefix,0,16)
	mtu := uint32(0)
	NOW := time.Now()

	/*
	 * RFC-4861 6.1.2.  Validation of Router Advertisement Messages
	 *
	 * - IP Source Address is a link-local address.  Routers must use
	 *   their link-local address as the source for Router Advertisement
	 *   and Redirect messages so that hosts can uniquely identify
	 *   routers.
	 */
	if i.SrcIP[0]!=0xfe { return }
	if (i.SrcIP[0]&0xc0)!=0x80 { return }
	
	/*
	 * - The IP Hop Limit field has a value of 255, i.e., the packet
         * could not possibly have been forwarded by a router.
	 */
	if i.V6.HopLimit != 255 { return }
	
	/* - ICMP Checksum is valid. */
	// XXX hopefully...
	
	/* - ICMP Code is 0. */
	if cm.TypeCode.Code() !=0 { return }
	
	/* - ICMP length (derived from the IP length) is 16 or more octets. */
	if len(cm.Payload)<8 { return } // 8 byte header + 8 byte payload = 16
	
	
	/* Decode the Router Advertisement Header */
	var radv1 struct {
		CurHopLimit uint8
		Flags uint8
		RouterLifetime uint16
	}
	var radv2 struct {
		ReachableTime uint32
		RetransTimer uint32
	}
	binary.Read(bytes.NewReader(cm.TypeBytes),binary.BigEndian,&radv1)
	binary.Read(bytes.NewReader(cm.Payload),binary.BigEndian,&radv2)
	
	source_lla := net.HardwareAddr(nil)
	
	options := cm.Payload[8:]
	for len(options)>1 {
		ohtype   := options[0]
		ohlength := options[1]
		
		/* - All included options have a length that is greater than zero. */
		if ohlength==0 { return }
		
		skip := ohlength<<3
		/*
		 * Source Link-Layer Address                    1
		 * Target Link-Layer Address                    2
		 * Prefix Information                           3
		 * Redirected Header                            4
		 * MTU                                          5
		 */
		
		switch ohtype {
		/* Source Link-Layer Address */
		case 1:
			source_lla = copymac(net.HardwareAddr(options[2:skip]))
			
			// XXX Crappy fix: 64-bit mac addresses are a possibility.
			if len(source_lla)==14 { source_lla = source_lla[:8] }
		/* Prefix Information */
		case 3:
			p := new(nd6_option_prefix)
			if binary.Read(bytes.NewReader(options[:skip]),binary.BigEndian,p)==nil {
				prefixed = append(prefixed,p)
			}
		/* MTU */
		case 5:
			var mtuopt nd6_option_mtu
			if binary.Read(bytes.NewReader(options[:skip]),binary.BigEndian,mtuopt)!=nil { return }
			mtu = mtuopt.MTU
			if mtu < 1280 { mtu = 1280 } // IP6_DEFAULT_MTU; = 1280
		}
		options = options[skip:]
	}
	/*
	 * If the received Cur Hop Limit value is non-zero, the host SHOULD set
	 * its CurHopLimit variable to the received value.
	 */
	if radv1.CurHopLimit!=0 {
		h.CurHopLimit = radv1.CurHopLimit
	}
	
	/*
	 * RFC:
	 *   If the received Reachable Time value is non-zero, the host SHOULD set
	 *   its BaseReachableTime variable to the received value. If the new
	 *   value differs from the previous value, the host SHOULD re-compute a
	 *   new random ReachableTime value.  ReachableTime is computed as a
	 *   uniformly distributed random value between MIN_RANDOM_FACTOR and
	 *   MAX_RANDOM_FACTOR times the BaseReachableTime.  Using a random
	 *   component eliminates the possibility that Neighbor Unreachability
	 *   Detection messages will synchronize with each other.
	 *
	 * BTW: MIN_RANDOM_FACTOR = 0.5 ; MAX_RANDOM_FACTOR = 1.5
	 *
	 * How to calculate ReachableTime:
	 *    ReachableTime := BaseReachableTime * random(0.5 ... 1.5)
	 *  aka.
	 *    ReachableTime := 1 + random(0 ... BaseReachableTime) + floor(BaseReachableTime / 2)
	 */
	if radv2.ReachableTime!=0 {
		BaseReachableTime := radv2.ReachableTime
		ReachableTime     := (BaseReachableTime>>1) + 1 + (rand.Uint32()%BaseReachableTime)
		
		h.BaseReachableTime = BaseReachableTime
		h.ReachableTime = ReachableTime
	}
	
	/*
	 * The RetransTimer variable SHOULD be copied from the Retrans Timer
	 * field, if the received value is non-zero.
	 */
	if radv2.RetransTimer!=0 { h.RetransTimer = radv2.RetransTimer }
	
	/*
	 * If the MTU option is present, hosts SHOULD copy the option's value
	 * into LinkMTU so long as the value is greater than or equal to the
	 * minimum link MTU [IPv6] and does not exceed the maximum LinkMTU value
	 * specified in the link-type-specific document (e.g., [IPv6-ETHER]).
	 */
	if mtu!=0 {
		if h.IPv6MTU==0 || h.IPv6MTU<mtu { h.IPv6MTU = mtu }
	}
	
	
	
	/*
	 * NOTE THAT:
	 *   If a Neighbor Cache entry is created
	 *   for the router, its reachability state MUST be set to STALE as
	 *   specified in Section 7.3.3.  If a cache entry already exists and is
	 *   updated with a different link-layer address, the reachability state
	 *   MUST also be set to STALE.
	 */
	
	
	ncache := h.NC6
restartCache:
	nce := ncache.LookupOrCreate(i.SrcIP)
	nce.Lock()
	
	/* This handles an extremely rare pathological case. */
	if nce.Entry.Parent()!=ncache {
		nce.Unlock()
		goto restartCache
	}
	/* XXX We should be using ``defer nce.Unlock()'' here, but we need to unlock earlier. */
	
	/*
	 * If the advertisement contains a Source Link-Layer Address
	 * option, the link-layer address SHOULD be recorded in the Neighbor
	 * Cache entry for the router (creating an entry if necessary) and the
	 * IsRouter flag in the Neighbor Cache entry MUST be set to TRUE.
	 */
	if len(source_lla)>0 {
		switch nce.State {
		case ND6_NC_REACHABLE,ND6_NC_DELAY,ND6_NC_PROBE:
			if !bytes.Equal(source_lla,nce.HWAddr) { break }
			fallthrough
		case ND6_NC__PHANTOM_,ND6_NC_INCOMPLETE:
			nce.State = ND6_NC_STALE
		}
		nce.HWAddr = source_lla
		nce.Tstamp = NOW
		nce.Entry.MoveToBack()
	}else{
		/*
		 * If no Source Link-Layer Address is included, but a corresponding Neighbor
		 * Cache entry exists, its IsRouter flag MUST be set to TRUE.
		 */
		nce.IsRouter = true
		nce.Entry.MoveToBack()
	}
	
	/*
	 * If the address is already present in the host's Default Router
	 * List and the received Router Lifetime value is zero, immediately
	 * time-out the entry as specified in Section 6.3.5.
	 */
	if radv1.RouterLifetime==0 {
		nce.RouterLifetime = 0
		nce.RouterEntry.Remove()
	
	/*
	 * If the address is not already present in the host's Default
	 * Router List, and the advertisement's Router Lifetime is non-
	 * zero, create a new entry in the list, and initialize its
	 * invalidation timer value from the advertisement's Router
	 * Lifetime field.
	 *
	 * If the address is already present in the host's Default Router
	 * List as a result of a previously received advertisement, reset
	 * its invalidation timer to the Router Lifetime value in the newly
	 * received advertisement.
	 */
	}else{
		nce.RouterLifetime = radv1.RouterLifetime
		nce.RouterTstamp = NOW
		h.NC6.Routers.PushBack(&nce.RouterEntry)
	}
	
	/* Unlock before processing prefixes. */
	nce.Unlock()
	
	h.Host.Lock();  h.Host.Unlock()
	
	/*
	 * For each Prefix Information option with the on-link flag set, a host
	 * does the following:
	 */
	for _,prefix := range prefixed {
		/*
		 * - If the prefix is the link-local prefix, silently ignore the
		 *   Prefix Information option.
		 */
		if (prefix.Prefix[0]==0xfe) && ((prefix.Prefix[1]&0xc0)==0x80) { continue }
		
		var pfk ip.IPv6Prefix
		
		if prefix.PrefixLength>128 { continue }
		mask := net.CIDRMask(int(prefix.PrefixLength),128)
		pfk.Len = prefix.PrefixLength
		
		for i,p := range prefix.Prefix {
			pfk.IP[i] = p & mask[i]
		}
		
		//shouldAdd := false
		//shouldRemove := false
		
		pe,ok := h.Host.Prefix6[pfk]
		
		if (!ok) && prefix.ValidLifetime!=0 {
			/*
			 * - If the prefix is not already present in the Prefix List, and the
			 *   Prefix Information option's Valid Lifetime field is non-zero,
			 *   create a new entry for the prefix and initialize its
			 *   invalidation timer to the Valid Lifetime value in the Prefix
			 *   Information option.
			 */
			pe = new(ip.IPv6PrefixEntry)
			pe.List.Init()
			pe.Prefix = pfk
			pe.Lifetime = prefix.ValidLifetime
			pe.Tstamp = NOW
			pe.Onlink = (prefix.Flags&0x80)!=0
			pe.Slaac  = (prefix.Flags&0x40)!=0
			h.Host.Prefix6[pfk] = pe
			//shouldAdd = true
		} else if ok {
			/*
			 * - If the prefix is already present in the host's Prefix List as
			 *   the result of a previously received advertisement, reset its
			 *   invalidation timer to the Valid Lifetime value in the Prefix
			 *   Information option.  If the new Lifetime value is zero, time-out
			 *   the prefix immediately (see Section 6.3.5).
			 */
			
			if prefix.ValidLifetime==0 {
				/* If the new Lifetime value is zero, time-out the prefix immediately. */
				delete(h.Host.Prefix6,pfk)
				//shouldRemove = true
			} else {
				pe.Lifetime = prefix.ValidLifetime
				pe.Tstamp = NOW
			}
		}
		/*
		 * - If the Prefix Information option's Valid Lifetime field is zero,
		 *   and the prefix is not present in the host's Prefix List,
		 *   silently ignore the option.
		 */
		
		// TODO: Use Prefixes.
	}
}

func (h *Host) nd6Redirect(i *ip.IPLayerPart, cm *layers.ICMPv6, po PacketOutput) {
	/* TODO: Verify redirect message before processing. */
	if len(cm.Payload) < 32 { return }
	
	var target,dest IPv6Addr
	copy(target.Array[:],cm.Payload[:16])
	copy(dest.Array[:],cm.Payload[16:])
	h.NC6.AddRedirect(target,dest)
}

