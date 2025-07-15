use netavark::{
    network::{
        core_utils::{open_netlink_sockets, CoreUtils},
        netlink, types,
    },
    new_error,
    plugin::{Info, Plugin, PluginExec, API_VERSION},
};

use std::net::{IpAddr, Ipv6Addr};
use ipnet::IpNet;
use netlink_packet_route::link::{InfoKind, LinkAttribute::Address, LinkAttribute::Link};
use netlink_packet_route::address::{AddressScope, AddressAttribute};
use netlink_packet_route::{AddressFamily};

fn main() {
    let info = Info::new("0.1.0".to_owned(), API_VERSION.to_owned(), None);

    PluginExec::new(Exec{}, info).exec();
}

fn generate_eui64_addr(mac: &Vec<u8>) -> Vec<u16>{
    let mut host_addr: Vec<u16> = vec![];
    host_addr.push(u16::from(mac[0]) << 8 | u16::from(mac[1]));
    host_addr.push(u16::from(mac[2]) << 8 | 0x00ff);
    host_addr.push(u16::from(mac[3]) | 0xfe00);
    host_addr.push(u16::from(mac[4]) << 8 | u16::from(mac[5]));
    return host_addr;
}

struct Exec{}

impl Plugin for Exec {

    fn create(&self, network: types::Network) -> Result<types::Network, Box<dyn std::error::Error>>{
        if network.subnets.clone().unwrap().len() != 1 {
            return Err(new_error!("This requires one and only one subnet!"))
        }
        Ok(network)

    }

    fn setup(&self, netns: String, opts: types::NetworkPluginExec) -> Result<types::StatusBlock, Box<dyn std::error::Error>> {
        let (mut nl, mut netns) = open_netlink_sockets(&netns)?;
        let short_id = &opts.container_id[0..12];
        let link_name = format!("pod{}", short_id);
        let subnet = &opts.network.subnets.unwrap()[0];
        let create_link_options = netlink::CreateLinkOptions::new(link_name.clone(), InfoKind::Veth);
        nl.netlink.create_link(create_link_options)?;
        let mut link = nl.netlink.get_link(netlink::LinkID::Name(link_name.clone()))?;
        let mut cont_link_idx: u32 = 0;
        let mut cont_link_local: Vec<u16> = vec![];
        let mut host_link_local: Vec<u16> = vec![];
        for item in &link.attributes {
            match item {
                Link(idx) => {
                    cont_link_idx = *idx;
                    let cont_link = nl.netlink.get_link(netlink::LinkID::ID(cont_link_idx))?;
                    for attr in cont_link.attributes {
                        match attr {
                            Address(mac) => {
                                cont_link_local = generate_eui64_addr(&mac);
                            },
                            _ => {},
                        }
                    }
                },
                Address(mac) => host_link_local = generate_eui64_addr(&mac),

                _ => {},
                
            }
        }
        eprintln!("{:?}", link);
        let mut cont_link = nl.netlink.get_link(netlink::LinkID::ID(link.header.index - 1));
        let mut ip_segments: [u16;8] = [0; 8];
        match subnet.subnet.addr() {
            IpAddr::V6(addr) => ip_segments = addr.segments(),
            _ => {},
        }
        let cont_addr = IpNet::new(IpAddr::V6(Ipv6Addr::new(ip_segments[0], ip_segments[1], ip_segments[2], ip_segments[3], ip_segments[4], cont_link_local[1], cont_link_local[2], cont_link_local[3])),subnet.subnet.prefix_len())?;
        link = nl.netlink.get_link(netlink::LinkID::Name(link_name.clone()))?;
        let _ = nl.netlink.set_link_ns(cont_link_idx, netns.file);
        let _ = nl.netlink.set_up(netlink::LinkID::ID(link.header.index));
        let _ = netns.netlink.set_up(netlink::LinkID::ID(cont_link_idx));
        let _ = netns.netlink.add_addr(cont_link_idx, &cont_addr);
        cont_link = netns.netlink.get_link(netlink::LinkID::ID(link.header.index-1));
        let mut cont_link_local: Ipv6Addr;
        for addr in netns.netlink.dump_addresses()?{
            if matches!(addr.header.family,AddressFamily::Inet6) && matches!(addr.header.scope, AddressScope::Link) {
                for attr in addr.attributes {
                    if matches!(attr, AddressAttribute::Local(_)) {
                        cont_link_local = IpAddr::V6(AddressAttribute::Local(attr));
                    }
                }
            }
        }



        let response = types::StatusBlock {
            dns_server_ips: None,
            dns_search_domains: None,
            interfaces: None,
        };
        Ok(response)

    }

    fn teardown(&self, netns: String, opts: types::NetworkPluginExec) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

}
