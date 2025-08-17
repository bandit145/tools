use netlink_packet_core::constants::NLM_F_MULTIPART;
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_MATCH, NLM_F_REQUEST, NetlinkHeader,
    NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::address::{AddressAttribute, AddressMessage, AddressScope};
use netlink_packet_route::link::{
    InfoKind, LinkAttribute, LinkAttribute::Address, LinkFlags, LinkInfo, LinkLayerType,
    LinkMessage,
};
use netlink_packet_route::nsid::{NsidAttribute, NsidMessage};
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage, RouteType};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use nix::sched;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io;
use std::net::{IpAddr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd};
use std::process::Command;
use std::thread;
use std::time;

const INFO: &str = "{\"version\": \"0.1.0\", \"api_version\": \"1.0.0\"}";

#[derive(Serialize, Deserialize, Debug)]
struct CreateConfig {
    name: String,
    id: String,
    driver: String,
    subnets: Vec<HashMap<String, Option<String>>>,
    options: Option<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PortMapping {
    container_port: u16,
    host_ip: String,
    host_port: u16,
    protocol: String,
    range: u16,
}

#[derive(Serialize, Deserialize, Debug)]
struct NetworkOptions {
    aliases: Vec<String>,
    interface_name: String,
    static_ips: Option<Vec<String>>,
    static_mac: Option<String>,
    options: Option<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SetupConfig {
    container_id: String,
    container_name: String,
    port_mappings: Option<Vec<PortMapping>>,
    network_options: NetworkOptions,
    network: CreateConfig,
}

struct NetlinkResponse {
    resp: Vec<NetlinkMessage<RouteNetlinkMessage>>,
    seq: u32,
}

fn main() {
    match env::args().nth(1) {
        Some(arg) if arg == "info".to_string() => println!("{}", INFO),
        Some(arg) if arg == "setup".to_string() => setup(),
        Some(arg) if arg == "teardown".to_string() => teardown(),
        Some(arg) if arg == "create".to_string() => create(),
        _ => println!("{}", json!({"error": "Invalid argument passed!"})),
    }
}

fn open_netlink(netns: &File) -> (Socket, Socket) {
    let self_file = File::open("/proc/self/ns/net").unwrap();
    let mut host_socket = Socket::new(NETLINK_ROUTE).unwrap();
    let host_addr = &SocketAddr::new(0, 0);
    host_socket.bind(host_addr).unwrap();
    host_socket.connect(host_addr).unwrap();

    sched::setns(netns.as_fd(), sched::CloneFlags::CLONE_NEWNET);

    let mut cont_socket = Socket::new(NETLINK_ROUTE).unwrap();
    let cont_addr = &SocketAddr::new(0, 0);
    cont_socket.bind(cont_addr);
    cont_socket.connect(cont_addr).unwrap();

    sched::setns(self_file.as_fd(), sched::CloneFlags::CLONE_NEWNET);

    return (host_socket, cont_socket);
}

fn create() {
    let mut raw_json = "".to_string();
    for line in io::stdin().lines() {
        raw_json += &line.unwrap();
    }
    let config: CreateConfig = serde_json::from_str(raw_json.as_str()).unwrap();
    if config.subnets.len() != 1 {
        eprintln!("gaped");
    }
    println!("{}", serde_json::to_string(&config).unwrap());
}

fn send_netlink_msg(
    msg: RouteNetlinkMessage,
    nl: &Socket,
    buffer: &mut [u8; 8192],
    flags: u16,
    seq: u32,
) -> NetlinkResponse {
    let mut packet = NetlinkMessage::new(NetlinkHeader::default(), NetlinkPayload::from(msg));
    packet.header.sequence_number = seq;
    packet.header.flags = NLM_F_REQUEST | flags;
    let mut responses: Vec<NetlinkMessage<RouteNetlinkMessage>> = vec![];
    packet.finalize();
    packet.serialize(&mut buffer[..]);
    nl.send(&buffer[..packet.buffer_len()], 0).unwrap();
    nl.recv(&mut &mut buffer[..], 0);
    let mut buffer_size = 0;
    loop {
        let resp: NetlinkMessage<RouteNetlinkMessage> =
            NetlinkMessage::deserialize(&buffer[buffer_size..]).unwrap();
        match (resp.clone().header.flags, resp.clone().payload) {
            (_, NetlinkPayload::Error(ref msg)) if msg.code != None => {
                if let Some(code) = msg.code {
                    println!("{}", json!({"error": format!("Netlink error, code: {}", code)}));
                    std::process::exit(2);
                }
                break;
            }

            (NLM_F_MULTIPART, NetlinkPayload::Done(_)) => break,
            (NLM_F_MULTIPART, _) => {
                responses.push(resp.clone());
                buffer_size += resp.header.length as usize;
            }

            _ => {
                responses.push(resp.clone());
                break;
            }
        }
    }
    return NetlinkResponse {
        resp: responses,
        seq: seq + 1,
    };
}

fn get_link_local_address(
    interface_idx: u32,
    nl: &Socket,
    buffer: &mut [u8; 8192],
    seq: u32,
) -> (Option<Ipv6Addr>, NetlinkResponse) {
    let mut addr_msg = AddressMessage::default();
    addr_msg.header.family = AddressFamily::Inet6;
    let resp = send_netlink_msg(
        RouteNetlinkMessage::GetAddress(addr_msg.clone()),
        &nl,
        buffer,
        NLM_F_DUMP,
        seq,
    );
    let mut link_local: Option<Ipv6Addr> = None;
    for msg in &resp.resp {
        match &msg.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(addr_msg))
                if addr_msg.header.index == interface_idx
                    && addr_msg.header.scope == AddressScope::Link =>
            {
                for attr in &addr_msg.attributes {
                    match attr {
                        AddressAttribute::Address(IpAddr::V6(addr)) => {
                            link_local = Some(*addr);
                            break;
                        }
                        _ => {}
                    }
                }
                break;
            }
            _ => {}
        }
    }
    return (link_local, resp);
}

fn setup() {
    let mut raw_json = "".to_string();
    for line in io::stdin().lines() {
        raw_json += &line.unwrap();
    }
    let ns_path = env::args().nth(2).unwrap();
    let mut anycast_addresses: HashMap<String, Ipv6Addr> = HashMap::new();
    let config: SetupConfig = serde_json::from_str(raw_json.as_str()).unwrap();
    let container_ip: Ipv6Addr = config.network_options.static_ips.clone().unwrap()[0]
        .parse()
        .unwrap();
    let mut cont_service = "".to_string();
    for (k, v) in std::env::vars(){
        if k == "PODMAN_ANYCAST_SERVICE".to_string() {
            cont_service = v;
            break;
        }
    }
    let mut ns_file = File::open(ns_path).unwrap();
    for (k, v) in config.network.options.clone().unwrap().into_iter() {
        if k.contains("anycast-addr") {
            let svc_name = k.split("-").max().unwrap();
            anycast_addresses.insert(String::from(svc_name), v.parse().unwrap());
        }
    }
    let svc_ip = anycast_addresses.get(&cont_service);
    let (mut nl, mut cont_nl) = open_netlink(&ns_file);
    let mut veth = LinkMessage::default();
    let mut buffer: [u8; 8192] = [0; 8192];
    let mut seq: u32 = 0;
    let mut out = Command::new("nft")
        .arg("list")
        .arg("tables")
        .output()
        .unwrap();
    if !str::from_utf8(&out.stdout)
        .unwrap()
        .contains("table ip6 podman")
    {
        out = Command::new("nft")
            .arg("add")
            .arg("table")
            .arg("ip6")
            .arg("podman")
            .output()
            .unwrap();
        out = Command::new("nft")
            .arg("add chain ip6 nat { type nat hook prerouting priority 0 }")
            .output()
            .unwrap();
    }
    let interface_name = "pod".to_owned() + &config.container_id[0..12];
    veth.attributes = vec![
        LinkAttribute::IfName(interface_name.to_string()),
        LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Veth)]),
    ];
    let mut resp = send_netlink_msg(
        RouteNetlinkMessage::NewLink(veth.clone()),
        &nl,
        &mut buffer,
        (NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE),
        seq,
    );

    let parent_idx: u32;
    let child_idx: u32;

    let resp = send_netlink_msg(
        RouteNetlinkMessage::GetLink(veth.clone()),
        &nl,
        &mut buffer,
        (NLM_F_REQUEST),
        resp.seq,
    );
    match &resp.resp[0].payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(m)) => {
            parent_idx = m.header.index;
            child_idx = m.header.index - 1;
        }
        _ => {
            println!(
                "{}",
                json!({"error": "Something has gone seriously wrong and netlink has not responded with a NewLink message"})
            );
            std::process::exit(2);
        }
    }

    veth.header.flags = LinkFlags::Up;
    let resp = send_netlink_msg(
        RouteNetlinkMessage::SetLink(veth.clone()),
        &nl,
        &mut buffer,
        (NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE),
        resp.seq,
    );

    let mut child_interface = LinkMessage::default();
    child_interface.header.index = child_idx;
    child_interface.attributes = vec![LinkAttribute::NetNsFd(
        ns_file.as_raw_fd().try_into().unwrap(),
    )];
    let resp = send_netlink_msg(
        RouteNetlinkMessage::SetLink(child_interface.clone()),
        &nl,
        &mut buffer,
        (NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE),
        resp.seq,
    );
    let mut nsid_msg = NsidMessage::default();
    nsid_msg.attributes = vec![NsidAttribute::Fd(ns_file.as_raw_fd().try_into().unwrap())];

    child_interface.attributes = vec![];
    child_interface.header.flags = LinkFlags::Up;
    let resp = send_netlink_msg(
        RouteNetlinkMessage::SetLink(child_interface.clone()),
        &cont_nl,
        &mut buffer,
        (NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE),
        resp.seq,
    );

    let mut new_addr = AddressMessage::default();
    new_addr.header.family = AddressFamily::Inet6;
    new_addr.header.prefix_len = 128;
    new_addr.header.index = child_idx;
    new_addr.attributes = vec![AddressAttribute::Address(IpAddr::V6(container_ip))];
    let resp = send_netlink_msg(RouteNetlinkMessage::NewAddress(new_addr.clone()), &cont_nl, &mut buffer, (NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE), resp.seq);

    thread::sleep(time::Duration::from_secs(2));

    let (mut gw_linklocal, resp) =
        get_link_local_address(child_idx, &cont_nl, &mut buffer, resp.seq);
    let (mut link_local, resp) = get_link_local_address(parent_idx, &nl, &mut buffer, resp.seq);

    if gw_linklocal.is_none() {
        println!(
            "{}",
            json!({"error": "No matching link local address for interface found!"})
        );
        std::process::exit(2);
    }

    let mut def_gw_rt = RouteMessage::default();
    def_gw_rt.header.address_family = AddressFamily::Inet6;
    def_gw_rt.header.kind = RouteType::Unicast;
    def_gw_rt.header.destination_prefix_length = 0;
    def_gw_rt.attributes = vec![
        RouteAttribute::Gateway(RouteAddress::Inet6(link_local.unwrap())),
        RouteAttribute::Destination(RouteAddress::Inet6("::".parse().unwrap())),
        RouteAttribute::Oif(child_idx),
    ];

    let resp = send_netlink_msg(
        RouteNetlinkMessage::NewRoute(def_gw_rt.clone()),
        &cont_nl,
        &mut buffer,
        (NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE),
        resp.seq,
    );

    match svc_ip {
        Some(ip) => {
            let mut svc_rt = RouteMessage::default();
            svc_rt.header.address_family = AddressFamily::Inet6;
            svc_rt.header.kind = RouteType::Unicast;
            svc_rt.header.destination_prefix_length = 128;
            svc_rt.attributes = vec![
                RouteAttribute::Gateway(RouteAddress::Inet6(link_local.unwrap())),
                RouteAttribute::Destination(RouteAddress::Inet6(*ip)),
                RouteAttribute::Oif(parent_idx),
            ];

            let resp = send_netlink_msg(
                RouteNetlinkMessage::NewRoute(svc_rt.clone()),
                &nl,
                &mut buffer,
                (NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE),
                resp.seq,
            );

            svc_rt.attributes = vec![
                RouteAttribute::Gateway(RouteAddress::Inet6(link_local.unwrap())),
                RouteAttribute::Destination(RouteAddress::Inet6(container_ip)),
                RouteAttribute::Oif(parent_idx),
            ];

            let resp = send_netlink_msg(
                RouteNetlinkMessage::NewRoute(svc_rt.clone()),
                &nl,
                &mut buffer,
                (NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE),
                resp.seq,
            );

            let nf_nat_rule = format!(
                "add rule podman nat meta iif {} ip6 daddr {} dnat to {}",
                child_idx, ip, container_ip
            );
        },
        _ => {},
    }

    let mut cont_rt = RouteMessage::default();
    cont_rt.header.address_family = AddressFamily::Inet6;
    cont_rt.header.kind = RouteType::Unicast;
    cont_rt.header.destination_prefix_length = 128;
    cont_rt.attributes = vec![RouteAttribute::Gateway(RouteAddress::Inet6(gw_linklocal.unwrap())),
    RouteAttribute::Destination(RouteAddress::Inet6(container_ip)),
    RouteAttribute::Oif(parent_idx),
    ];
    let resp = send_netlink_msg(RouteNetlinkMessage::NewRoute(cont_rt.clone()), &nl, &mut buffer, (NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE), resp.seq);
    println!("{}", serde_json::to_string(&config).unwrap());

}

fn teardown() {
    todo!();
}
