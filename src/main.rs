use std::net::{IpAddr, Ipv6Addr};
use std::env;
use std::io;
use std::time;
use std::thread;
use std::os::fd::{AsRawFd, AsFd};
use std::fs::File;
use std::process::Command;
use nix::sched;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json;
use netlink_packet_route::link::{InfoKind, LinkAttribute::Address, LinkAttribute, LinkMessage, LinkInfo, LinkLayerType, LinkFlags};
use netlink_packet_route::nsid::{NsidMessage, NsidAttribute};
use netlink_packet_route::address::{AddressScope, AddressAttribute, AddressMessage};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_packet_core::{NetlinkPayload, NetlinkHeader, NetlinkMessage, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, NLM_F_ACK, NLM_F_MATCH, NLM_F_DUMP};
use netlink_packet_core::constants::{NLM_F_MULTIPART};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

const INFO: &str = "{\"version\": \"0.1.0\", \"api_version\": \"1.0.0\"}";

#[derive(Serialize, Deserialize, Debug)]
struct CreateConfig{
    name: String,
    id: String,
    driver: String,
    subnets: Vec<HashMap<String, String>>,
    options: Option<HashMap<String, String>>
}

#[derive(Serialize, Deserialize, Debug)]
struct PortMapping {
    container_port: u16,
    host_ip: String,
    host_port: u16,
    protocol: String,
    range: u16
}

#[derive(Serialize, Deserialize, Debug)]
struct NetworkOptions {
    aliases: Vec<String>,
    interface_name: String,
    static_ips: Option<Vec<String>>,
    static_mac: Option<String>,
    options: Option<HashMap<String,String>>
}

#[derive(Serialize, Deserialize, Debug)]
struct SetupConfig{
    container_id: String,
    container_name: String,
    port_mappings: Option<Vec<PortMapping>>,
    network_options: NetworkOptions,

}

struct NetlinkResponse {
    resp: Vec<NetlinkMessage<RouteNetlinkMessage>>,
    seq: u32,
}

fn main() {
    match env::args().nth(1){
        Some(arg) if arg == "info".to_string() => println!("{}",INFO),
        Some(arg) if arg == "setup".to_string() => setup(),
        Some(arg) if arg == "teardown".to_string() => teardown(),
        Some(arg) if arg == "create".to_string() => create(),
        _ => eprintln!("Invalid argument passed!")
    }
}

fn open_netlink(netns: &File) -> (Socket, Socket) {
    let mut self_file = File::open("/proc/self/ns/net").unwrap();
    let mut host_socket = Socket::new(NETLINK_ROUTE).unwrap();
    let host_addr = &SocketAddr::new(0,0);
    host_socket.bind(host_addr).unwrap();
    host_socket.connect(host_addr).unwrap();

    sched::setns(netns.as_fd(), sched::CloneFlags::CLONE_NEWNET);

    let mut cont_socket = Socket::new(NETLINK_ROUTE).unwrap();
    let cont_addr = &SocketAddr::new(0,0);
    cont_socket.bind(cont_addr);
    cont_socket.connect(cont_addr).unwrap();

    sched::setns(self_file.as_fd(), sched::CloneFlags::CLONE_NEWNET);

    return (host_socket, cont_socket)
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

fn send_netlink_msg(msg: RouteNetlinkMessage, nl: &Socket ,buffer: &mut [u8; 8192], flags: u16, seq: u32) -> NetlinkResponse {
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
        let resp: NetlinkMessage<RouteNetlinkMessage> = NetlinkMessage::deserialize(&buffer[buffer_size..]).unwrap();
        match (resp.clone().header.flags,resp.clone().payload) {
            (_,NetlinkPayload::Error(ref msg)) if msg.code != None => {
                if let Some(code) = msg.code {
                    eprintln!("{:?}", code);
                }
                break;
            },

            (NLM_F_MULTIPART, NetlinkPayload::Done(_)) => break,
            (NLM_F_MULTIPART, _) => {
                responses.push(resp.clone());
                buffer_size += resp.header.length as usize;
            },

            _ => {
                responses.push(resp.clone());
                break;
            }
        }
    }
    return NetlinkResponse{resp: responses, seq: seq + 1};
}

fn setup() {
   let mut raw_json = "".to_string();
   for line in io::stdin().lines() {
       raw_json += &line.unwrap();
   }
   let ns_path = env::args().nth(2).unwrap();
   eprintln!("{:?}", ns_path);
   eprintln!("{:?}", raw_json);
   let config: SetupConfig = serde_json::from_str(raw_json.as_str()).unwrap();
   eprintln!("{:?}", config);
   let mut ns_file = File::open(ns_path).unwrap();

   let (mut nl, mut cont_nl) = open_netlink(&ns_file);
   let mut veth = LinkMessage::default();
   let mut buffer: [u8; 8192] = [0; 8192];
   let mut seq: u32 = 0;
   let interface_name = "pod".to_owned() + &config.container_id[0..12];
   veth.attributes =  vec![LinkAttribute::IfName(interface_name.to_string()), LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Veth)])];
   let mut resp = send_netlink_msg(RouteNetlinkMessage::NewLink(veth.clone()), &nl, &mut buffer, (NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE) ,seq);


   let parent_idx: u32;
   let child_idx: u32;

   let resp = send_netlink_msg(RouteNetlinkMessage::GetLink(veth.clone()), &nl, &mut buffer, (NLM_F_REQUEST), resp.seq);
   match &resp.resp[0].payload {
       NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(m)) => {
           parent_idx = m.header.index;
           child_idx = m.header.index - 1;

       },
       _ => panic!("shouldn't be here"),
   }

   veth.header.flags = LinkFlags::Up;
   let resp = send_netlink_msg(RouteNetlinkMessage::SetLink(veth.clone()), &nl, &mut buffer, (NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE), resp.seq);

   let mut child_interface = LinkMessage::default();
   child_interface.header.index = child_idx;
   child_interface.attributes = vec![LinkAttribute::NetNsFd(ns_file.as_raw_fd().try_into().unwrap())];
   let resp = send_netlink_msg(RouteNetlinkMessage::SetLink(child_interface.clone()), &nl, &mut buffer, (NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE), resp.seq);

   let mut nsid_msg = NsidMessage::default();
   nsid_msg.attributes = vec![NsidAttribute::Fd(ns_file.as_raw_fd().try_into().unwrap())];

   child_interface.attributes = vec![];
   child_interface.header.flags = LinkFlags::Up;
   let resp = send_netlink_msg(RouteNetlinkMessage::SetLink(child_interface.clone()), &cont_nl, &mut buffer, (NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE), resp.seq);

   thread::sleep(time::Duration::from_secs(2));
   let mut addr_msg = AddressMessage::default();
   addr_msg.header.index = parent_idx;
   addr_msg.header.scope = AddressScope::Link;
   addr_msg.header.family = AddressFamily::Inet6;
   eprintln!("{:?}", addr_msg);
   let resp = send_netlink_msg(RouteNetlinkMessage::GetAddress(addr_msg.clone()), &nl, &mut buffer, NLM_F_DUMP, resp.seq);
   eprintln!("{:?}", resp.resp);





   


}

fn teardown() {
    todo!();
}
