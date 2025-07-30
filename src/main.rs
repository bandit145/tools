
use std::net::{IpAddr, Ipv6Addr};
use std::env;
use std::io;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json;
use netlink_packet_route::link::{InfoKind, LinkAttribute::Address, LinkAttribute, LinkMessage, LinkInfo, LinkLayerType};
use netlink_packet_route::address::{AddressScope, AddressAttribute};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_packet_core::{NetlinkPayload, NetlinkHeader, NetlinkMessage, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, NLM_F_ACK, NLM_F_MATCH};
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
    static_ips: Vec<String>,
    static_mac: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct SetupConfig{
    container_id: String,
    container_name: String,
    port_mappings: Vec<PortMapping>,
    network: CreateConfig,
    network_options: NetworkOptions,

}

struct NetlinkResponse {
    resp: NetlinkMessage<RouteNetlinkMessage>,
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

fn open_netlink() -> Socket {
    let mut socket = Socket::new(NETLINK_ROUTE).unwrap();
    let addr = &SocketAddr::new(0,0);
    socket.bind(addr).unwrap();
    socket.connect(addr).unwrap();

    return socket
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
    packet.finalize();
    packet.serialize(&mut buffer[..]);
    nl.send(&buffer[..packet.buffer_len()], 0).unwrap();
    nl.recv(&mut &mut buffer[..], 0);
    let resp: NetlinkMessage<RouteNetlinkMessage> = NetlinkMessage::deserialize(&buffer[0..]).unwrap();
    match resp.payload {
        NetlinkPayload::Error(ref msg) if msg.code != None => {
            if let Some(code) = msg.code {
                eprintln!("{:?}", code);
            }
        },
        _ => {},
    }
    return NetlinkResponse{resp: resp, seq: seq + 1};
}

fn setup() {
   let mut raw_json = "".to_string();
   for line in io::stdin().lines() {
       raw_json += &line.unwrap();
   }
   eprintln!("{:?}", env::args().nth(2).unwrap());

   let config: SetupConfig = serde_json::from_str(raw_json.as_str()).unwrap();
   eprintln!("{:?}", config);
   let mut nl = open_netlink();
   let mut veth = LinkMessage::default();
   let mut buffer: [u8; 8192] = [0; 8192];
   let mut seq: u32 = 0;
   let interface_name = "pod".to_owned() + &config.container_id[0..12];
   veth.attributes =  vec![LinkAttribute::IfName(interface_name.to_string()), LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Veth)])];
   let mut resp = send_netlink_msg(RouteNetlinkMessage::NewLink(veth.clone()), &nl, &mut buffer, (NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE) ,seq);

   resp = send_netlink_msg(RouteNetlinkMessage::GetLink(veth.clone()), &nl, &mut buffer, (NLM_F_ACK | NLM_F_EXCL | NLM_F_MATCH), resp.seq);
   println!("{:?}", resp.resp);

   


}

fn teardown() {
    todo!();
}
