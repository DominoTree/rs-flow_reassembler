extern crate nom;
extern crate pktparse;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use nom::IResult;
use pktparse::{ethernet, ipv4, tcp};

#[derive(Debug)]
pub struct FlowAssembler {
    pub build: bool,
    pub flows: HashMap<u32, Flow>,
    pub timeout: Duration,
}

#[derive(Debug)]
pub struct Packet {
    pub ip: pktparse::ipv4::IPv4Header,
    pub tcp: pktparse::tcp::TcpHeader,
    pub ts: Instant,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub struct Flow {
    pub data: HashMap<u32, Packet>,
    pub ack: Vec<u32>,
    pub flow_start: Instant,
    pub last_packet: Instant,
    pub fin_recvd: Option<u32>
}

#[derive(Debug)]
pub struct TCPSession {
    pub initiator: String,
    pub responder: String,
    pub src_port: u16,
    pub dest_port: u16,
    pub session_start: Instant,
    pub session_end: Instant,
    pub flows: Vec<AssembledFlow>
}

#[derive(Debug)]
pub struct AssembledFlow {
    pub from: String,
    pub to: String,
    pub bytes: Vec<u8>,
}

impl<'a> FlowAssembler {
    #[inline]
    pub fn new(secs: u64, build: bool) -> FlowAssembler {
        FlowAssembler {
            build,
            flows: HashMap::new(),
            timeout: Duration::from_secs(secs),
        }
    }

    pub fn assemble(&mut self) -> Option<TCPSession> {
        None
    }

    #[inline]
    pub fn add_packet(&mut self, packet: Vec<u8>, rxhash: u32) -> Option<Flow> {
        //TODO: find a way not to have to pop and push flows
        //maybe the compiler is nice about this
        //index flows based on rxhash calculated by lunix
        let mut flow = match self.flows.remove(&rxhash) {
            Some(mut flow) => {
                flow.last_packet = Instant::now();
                flow
            },
            None => {
                Flow {
                    data: HashMap::new(),
                    ack: Vec::new(),
                    flow_start: Instant::now(),
                    last_packet: Instant::now(),
                    fin_recvd: None
                }
            }
        };

        if let Some(should_end) = flow.add_packet(packet.to_owned()) {
            if should_end {
                //let's just return a flow record here if a packet finished one out
                if self.build {

                }

                return Some(flow);
            }
        }
        self.flows.insert(rxhash, flow).unwrap();
        None
    }

    #[inline]
    pub fn flush_flows(&mut self) -> Vec<Flow> {
        let mut hashes = Vec::new();
        for (hash, flow) in &self.flows {
            if flow.last_packet.elapsed() > self.timeout {
                hashes.push(*hash);
            }
        }

        let mut flows = Vec::new();

        for hash in hashes {
            flows.push(self.flows.remove(&hash).unwrap());
        }

        //just return a vec of flows that have passed an arbitrary timeout
        //the timeout can be adjusted on the fly
        flows
    }
}

impl Flow {
    #[inline]
    fn should_end(&mut self, tcp: &tcp::TcpHeader) -> bool {
        //we either get an ACK that matches the sequence number of a FIN, or we get a RST
        if let Some(ack_nr) = self.fin_recvd {
            if tcp.sequence_no == ack_nr && tcp.flag_ack {
                return true;
            }
        }

        //if we have a FIN and we've already received an ACK for this sequence
        if tcp.flag_fin && self.ack.contains(&tcp.sequence_no) {
            return true;
        }

        tcp.flag_rst
    }

    #[inline]
    pub fn add_packet(&mut self, data: Vec<u8>) -> Option<bool> {
        let ts = Instant::now();
        self.last_packet = ts;

        if let IResult::Done(remainder, frame) = ethernet::parse_ethernet_frame(&data[82..]) {
            if frame.ethertype == ethernet::EtherType::IPv4 {
                if let IResult::Done(remainder, v4) = ipv4::parse_ipv4_header(&remainder) {
                    if v4.protocol == ipv4::IPv4Protocol::TCP {
                        if let IResult::Done(payload, tcp) = tcp::parse_tcp_header(&remainder) {
                            //check to see if the tcp sequence number already exists within the
                            //flow - if so, we can stop here
                            if !self.ack.contains(&tcp.ack_no) {
                                self.ack.push(tcp.ack_no)
                            }
                            if !self.data.contains_key(&tcp.sequence_no) {
                                //check to see if this packet ends the flow
                                let should_end = self.should_end(&tcp);
                                self.data.insert(tcp.sequence_no, Packet {
                                    ip: v4,
                                    tcp: tcp,
                                    ts: ts,
                                    payload: payload.to_owned()
                                });
                                return Some(should_end)
                            }
                        }
                    }
                }
            }
        }
        None
    }
}

