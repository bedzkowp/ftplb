/*
 * Copyright 2018-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package pl.edu.pw;

import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.*;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.*;
import org.onosproject.net.packet.*;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.*;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    private FtpPacketProcessor ftpPacketProcessor = new FtpPacketProcessor();
    private PacketPriority packetPriority = PacketPriority.MEDIUM;

    private ApplicationId appId;
    private TrafficSelector selector;
    private TrafficSelector selector2;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private HostStore hostStore;

    private Ip4Address sharedAddress;
    private List<Ip4Address> hostsAssignedToSharedAddress = new ArrayList<>();
    private Map<Ip4Address, Ip4Address> activeSessionsHostToServer = new HashMap<>();
    private Map<Ip4Address, List<Ip4Address>> hostsWithActiveFtpSessionsAssignedToOldSharedAddresses;
    private Random random = new Random();

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("pl.edu.pw");
        packetService.addProcessor(ftpPacketProcessor, PacketProcessor.director(1)); // TODO check priority
        requestIntercepts();
        loadInitialConfig();
        log.info("Packet priotiry REACTIVE/MEDIUM" + PacketPriority.REACTIVE + "/" + PacketPriority.MEDIUM);
        log.info("Started: " + appId.name());
    }

    @Deactivate
    protected void deactivate() {
       packetService.removeProcessor(ftpPacketProcessor);
       ftpPacketProcessor = null;
       withdrawIntercepts();
        // TODO drop all flows installed by this app
        log.info("Stopped: " + appId.name());
    }


    // TODO check if this can be deleted
    private void requestIntercepts() {
        selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_ARP)
                .build();

        selector2 = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .build();
        packetService.requestPackets(selector, packetPriority, appId); // TODO check with HIGH or MEDIUM
        packetService.requestPackets(selector2, packetPriority, appId);
    }

    private void withdrawIntercepts() {
        packetService.cancelPackets(selector, packetPriority, appId);
        packetService.cancelPackets(selector2, packetPriority, appId);
    }

    private void loadInitialConfig() {
        // TODO load from REST and check for correctness
        sharedAddress = Ip4Address.valueOf("10.0.1.10");
        Ip4Address serverAddress1 = Ip4Address.valueOf("10.0.1.1");
        Ip4Address serverAddress2 = Ip4Address.valueOf("10.0.1.2");
        Ip4Address serverAddress3 = Ip4Address.valueOf("10.0.1.3");
        hostsAssignedToSharedAddress.add(serverAddress1);
        hostsAssignedToSharedAddress.add(serverAddress2);
        hostsAssignedToSharedAddress.add(serverAddress3);

        Host host1 = hostService.getHostsByIp(serverAddress1).iterator().next();
//        Set<IpAddress> ipSEt = new HashSet<>();
//        ipSEt.add(serverAddress1);

//        HostDescription hostDescription = new DefaultHostDescription(host1.mac(),
//                host1.vlan(),
//                host1.location(),
//                Collections.unmodifiableSet(ipSEt),
//                DefaultAnnotations.EMPTY);
//
//        hostStore.createOrUpdateHost(host1.providerId(),
//                HostId.hostId(host1.mac()),
//                hostDescription,
//                false);

        log.info("Host ips: " + hostService.getHost(HostId.hostId(host1.mac())).ipAddresses());
        hostService.getHosts().forEach(host -> log.info("Host: " + host));

    }

    private Optional<Ip4Address> getNextServerIp() {
        int index = random.nextInt(hostsAssignedToSharedAddress.size());
        return Optional.ofNullable(Ip4Address.valueOf("10.0.1.1"));
        // TODO get from list
        // return hostsAssignedToSharedAddress.get(index);
    }

    private class FtpPacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            InboundPacket inPacket = context.inPacket();
            Ethernet ethPacket = inPacket.parsed();
            ConnectPoint srcConnectPoint = inPacket.receivedFrom();

            if(ethPacket == null) {
                return;
            }

            switch (EthType.EtherType.lookup(ethPacket.getEtherType())) {
                case ARP:
                    ARP arpPacket = (ARP) ethPacket.getPayload();
                    Ip4Address targetAddress = Ip4Address.valueOf(arpPacket.getTargetProtocolAddress());

                    if(arpPacket.getOpCode() == ARP.OP_REQUEST &&
                            targetAddress.equals(sharedAddress)) {
                        log.info("Got ARP request for shared address: " + arpPacket);
                        Optional<Ip4Address> nextServerIpOptional = getNextServerIp(); // TODO throw exception
                        if(nextServerIpOptional.isPresent()) {
                            Ip4Address nextServerIp = nextServerIpOptional.get();
                            Set<Host> hosts = hostService.getHostsByIp(nextServerIp);
                            if(hosts.size() == 0) {
                                log.info("hosts size is 0");
                                return; // TODO throw exception
                            } else if(hosts.size() > 1) {
                                log.info("hosts size is > 1");
                                return; // TODO throw exception
                            } else {
                                Host srcHost = hostService.getHost(HostId.hostId(
                                        MacAddress.valueOf(arpPacket.getSenderHardwareAddress())));
                                if(srcConnectPoint.deviceId().equals(srcHost.location().deviceId())
                                    && srcConnectPoint.port().equals(srcHost.location().port())
                                ) {
                                    MacAddress nextServerMac = hosts.iterator().next().mac();

                                    Ethernet arpReply = ARP.buildArpReply(targetAddress, nextServerMac, ethPacket);
                                    // TODO check topo if it is switch connected to src
                                    TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                            .setOutput(srcConnectPoint.port())
                                            .build();
                                    log.info("Emiting to device and port " + srcConnectPoint.deviceId() + " " +
                                            srcConnectPoint.port());
                                    packetService.emit(new DefaultOutboundPacket(
                                            srcConnectPoint.deviceId(),
                                            treatment,
                                            ByteBuffer.wrap(arpReply.serialize())));
                                }

                            }
                        } else {
                            log.info("Next server is optional");
                            return;
                        }
                    }
                    break;
                case IPV4:
                    IPv4 ipv4Packet = (IPv4) ethPacket.getPayload();
                    log.info("Received IPv4 packet from device/port: " + srcConnectPoint.deviceId() + "/" +
                            srcConnectPoint.port());
                    log.info("Received packet for IP: " + ethPacket);

//                    if (!Ip4Address.valueOf(ipv4Packet.getDestinationAddress()).equals(sharedAddress) &&
//                            !Ip4Address.valueOf(ipv4Packet.getDestinationAddress()).equals(Ip4Address.valueOf("10.0.1.1"))) {
//                        return;
//                    }

                    if(ipv4Packet.getProtocol() != IPv4.PROTOCOL_TCP) {
                        log.info("Not a TCP protocol");
                        return;
                    }

                    List<Integer> standardFtpPorts = Arrays.asList(20, 21);
                    TCP tcpPacket = (TCP) ipv4Packet.getPayload();
                    int destinationPort = tcpPacket.getDestinationPort();
                    int srcPort = tcpPacket.getSourcePort();

                    log.info("IP packet: " + ipv4Packet);

//                    log.info("TCP src/dst port: " + destinationPort + "/" + srcPort);
//
//                    if(!standardFtpPorts.contains(destinationPort) &&
//                    !standardFtpPorts.contains(srcPort)) {
//                        log.info("NO FTP PORTS!");
//                    }

//                    if(tcpPacket.getFlags()) {
//                        log.info("Got TCP ACK: " + tcpPacket);
//                    }

                    if(standardFtpPorts.contains(destinationPort) ||
                    standardFtpPorts.contains(srcPort)) {
                        log.info("Received FTP packet: " + tcpPacket);
                        if(context.isHandled()) {
                            log.info("Context is handled");
                        }

                        if(srcConnectPoint.deviceId().equals(DeviceId.deviceId("of:0000000000000001"))) {
                            if(srcConnectPoint.port().equals(PortNumber.portNumber(4))) {
                                log.info("DEV 1, PORT 4");
                                // emitPacket(srcConnectPoint.deviceId(), ethPacket, 1);

                            } else if (srcConnectPoint.port().equals(PortNumber.portNumber(1))) {
                                log.info("DEV 1, PORT 1");
                                ipv4Packet.setSourceAddress("10.0.1.10");
                                ipv4Packet.setDestinationAddress("10.0.2.1");
                                ipv4Packet.resetChecksum();
                                ethPacket.setPayload(ipv4Packet);
                                ethPacket.setDestinationMACAddress("00:00:00:00:02:01");
                                ethPacket.resetChecksum();
                                emitPacket(srcConnectPoint.deviceId(), ethPacket, 4);
                                // context.block();
                            }
                        } else if(srcConnectPoint.deviceId().equals(DeviceId.deviceId("of:0000000000000002"))) {
                            if(srcConnectPoint.port().equals(PortNumber.portNumber(1))) {
                                log.info("DEV 2, PORT 1");
                                ipv4Packet.setDestinationAddress("10.0.1.1");
                                ipv4Packet.resetChecksum();
                                ethPacket.setPayload(ipv4Packet);
                                ethPacket.resetChecksum();
                                emitPacket(srcConnectPoint.deviceId(), ethPacket, 3);
                                // context.block();
                            } else if (srcConnectPoint.port().equals(PortNumber.portNumber(3))) {
                                log.info("DEV 2, PORT 3");
                                // emitPacket(srcConnectPoint.deviceId(), ethPacket, 1);
                            }

                        }

                        // context.block();

//                        installRules(context,
//                                srcConnectPoint.deviceId(),
//                                ethPacket.getSourceMAC(),
//                                ethPacket.getDestinationMAC(),
//                                sharedAddress,
//                                Ip4Address.valueOf("10.0.1.1"),
//                                TpPort.tpPort(tcpPacket.getSourcePort()),
//                                ethPacket,
//                                ipv4Packet,
//                                3);
//                        installNextFlow(context,
//                                DeviceId.deviceId("of:0000000000000001"),
//                                ethPacket.getSourceMAC(),
//                                ethPacket.getDestinationMAC(),
//                                sharedAddress,
//                                Ip4Address.valueOf("10.0.1.1"),
//                                TpPort.tpPort(tcpPacket.getSourcePort()),
//                                ethPacket,
//                                ipv4Packet,
//                                1);
                        return;
                    }
                    break;
            }
        }

        private void emitPacket(DeviceId deviceId, Ethernet ethPacket, int outPort) {
            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setIpDst(Ip4Address.valueOf("10.0.1.1"))
                    .setOutput(PortNumber.portNumber(outPort))
                    .build();
            OutboundPacket packet = new DefaultOutboundPacket(deviceId,
                    treatment, ByteBuffer.wrap(ethPacket.serialize()));
            packetService.emit(packet);
            log.info("sending packet: {}", packet);
        }

        private void installRules(PacketContext context, DeviceId deviceId, MacAddress ethSrc, MacAddress ethDst,
                                  Ip4Address sharedIp, Ip4Address ipDst, TpPort srcPort,
                                  Ethernet ethPacket, IPv4 ipPacket, long outPort) {
            TrafficSelector selector = DefaultTrafficSelector.builder()
                    .matchEthSrc(ethSrc)
                    .matchEthDst(ethDst)
                    .matchEthType(EthType.EtherType.IPV4.ethType().toShort())
                    .matchIPDst(sharedIp.toIpPrefix())
                    .matchIPProtocol(IPv4.PROTOCOL_TCP)
                    .matchTcpSrc(srcPort)
                    .build();

            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setIpDst(ipDst)
                    .setOutput(PortNumber.portNumber(3))
                    .build();

            log.info("Installing rule");

            flowObjectiveService.forward(deviceId,
                    DefaultForwardingObjective.builder()
                    .fromApp(appId)
                    .withSelector(selector)
                    .withTreatment(treatment)
                    .withFlag(ForwardingObjective.Flag.VERSATILE)
                    .withPriority(100)
                            .makeTemporary(120)
                    .add());

            ipPacket.setDestinationAddress(ipDst.toInt());
            ethPacket.setPayload(ipPacket);
            OutboundPacket packet = new DefaultOutboundPacket(deviceId,
                    treatment, ByteBuffer.wrap(ethPacket.serialize()));
            packetService.emit(packet);
            log.info("sending packet: {}", packet);
            log.info("Context sent");

            // context.block();
            log.info("Context blocked");
        }

        private void installNextFlow(PacketContext context, DeviceId deviceId, MacAddress ethSrc, MacAddress ethDst,
                                     Ip4Address sharedIp, Ip4Address ipDst, TpPort srcPort,
                                     Ethernet ethPacket, IPv4 ipPacket, long outPort) {
            TrafficSelector selector = DefaultTrafficSelector.builder()
                    .matchEthSrc(ethSrc)
                    .matchEthDst(ethDst)
                    .matchIPDst(ipDst.toIpPrefix())
                    .matchEthType(EthType.EtherType.IPV4.ethType().toShort())
                    .matchIPProtocol(IPv4.PROTOCOL_TCP)
                    .matchTcpSrc(srcPort)
                    .build();

            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setOutput(PortNumber.portNumber(1))
                    .build();

            log.info("Installing rule");

            flowObjectiveService.forward(deviceId,
                    DefaultForwardingObjective.builder()
                            .fromApp(appId)
                            .withSelector(selector)
                            .withTreatment(treatment)
                            .withFlag(ForwardingObjective.Flag.VERSATILE)
                            .withPriority(100)
                            .makeTemporary(120)
                            .add());
        }

        private void installReverseFlow(PacketContext context, DeviceId deviceId, MacAddress ethSrc, MacAddress ethDst,
                                        Ip4Address sharedIp, Ip4Address ipDst, TpPort srcPort,
                                        Ethernet ethPacket, IPv4 ipPacket, long outPort) {
            TrafficSelector selector = DefaultTrafficSelector.builder()
                    .matchEthSrc(ethSrc)
                    .matchEthDst(ethDst)
                    .matchEthType(EthType.EtherType.IPV4.ethType().toShort())
                    .matchIPDst(sharedIp.toIpPrefix())
                    .matchIPProtocol(IPv4.PROTOCOL_TCP)
                    .matchTcpSrc(srcPort)
                    .build();

            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setIpDst(ipDst)
                    .setOutput(PortNumber.portNumber(3))
                    .build();

            log.info("Installing rule");

            flowObjectiveService.forward(deviceId,
                    DefaultForwardingObjective.builder()
                            .fromApp(appId)
                            .withSelector(selector)
                            .withTreatment(treatment)
                            .withFlag(ForwardingObjective.Flag.VERSATILE)
                            .withPriority(100)
                            .makeTemporary(120)
                            .add());
        }
    }

}
